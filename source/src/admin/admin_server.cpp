#include "admin/admin_server.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <set>
#include <sstream>
#include <spdlog/spdlog.h>
#include <stdexcept>

#include "admin/http_util.hpp"
#include "admin/json_view.hpp"
#include "admin/static_files.hpp"
#include "admin/url_fetch.hpp"
#include "auth/password_hash.hpp"
#include "config/blacklist_ops.hpp"
#include "config/site_ops.hpp"
#include "config/status_page_ops.hpp"
#include "history/sse_stream.hpp"
#include "listener/tls_context.hpp"
#include "pipeline/net_utils.hpp"

namespace atomwall {

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace json = boost::json;
using net::awaitable;
using net::use_awaitable;
using net::ip::tcp;

namespace {

constexpr std::size_t kAdminMaxBodyBytes = 1 * 1024 * 1024;
// GeoLite2-City.mmdb is typically 60-70MB; give real headroom above that.
constexpr std::size_t kGeoipUploadMaxBytes = 128 * 1024 * 1024;
constexpr std::string_view kApiGeoipUpload = "/api/geoip-upload";
constexpr std::string_view kApiAsnUpload = "/api/asn-upload";
constexpr std::string_view kApiBlacklistPrefix = "/api/blacklist/";
constexpr std::string_view kImportSuffix = "/import";
constexpr std::string_view kImportUrlSuffix = "/import-url";
constexpr std::string_view kClearSuffix = "/clear";
// Whitelist has no per-category prefix (it's one fixed resource, not eight
// like blacklist) so these are exact targets, not a prefix+suffix pair.
constexpr std::string_view kApiWhitelist = "/api/whitelist";
constexpr std::string_view kApiWhitelistImport = "/api/whitelist/import";
constexpr std::string_view kApiWhitelistImportUrl = "/api/whitelist/import-url";
constexpr std::string_view kApiWhitelistClear = "/api/whitelist/clear";
constexpr std::size_t kImportUrlMaxBytes = 64 * 1024 * 1024;
constexpr std::chrono::seconds kImportUrlTimeout{60};
constexpr std::string_view kApiRequests = "/api/requests";
constexpr std::string_view kApiRequestsStream = "/api/requests/stream";
constexpr std::string_view kApiGlobeStream = "/api/globe/stream";
constexpr std::string_view kApiUsersPrefix = "/api/users/";
constexpr std::string_view kApiSitesPrefix = "/api/sites/";
constexpr std::string_view kApiPagesStatusPrefix = "/api/pages/status/";
constexpr std::size_t kDefaultHistoryLimit = 200;
constexpr const char* kSessionCookieName = "atomwall_session";

std::optional<json::object> parse_json_object(std::string_view body) {
    try {
        auto parsed = json::parse(body);
        if (!parsed.is_object()) {
            return std::nullopt;
        }
        return parsed.as_object();
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<std::string> json_string_field(const json::object& obj, std::string_view key) {
    auto it = obj.find(key);
    if (it == obj.end() || !it->value().is_string()) {
        return std::nullopt;
    }
    return std::string(it->value().as_string());
}

std::optional<int> json_int_field(const json::object& obj, std::string_view key) {
    auto it = obj.find(key);
    if (it == obj.end() || !it->value().is_number()) {
        return std::nullopt;
    }
    return static_cast<int>(it->value().to_number<double>());
}

std::optional<std::string> extract_session_token(const http::request<http::string_body>& request) {
    auto it = request.find(http::field::cookie);
    if (it == request.end()) {
        return std::nullopt;
    }
    std::string_view cookies = it->value();
    while (!cookies.empty()) {
        const auto semi = cookies.find(';');
        auto part = cookies.substr(0, semi);
        while (!part.empty() && part.front() == ' ') {
            part.remove_prefix(1);
        }
        const auto eq = part.find('=');
        if (eq != std::string_view::npos && part.substr(0, eq) == kSessionCookieName) {
            return std::string(part.substr(eq + 1));
        }
        if (semi == std::string_view::npos) {
            break;
        }
        cookies.remove_prefix(semi + 1);
    }
    return std::nullopt;
}

bool is_public_api_route(std::string_view target) {
    return target == "/api/auth/status" || target == "/api/auth/setup" ||
           target == "/api/auth/login";
}

// `secure` is driven off whether the admin server is actually running with
// TLS (admin.tls_cert_file/tls_key_file both set) — see run_admin_server().
// A plain-HTTP loopback deployment must NOT get a Secure cookie, or no
// browser would ever send it back.
std::string session_set_cookie_header(const std::string& token, bool secure) {
    return std::string(kSessionCookieName) + "=" + token +
           "; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200" + (secure ? "; Secure" : "");
}

std::string session_clear_cookie_header(bool secure) {
    return std::string(kSessionCookieName) + "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" +
           (secure ? "; Secure" : "");
}

bool admin_uses_tls(const AppState& state) {
    auto config = state.config_store->get();
    return !config->admin.tls_cert_file.empty() && !config->admin.tls_key_file.empty();
}

http::response<http::string_body> serve_static_file(const std::filesystem::path& static_dir,
                                                      std::string_view target, unsigned version) {
    auto resolved = resolve_static_path(static_dir, target);
    if (!resolved) {
        return error_response(http::status::not_found, "not found", version);
    }

    std::ifstream file(*resolved, std::ios::binary);
    std::ostringstream buffer;
    buffer << file.rdbuf();

    http::response<http::string_body> res{http::status::ok, version};
    res.set(http::field::server, "atomwall-admin");
    res.set(http::field::content_type, std::string(mime_type_for(*resolved)));
    res.body() = buffer.str();
    res.prepare_payload();
    return res;
}

// --- auth handlers -------------------------------------------------------

http::response<http::string_body> handle_auth_status(
    AppState& state, const http::request<http::string_body>& request, unsigned version) {
    json::object obj;
    obj["setup_required"] = state.users->empty();
    auto token = extract_session_token(request);
    obj["authenticated"] = token.has_value() && state.sessions->validate(*token).has_value();
    return json_response(http::status::ok, obj, version);
}

http::response<http::string_body> handle_auth_setup(AppState& state, std::string_view body,
                                                      unsigned version, const std::string& client_ip) {
    if (!state.users->empty()) {
        return error_response(http::status::conflict, "setup already completed", version);
    }
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    auto username = json_string_field(*json_body, "username");
    auto password = json_string_field(*json_body, "password");
    if (!username || !password) {
        return error_response(http::status::bad_request, "username and password are required",
                               version);
    }
    try {
        state.users->create(*username, *password);
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }

    auto token = state.sessions->create(*username);
    state.login_history->record(
        LoginEvent{0, std::chrono::system_clock::now(), *username, client_ip});
    auto res = json_response(http::status::ok, json::object{{"username", *username}}, version);
    res.set(http::field::set_cookie, session_set_cookie_header(token, admin_uses_tls(state)));
    return res;
}

http::response<http::string_body> handle_auth_login(AppState& state, std::string_view body,
                                                      unsigned version, const std::string& client_ip) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    auto username = json_string_field(*json_body, "username");
    auto password = json_string_field(*json_body, "password");
    if (!username || !password) {
        return error_response(http::status::bad_request, "username and password are required",
                               version);
    }
    auto user = state.users->find(*username);
    PasswordHash stored;
    if (user) {
        stored = {user->salt_hex, user->hash_hex, user->iterations};
    }
    // Always run verify_password (even against a dummy hash) so a nonexistent
    // username doesn't return faster than a wrong password would.
    if (!user || !verify_password(*password, stored)) {
        return error_response(http::status::unauthorized, "invalid username or password", version);
    }

    auto token = state.sessions->create(*username);
    state.login_history->record(
        LoginEvent{0, std::chrono::system_clock::now(), *username, client_ip});
    auto res = json_response(http::status::ok, json::object{{"username", *username}}, version);
    res.set(http::field::set_cookie, session_set_cookie_header(token, admin_uses_tls(state)));
    return res;
}

http::response<http::string_body> handle_auth_logout(AppState& state,
                                                       const http::request<http::string_body>& request,
                                                       unsigned version) {
    if (auto token = extract_session_token(request)) {
        state.sessions->invalidate(*token);
    }
    auto res = json_response(http::status::ok, json::object{}, version);
    res.set(http::field::set_cookie, session_clear_cookie_header(admin_uses_tls(state)));
    return res;
}

// --- user management -------------------------------------------------------

http::response<http::string_body> handle_users_create(AppState& state, std::string_view body,
                                                        unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    auto username = json_string_field(*json_body, "username");
    auto password = json_string_field(*json_body, "password");
    if (!username || !password) {
        return error_response(http::status::bad_request, "username and password are required",
                               version);
    }
    try {
        state.users->create(*username, *password);
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }
    return json_response(http::status::ok, users_to_json(state.users->list()), version);
}

http::response<http::string_body> handle_users_delete(AppState& state, std::string_view username,
                                                        unsigned version) {
    try {
        if (!state.users->remove(std::string(username))) {
            return error_response(http::status::not_found, "user not found", version);
        }
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }
    return json_response(http::status::ok, users_to_json(state.users->list()), version);
}

// --- ip blocks (unified permanent + temporary) ------------------------------

TemporaryIpBlock build_temporary_block(const std::string& text, std::string source,
                                        std::chrono::hours duration) {
    TemporaryIpBlock block;
    block.text = text;
    block.source = std::move(source);
    block.created_at = std::chrono::system_clock::now();
    block.expires_at = block.created_at + duration;

    if (text.find('/') != std::string::npos) {
        auto range = parse_cidr(text);
        if (!range) {
            throw std::invalid_argument("not a valid CIDR range: " + text);
        }
        block.is_cidr = true;
        block.address = range->prefix;
        block.prefix_len = range->prefix_len;
    } else {
        boost::system::error_code ec;
        auto addr = net::ip::make_address(text, ec);
        if (ec) {
            throw std::invalid_argument("not a valid IP address: " + text);
        }
        block.is_cidr = false;
        block.address = addr;
    }
    return block;
}

http::response<http::string_body> handle_ip_block_mutation(
    AppState& state, http::verb method, std::string_view body, unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body {\"value\": \"...\"}",
                               version);
    }
    auto value = json_string_field(*json_body, "value");
    if (!value) {
        return error_response(http::status::bad_request, "expected JSON body {\"value\": \"...\"}",
                               version);
    }

    if (method == http::verb::delete_) {
        if (!state.ip_blocks->remove(*value)) {
            try {
                state.config_store->update(
                    [&](RuntimeConfig& config) {
                        remove_blacklist_entry(config, BlacklistCategory::Ips, *value);
                    });
            } catch (const std::exception& e) {
                spdlog::error("admin: failed to persist config change: {}", e.what());
            }
        }
    } else {
        const auto duration_hours = json_int_field(*json_body, "duration_hours").value_or(0);
        try {
            if (duration_hours > 0) {
                state.ip_blocks->add(
                    build_temporary_block(*value, "manual", std::chrono::hours(duration_hours)));
            } else {
                state.config_store->update(
                    [&](RuntimeConfig& config) { add_blacklist_entry(config, BlacklistCategory::Ips, *value); });
            }
        } catch (const std::invalid_argument& e) {
            return error_response(http::status::bad_request, e.what(), version);
        } catch (const std::exception& e) {
            spdlog::error("admin: failed to persist config change: {}", e.what());
            return error_response(http::status::internal_server_error, "failed to persist config",
                                   version);
        }
    }

    auto config = state.config_store->get();
    return json_response(http::status::ok,
                          ip_blocks_to_json(config->blacklist, state.ip_blocks->list_active()), version);
}

// --- generic blacklist categories (routes, countries, isps, user_agents, body_patterns) --

http::response<http::string_body> handle_blacklist_mutation(
    AppState& state, http::verb method, std::string_view category_name, std::string_view body,
    unsigned version, const std::string& acting_user) {
    auto category = parse_blacklist_category(category_name);
    if (!category) {
        return error_response(http::status::not_found, "unknown blacklist category", version);
    }
    if (*category == BlacklistCategory::Ips) {
        return handle_ip_block_mutation(state, method, body, version);
    }

    auto json_body = parse_json_object(body);
    auto value = json_body ? json_string_field(*json_body, "value") : std::nullopt;
    if (!value) {
        return error_response(http::status::bad_request, "expected JSON body {\"value\": \"...\"}",
                               version);
    }

    try {
        state.config_store->update([&](RuntimeConfig& config) {
            if (method == http::verb::post) {
                add_blacklist_entry(config, *category, *value, acting_user);
            } else {
                remove_blacklist_entry(config, *category, *value);
            }
        });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    } catch (const std::exception& e) {
        spdlog::error("admin: failed to persist config change: {}", e.what());
        return error_response(http::status::internal_server_error, "failed to persist config",
                               version);
    }

    auto updated = state.config_store->get();
    return json_response(http::status::ok,
                          blacklist_category_to_json(updated->blacklist, *category), version);
}

// Empties every entry in a category (the permanent YAML-backed list only —
// see clear_blacklist_category). The UI confirms with the admin before
// calling this; there's no further confirmation on the server side.
http::response<http::string_body> handle_blacklist_clear(AppState& state,
                                                           std::string_view category_name,
                                                           unsigned version) {
    auto category = parse_blacklist_category(category_name);
    if (!category) {
        return error_response(http::status::not_found, "unknown blacklist category", version);
    }

    try {
        state.config_store->update(
            [&](RuntimeConfig& config) { clear_blacklist_category(config, *category); });
    } catch (const std::exception& e) {
        spdlog::error("admin: failed to persist config change: {}", e.what());
        return error_response(http::status::internal_server_error, "failed to persist config",
                               version);
    }

    auto updated = state.config_store->get();
    return json_response(http::status::ok,
                          *category == BlacklistCategory::Ips
                              ? ip_blacklist_to_json(updated->blacklist)
                              : blacklist_category_to_json(updated->blacklist, *category),
                          version);
}

// Shared by both import paths below: takes raw list text (one entry per
// line — see import_blacklist_entries) and applies it to `category` in a
// single config_store->update, so the batch costs one disk write and one
// republish, not one per line.
http::response<http::string_body> apply_blacklist_import(AppState& state,
                                                           BlacklistCategory category,
                                                           std::string_view body,
                                                           unsigned version,
                                                           const std::string& acting_user) {
    ImportResult result;
    try {
        state.config_store->update([&](RuntimeConfig& config) {
            result = import_blacklist_entries(config, category, body, acting_user);
        });
    } catch (const std::exception& e) {
        spdlog::error("admin: failed to persist config change: {}", e.what());
        return error_response(http::status::internal_server_error, "failed to persist config",
                               version);
    }

    auto updated = state.config_store->get();
    json::object obj;
    obj["added"] = result.added;
    obj["skipped"] = result.skipped;
    obj["entries"] = category == BlacklistCategory::Ips
                          ? ip_blacklist_to_json(updated->blacklist)
                          : blacklist_category_to_json(updated->blacklist, category);
    return json_response(http::status::ok, obj, version);
}

// Bulk import from a `.list` file upload: request body is the raw file text
// (not JSON).
http::response<http::string_body> handle_blacklist_import(
    AppState& state, std::string_view category_name, std::string_view body, unsigned version,
    const std::string& acting_user) {
    auto category = parse_blacklist_category(category_name);
    if (!category) {
        return error_response(http::status::not_found, "unknown blacklist category", version);
    }
    return apply_blacklist_import(state, *category, body, version, acting_user);
}

// Bulk import from an admin-supplied URL: request body is JSON
// {"url": "..."}. The fetch runs on this coroutine (not a blocking call —
// see CLAUDE.md Performance posture) with a hard size cap and timeout, and
// fetch_url() refuses loopback/private targets so the admin API can't be
// used to probe the proxy's own internal network.
awaitable<http::response<http::string_body>> handle_blacklist_import_url(
    AppState& state, std::string_view category_name, std::string_view body, unsigned version,
    std::string acting_user) {
    auto category = parse_blacklist_category(category_name);
    if (!category) {
        co_return error_response(http::status::not_found, "unknown blacklist category", version);
    }

    auto json_body = parse_json_object(body);
    auto url = json_body ? json_string_field(*json_body, "url") : std::nullopt;
    if (!url) {
        co_return error_response(http::status::bad_request, "expected JSON body {\"url\": \"...\"}",
                                  version);
    }

    auto fetched = co_await fetch_url(*url, kImportUrlMaxBytes, kImportUrlTimeout);
    if (!fetched.ok) {
        co_return error_response(http::status::bad_gateway, fetched.error, version);
    }

    co_return apply_blacklist_import(state, *category, fetched.body, version, acting_user);
}

// --- whitelist (see WhitelistConfig in runtime_config.hpp) --------------
// Deliberately not routed through handle_blacklist_mutation/BlacklistCategory
// — it isn't a blacklist category, it's the opposite, and always permanent
// (no duration_hours like the "ips" blacklist category takes).

http::response<http::string_body> handle_whitelist_mutation(AppState& state, http::verb method,
                                                              std::string_view body, unsigned version,
                                                              const std::string& acting_user) {
    auto json_body = parse_json_object(body);
    auto value = json_body ? json_string_field(*json_body, "value") : std::nullopt;
    if (!value) {
        return error_response(http::status::bad_request, "expected JSON body {\"value\": \"...\"}",
                               version);
    }

    try {
        state.config_store->update([&](RuntimeConfig& config) {
            if (method == http::verb::post) {
                add_whitelist_entry(config, *value, acting_user);
            } else {
                remove_whitelist_entry(config, *value);
            }
        });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    } catch (const std::exception& e) {
        spdlog::error("admin: failed to persist config change: {}", e.what());
        return error_response(http::status::internal_server_error, "failed to persist config",
                               version);
    }

    auto updated = state.config_store->get();
    return json_response(http::status::ok, whitelist_to_json(updated->whitelist), version);
}

http::response<http::string_body> handle_whitelist_clear(AppState& state, unsigned version) {
    try {
        state.config_store->update([&](RuntimeConfig& config) { clear_whitelist(config); });
    } catch (const std::exception& e) {
        spdlog::error("admin: failed to persist config change: {}", e.what());
        return error_response(http::status::internal_server_error, "failed to persist config",
                               version);
    }

    auto updated = state.config_store->get();
    return json_response(http::status::ok, whitelist_to_json(updated->whitelist), version);
}

http::response<http::string_body> handle_whitelist_import(AppState& state, std::string_view body,
                                                            unsigned version,
                                                            const std::string& acting_user) {
    ImportResult result;
    try {
        state.config_store->update([&](RuntimeConfig& config) {
            result = import_whitelist_entries(config, body, acting_user);
        });
    } catch (const std::exception& e) {
        spdlog::error("admin: failed to persist config change: {}", e.what());
        return error_response(http::status::internal_server_error, "failed to persist config",
                               version);
    }

    auto updated = state.config_store->get();
    json::object obj;
    obj["added"] = result.added;
    obj["skipped"] = result.skipped;
    obj["entries"] = whitelist_to_json(updated->whitelist);
    return json_response(http::status::ok, obj, version);
}

awaitable<http::response<http::string_body>> handle_whitelist_import_url(AppState& state,
                                                                          std::string_view body,
                                                                          unsigned version,
                                                                          std::string acting_user) {
    auto json_body = parse_json_object(body);
    auto url = json_body ? json_string_field(*json_body, "url") : std::nullopt;
    if (!url) {
        co_return error_response(http::status::bad_request, "expected JSON body {\"url\": \"...\"}",
                                  version);
    }

    auto fetched = co_await fetch_url(*url, kImportUrlMaxBytes, kImportUrlTimeout);
    if (!fetched.ok) {
        co_return error_response(http::status::bad_gateway, fetched.error, version);
    }

    co_return handle_whitelist_import(state, fetched.body, version, acting_user);
}

// --- sites (multi-domain) -----------------------------------------------

http::response<http::string_body> handle_sites_create(AppState& state, std::string_view body,
                                                        unsigned version) {
    auto json_body = parse_json_object(body);
    auto domain = json_body ? json_string_field(*json_body, "domain") : std::nullopt;
    auto upstream_host = json_body ? json_string_field(*json_body, "upstream_host") : std::nullopt;
    auto upstream_port = json_body ? json_int_field(*json_body, "upstream_port") : std::nullopt;
    if (!domain || !upstream_host || !upstream_port) {
        return error_response(
            http::status::bad_request,
            "expected JSON body {\"domain\", \"upstream_host\", \"upstream_port\", ...}", version);
    }
    if (*upstream_port <= 0 || *upstream_port > 65535) {
        return error_response(http::status::bad_request,
                               "upstream_port must be between 1 and 65535", version);
    }

    SiteConfig site;
    site.domain = *domain;
    site.upstream.host = *upstream_host;
    site.upstream.port = static_cast<unsigned short>(*upstream_port);
    site.cert_file = json_string_field(*json_body, "cert_file").value_or("");
    site.key_file = json_string_field(*json_body, "key_file").value_or("");
    if (auto it = json_body->find("enabled"); it != json_body->end() && it->value().is_bool()) {
        site.enabled = it->value().as_bool();
    }

    try {
        state.config_store->update([&](RuntimeConfig& config) { add_site(config, site); });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }
    return json_response(http::status::ok, sites_to_json(*state.config_store->get()), version);
}

http::response<http::string_body> handle_sites_update(AppState& state, std::string_view domain,
                                                        std::string_view body, unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }

    SiteUpdate update;
    if (auto it = json_body->find("enabled"); it != json_body->end() && it->value().is_bool()) {
        update.enabled = it->value().as_bool();
    }
    update.cert_file = json_string_field(*json_body, "cert_file");
    update.key_file = json_string_field(*json_body, "key_file");
    update.upstream_host = json_string_field(*json_body, "upstream_host");
    if (auto port = json_int_field(*json_body, "upstream_port")) {
        if (*port <= 0 || *port > 65535) {
            return error_response(http::status::bad_request,
                                   "upstream_port must be between 1 and 65535", version);
        }
        update.upstream_port = static_cast<unsigned short>(*port);
    }

    try {
        state.config_store->update(
            [&](RuntimeConfig& config) { update_site(config, std::string(domain), update); });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::not_found, e.what(), version);
    }
    return json_response(http::status::ok, sites_to_json(*state.config_store->get()), version);
}

http::response<http::string_body> handle_sites_delete(AppState& state, std::string_view domain,
                                                        unsigned version) {
    try {
        state.config_store->update(
            [&](RuntimeConfig& config) { remove_site(config, std::string(domain)); });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::not_found, e.what(), version);
    }
    return json_response(http::status::ok, sites_to_json(*state.config_store->get()), version);
}

// --- ban config / pages / body-size-limit -----------------------------------

http::response<http::string_body> handle_ban_config_update(AppState& state, std::string_view body,
                                                             unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    try {
        state.config_store->update([&](RuntimeConfig& config) {
            if (auto it = json_body->find("enabled"); it != json_body->end() && it->value().is_bool()) {
                config.ban.enabled = it->value().as_bool();
            }
            if (auto threshold = json_int_field(*json_body, "threshold")) {
                if (*threshold <= 0) {
                    throw std::invalid_argument("threshold must be positive");
                }
                config.ban.threshold = *threshold;
            }
            if (auto hours = json_int_field(*json_body, "ban_duration_hours")) {
                if (*hours <= 0) {
                    throw std::invalid_argument("ban_duration_hours must be positive");
                }
                config.ban.ban_duration_hours = *hours;
            }
            if (auto it = json_body->find("scores"); it != json_body->end() && it->value().is_object()) {
                for (const auto& [name, points] : it->value().as_object()) {
                    if (points.is_number()) {
                        config.ban.scores[std::string(name)] = static_cast<int>(points.to_number<double>());
                    }
                }
            }
        });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }
    return json_response(http::status::ok, ban_config_to_json(state.config_store->get()->ban), version);
}

http::response<http::string_body> handle_speed_check_update(AppState& state, std::string_view body,
                                                              unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    try {
        state.config_store->update([&](RuntimeConfig& config) {
            if (auto it = json_body->find("enabled"); it != json_body->end() && it->value().is_bool()) {
                config.speed_check.enabled = it->value().as_bool();
            }
            if (auto max_requests = json_int_field(*json_body, "max_requests")) {
                if (*max_requests <= 0) {
                    throw std::invalid_argument("max_requests must be positive");
                }
                config.speed_check.max_requests = *max_requests;
            }
            if (auto window_seconds = json_int_field(*json_body, "window_seconds")) {
                if (*window_seconds <= 0) {
                    throw std::invalid_argument("window_seconds must be positive");
                }
                config.speed_check.window_seconds = *window_seconds;
            }
        });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }
    return json_response(http::status::ok, speed_check_to_json(state.config_store->get()->speed_check),
                          version);
}

http::response<http::string_body> handle_method_check_update(AppState& state, std::string_view body,
                                                               unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    try {
        state.config_store->update([&](RuntimeConfig& config) {
            if (auto it = json_body->find("enabled"); it != json_body->end() && it->value().is_bool()) {
                config.method_check.enabled = it->value().as_bool();
            }
            if (auto it = json_body->find("allowed_methods");
                it != json_body->end() && it->value().is_array()) {
                std::vector<std::string> methods;
                for (const auto& item : it->value().as_array()) {
                    if (item.is_string()) {
                        methods.emplace_back(item.as_string());
                    }
                }
                if (config.method_check.enabled && methods.empty()) {
                    throw std::invalid_argument(
                        "allowed_methods can't be empty while method_check is enabled — that "
                        "would block every request");
                }
                config.method_check.allowed_methods = std::move(methods);
            }
        });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }
    return json_response(http::status::ok,
                          method_check_to_json(state.config_store->get()->method_check), version);
}

http::response<http::string_body> handle_pages_update(AppState& state, std::string_view body,
                                                        unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    state.config_store->update([&](RuntimeConfig& config) {
        if (auto blocked = json_string_field(*json_body, "blocked_html")) {
            config.pages.blocked_html = *blocked;
        }
        if (auto banned = json_string_field(*json_body, "banned_html")) {
            config.pages.banned_html = *banned;
        }
    });
    return json_response(http::status::ok, pages_to_json(state.config_store->get()->pages), version);
}

http::response<http::string_body> handle_status_page_add(AppState& state, std::string_view body,
                                                           unsigned version) {
    auto json_body = parse_json_object(body);
    auto code = json_body ? json_int_field(*json_body, "code") : std::nullopt;
    auto html = json_body ? json_string_field(*json_body, "html") : std::nullopt;
    if (!code || !html) {
        return error_response(http::status::bad_request,
                               "expected JSON body {\"code\": <int>, \"html\": \"...\"}", version);
    }
    try {
        state.config_store->update(
            [&](RuntimeConfig& config) { add_status_page(config, *code, *html); });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }
    return json_response(http::status::ok, pages_to_json(state.config_store->get()->pages), version);
}

http::response<http::string_body> handle_status_page_update(AppState& state, std::string_view code_text,
                                                              std::string_view body, unsigned version) {
    int code = 0;
    if (auto [ptr, ec] = std::from_chars(code_text.data(), code_text.data() + code_text.size(), code);
        ec != std::errc{}) {
        return error_response(http::status::bad_request, "status code must be numeric", version);
    }
    auto json_body = parse_json_object(body);
    auto html = json_body ? json_string_field(*json_body, "html") : std::nullopt;
    if (!html) {
        return error_response(http::status::bad_request, "expected JSON body {\"html\": \"...\"}",
                               version);
    }
    try {
        state.config_store->update(
            [&](RuntimeConfig& config) { update_status_page(config, code, *html); });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::not_found, e.what(), version);
    }
    return json_response(http::status::ok, pages_to_json(state.config_store->get()->pages), version);
}

http::response<http::string_body> handle_status_page_delete(AppState& state, std::string_view code_text,
                                                              unsigned version) {
    int code = 0;
    if (auto [ptr, ec] = std::from_chars(code_text.data(), code_text.data() + code_text.size(), code);
        ec != std::errc{}) {
        return error_response(http::status::bad_request, "status code must be numeric", version);
    }
    try {
        state.config_store->update([&](RuntimeConfig& config) { remove_status_page(config, code); });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::not_found, e.what(), version);
    }
    return json_response(http::status::ok, pages_to_json(state.config_store->get()->pages), version);
}

// Only takes effect on the next restart — RequestLog's writer thread and CSV
// path are fixed at construction in main.cpp, same "restart to apply" caveat
// as http.enabled/https.enabled/admin.enabled/globe.public_enabled.
http::response<http::string_body> handle_request_log_config_update(AppState& state,
                                                                     std::string_view body,
                                                                     unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    state.config_store->update([&](RuntimeConfig& config) {
        if (auto it = json_body->find("enabled"); it != json_body->end() && it->value().is_bool()) {
            config.request_log.enabled = it->value().as_bool();
        }
        if (auto path = json_string_field(*json_body, "csv_path")) {
            config.request_log.csv_path = *path;
        }
    });
    return json_response(http::status::ok,
                          request_log_config_to_json(state.config_store->get()->request_log), version);
}

http::response<http::string_body> handle_body_size_limit_update(AppState& state,
                                                                  std::string_view body,
                                                                  unsigned version) {
    auto json_body = parse_json_object(body);
    auto max_bytes = json_body ? json_int_field(*json_body, "max_bytes") : std::nullopt;
    if (!max_bytes || *max_bytes < 0) {
        return error_response(http::status::bad_request, "expected JSON body {\"max_bytes\": N}",
                               version);
    }
    state.config_store->update([&](RuntimeConfig& config) {
        config.blacklist.max_body_size_bytes = static_cast<std::size_t>(*max_bytes);
    });
    json::object obj;
    obj["max_bytes"] = state.config_store->get()->blacklist.max_body_size_bytes;
    return json_response(http::status::ok, obj, version);
}

// --- geoip / globe config, and the anonymized globe snapshot ----------------

// Shared by both mmdb upload routes below: writes the body to <config
// dir>/geoip/<filename> and applies `apply_path` to the config. Loading only
// happens at startup (see main.cpp), so this takes effect on the next
// restart, same as every other "restart to apply" listener/service setting.
http::response<http::string_body> handle_mmdb_upload(
    AppState& state, std::string_view body, unsigned version, const char* filename,
    const std::function<void(RuntimeConfig&, std::string)>& apply_path) {
    if (body.empty()) {
        return error_response(http::status::bad_request, "empty upload", version);
    }
    const auto config_dir = std::filesystem::path(state.config_store->path()).parent_path();
    const auto dest_dir = config_dir / "geoip";
    const auto dest_path = dest_dir / filename;
    try {
        std::filesystem::create_directories(dest_dir);
        const auto tmp_path = dest_dir / (std::string(filename) + ".tmp");
        {
            std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
            if (!out) {
                return error_response(http::status::internal_server_error,
                                       "failed to open destination file for writing", version);
            }
            out.write(body.data(), static_cast<std::streamsize>(body.size()));
        }
        std::filesystem::rename(tmp_path, dest_path);
    } catch (const std::exception& e) {
        return error_response(http::status::internal_server_error,
                               std::string("failed to save upload: ") + e.what(), version);
    }
    state.config_store->update(
        [&](RuntimeConfig& config) { apply_path(config, dest_path.string()); });
    boost::json::object obj;
    obj["mmdb_path"] = dest_path.string();
    obj["bytes"] = body.size();
    return json_response(http::status::ok, obj, version);
}

http::response<http::string_body> handle_geoip_upload(AppState& state, std::string_view body,
                                                        unsigned version) {
    return handle_mmdb_upload(state, body, version, "GeoLite2-City.mmdb",
                               [](RuntimeConfig& config, std::string path) {
                                   config.geoip.mmdb_path = std::move(path);
                               });
}

http::response<http::string_body> handle_asn_upload(AppState& state, std::string_view body,
                                                      unsigned version) {
    return handle_mmdb_upload(state, body, version, "GeoLite2-ASN.mmdb",
                               [](RuntimeConfig& config, std::string path) {
                                   config.geoip.asn_mmdb_path = std::move(path);
                               });
}

http::response<http::string_body> handle_geoip_config_update(AppState& state, std::string_view body,
                                                               unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    auto path = json_string_field(*json_body, "mmdb_path");
    auto asn_path = json_string_field(*json_body, "asn_mmdb_path");
    if (!path && !asn_path) {
        return error_response(
            http::status::bad_request,
            "expected JSON body with \"mmdb_path\" and/or \"asn_mmdb_path\"", version);
    }
    state.config_store->update([&](RuntimeConfig& config) {
        if (path) config.geoip.mmdb_path = *path;
        if (asn_path) config.geoip.asn_mmdb_path = *asn_path;
    });
    auto updated = state.config_store->get();
    return json_response(
        http::status::ok,
        geoip_config_to_json(updated->geoip, state.geoip && state.geoip->loaded(),
                              state.asn && state.asn->loaded()),
        version);
}

http::response<http::string_body> handle_globe_config_update(AppState& state, std::string_view body,
                                                               unsigned version) {
    auto json_body = parse_json_object(body);
    if (!json_body) {
        return error_response(http::status::bad_request, "expected JSON body", version);
    }
    try {
        state.config_store->update([&](RuntimeConfig& config) {
            if (auto it = json_body->find("public_enabled");
                it != json_body->end() && it->value().is_bool()) {
                config.globe.public_enabled = it->value().as_bool();
            }
            if (auto host = json_string_field(*json_body, "public_bind")) {
                config.globe.public_bind_host = *host;
            }
            if (auto port = json_int_field(*json_body, "public_port")) {
                if (*port <= 0 || *port > 65535) {
                    throw std::invalid_argument("public_port must be between 1 and 65535");
                }
                config.globe.public_port = static_cast<unsigned short>(*port);
            }
            if (auto cert = json_string_field(*json_body, "public_tls_cert_file")) {
                config.globe.public_tls_cert_file = *cert;
            }
            if (auto key = json_string_field(*json_body, "public_tls_key_file")) {
                config.globe.public_tls_key_file = *key;
            }
            if (auto it = json_body->find("server_lat"); it != json_body->end()) {
                if (it->value().is_null()) {
                    config.globe.server_lat = std::nullopt;
                } else if (it->value().is_number()) {
                    const double lat = it->value().to_number<double>();
                    if (lat < -90.0 || lat > 90.0) {
                        throw std::invalid_argument("server_lat must be between -90 and 90");
                    }
                    config.globe.server_lat = lat;
                }
            }
            if (auto it = json_body->find("server_lon"); it != json_body->end()) {
                if (it->value().is_null()) {
                    config.globe.server_lon = std::nullopt;
                } else if (it->value().is_number()) {
                    const double lon = it->value().to_number<double>();
                    if (lon < -180.0 || lon > 180.0) {
                        throw std::invalid_argument("server_lon must be between -180 and 180");
                    }
                    config.globe.server_lon = lon;
                }
            }
            if (auto it = json_body->find("auto_detect_server_location");
                it != json_body->end() && it->value().is_bool()) {
                config.globe.auto_detect_server_location = it->value().as_bool();
            }
            if (auto history_size = json_int_field(*json_body, "history_size")) {
                if (*history_size <= 0) {
                    throw std::invalid_argument("history_size must be positive");
                }
                config.globe.history_size = static_cast<std::size_t>(*history_size);
            }
        });
    } catch (const std::invalid_argument& e) {
        return error_response(http::status::bad_request, e.what(), version);
    }
    return json_response(http::status::ok, globe_config_to_json(state.config_store->get()->globe),
                          version);
}

http::response<http::string_body> handle_globe_snapshot(AppState& state, std::string_view target,
                                                          unsigned version) {
    const auto limit = query_param_size_t(target, "limit", kDefaultHistoryLimit);
    boost::json::object obj;
    obj["events"] = globe_events_to_json(state.globe_events->recent(limit));
    obj["server_location"] = server_location_to_json(state.server_location->get());
    obj["geoip_ready"] = state.geoip && state.geoip->loaded();
    return json_response(http::status::ok, obj, version);
}

http::response<http::string_body> handle_live_visitors(AppState& state, unsigned version) {
    constexpr auto kWindow = std::chrono::minutes(5);
    const auto cutoff = std::chrono::system_clock::now() - kWindow;
    std::set<std::string> unique_ips;
    for (const auto& event : state.request_log->recent(2000)) {
        if (event.timestamp >= cutoff) {
            unique_ips.insert(event.client_ip);
        }
    }
    json::object obj;
    obj["count"] = unique_ips.size();
    return json_response(http::status::ok, obj, version);
}

// --- routing -----------------------------------------------------------------

http::response<http::string_body> route(AppState& state,
                                         const http::request<http::string_body>& request,
                                         const std::string& acting_user,
                                         const std::string& client_ip) {
    const auto target = request.target();
    const auto version = request.version();
    const auto method = request.method();
    auto config = state.config_store->get();

    if (method == http::verb::get && target == "/api/auth/status") {
        return handle_auth_status(state, request, version);
    }
    if (method == http::verb::post && target == "/api/auth/setup") {
        return handle_auth_setup(state, request.body(), version, client_ip);
    }
    if (method == http::verb::post && target == "/api/auth/login") {
        return handle_auth_login(state, request.body(), version, client_ip);
    }
    if (method == http::verb::post && target == "/api/auth/logout") {
        return handle_auth_logout(state, request, version);
    }

    if (method == http::verb::get && target == "/api/users") {
        return json_response(http::status::ok, users_to_json(state.users->list()), version);
    }
    if (method == http::verb::post && target == "/api/users") {
        return handle_users_create(state, request.body(), version);
    }
    if (method == http::verb::delete_ && std::string_view(target).starts_with(kApiUsersPrefix)) {
        return handle_users_delete(state, std::string_view(target).substr(kApiUsersPrefix.size()),
                                    version);
    }
    if (method == http::verb::get && target == "/api/login-history") {
        const auto limit = query_param_size_t(target, "limit", kDefaultHistoryLimit);
        return json_response(http::status::ok, login_events_to_json(state.login_history->recent(limit)),
                              version);
    }

    if (method == http::verb::get && target == "/api/config") {
        return json_response(http::status::ok, config_to_json(*config), version);
    }
    if (method == http::verb::get && target == "/api/blacklist") {
        return json_response(http::status::ok, blacklist_to_json(config->blacklist), version);
    }
    if (method == http::verb::get && target == "/api/sites") {
        return json_response(http::status::ok, sites_to_json(*config), version);
    }
    if (method == http::verb::post && target == "/api/sites") {
        return handle_sites_create(state, request.body(), version);
    }
    if (method == http::verb::put && std::string_view(target).starts_with(kApiSitesPrefix)) {
        return handle_sites_update(
            state, std::string_view(target).substr(kApiSitesPrefix.size()), request.body(), version);
    }
    if (method == http::verb::delete_ && std::string_view(target).starts_with(kApiSitesPrefix)) {
        return handle_sites_delete(state, std::string_view(target).substr(kApiSitesPrefix.size()),
                                    version);
    }
    if (method == http::verb::get && target == "/api/ip-blocks") {
        return json_response(
            http::status::ok, ip_blocks_to_json(config->blacklist, state.ip_blocks->list_active()),
            version);
    }
    if (method == http::verb::get &&
        std::string_view(target).substr(0, kApiRequests.size()) == kApiRequests &&
        (target.size() == kApiRequests.size() || target[kApiRequests.size()] == '?')) {
        const auto limit = query_param_size_t(target, "limit", kDefaultHistoryLimit);
        return json_response(http::status::ok, request_events_to_json(state.request_log->recent(limit)),
                              version);
    }
    if (method == http::verb::get && target == "/api/live-visitors") {
        return handle_live_visitors(state, version);
    }
    if (method == http::verb::get && target == "/api/ban-config") {
        return json_response(http::status::ok, ban_config_to_json(config->ban), version);
    }
    if (method == http::verb::put && target == "/api/ban-config") {
        return handle_ban_config_update(state, request.body(), version);
    }
    if (method == http::verb::get && target == "/api/speed-check") {
        return json_response(http::status::ok, speed_check_to_json(config->speed_check), version);
    }
    if (method == http::verb::put && target == "/api/speed-check") {
        return handle_speed_check_update(state, request.body(), version);
    }
    if (method == http::verb::get && target == "/api/method-check") {
        return json_response(http::status::ok, method_check_to_json(config->method_check), version);
    }
    if (method == http::verb::put && target == "/api/method-check") {
        return handle_method_check_update(state, request.body(), version);
    }
    if (method == http::verb::get && target == "/api/pages") {
        return json_response(http::status::ok, pages_to_json(config->pages), version);
    }
    if (method == http::verb::put && target == "/api/pages") {
        return handle_pages_update(state, request.body(), version);
    }
    if (method == http::verb::post && target == "/api/pages/status") {
        return handle_status_page_add(state, request.body(), version);
    }
    if (method == http::verb::put && std::string_view(target).starts_with(kApiPagesStatusPrefix)) {
        return handle_status_page_update(
            state, std::string_view(target).substr(kApiPagesStatusPrefix.size()), request.body(), version);
    }
    if (method == http::verb::delete_ && std::string_view(target).starts_with(kApiPagesStatusPrefix)) {
        return handle_status_page_delete(
            state, std::string_view(target).substr(kApiPagesStatusPrefix.size()), version);
    }
    if (method == http::verb::get && target == "/api/request-log-config") {
        return json_response(http::status::ok, request_log_config_to_json(config->request_log),
                              version);
    }
    if (method == http::verb::put && target == "/api/request-log-config") {
        return handle_request_log_config_update(state, request.body(), version);
    }
    if (method == http::verb::put && target == "/api/body-size-limit") {
        return handle_body_size_limit_update(state, request.body(), version);
    }
    if (method == http::verb::post && target == kApiGeoipUpload) {
        return handle_geoip_upload(state, request.body(), version);
    }
    if (method == http::verb::post && target == kApiAsnUpload) {
        return handle_asn_upload(state, request.body(), version);
    }
    if (method == http::verb::get && target == "/api/geoip-config") {
        return json_response(
            http::status::ok,
            geoip_config_to_json(config->geoip, state.geoip && state.geoip->loaded(),
                                  state.asn && state.asn->loaded()),
            version);
    }
    if (method == http::verb::put && target == "/api/geoip-config") {
        return handle_geoip_config_update(state, request.body(), version);
    }
    if (method == http::verb::get && target == "/api/globe-config") {
        return json_response(http::status::ok, globe_config_to_json(config->globe), version);
    }
    if (method == http::verb::put && target == "/api/globe-config") {
        return handle_globe_config_update(state, request.body(), version);
    }
    if (method == http::verb::get &&
        std::string_view(target).substr(0, std::string_view("/api/globe/snapshot").size()) ==
            "/api/globe/snapshot") {
        return handle_globe_snapshot(state, target, version);
    }
    if (method == http::verb::post && std::string_view(target).starts_with(kApiBlacklistPrefix) &&
        std::string_view(target).ends_with(kImportSuffix)) {
        const auto category_name = std::string_view(target).substr(
            kApiBlacklistPrefix.size(),
            target.size() - kApiBlacklistPrefix.size() - kImportSuffix.size());
        return handle_blacklist_import(state, category_name, request.body(), version, acting_user);
    }
    if (method == http::verb::delete_ && std::string_view(target).starts_with(kApiBlacklistPrefix) &&
        std::string_view(target).ends_with(kClearSuffix)) {
        const auto category_name = std::string_view(target).substr(
            kApiBlacklistPrefix.size(),
            target.size() - kApiBlacklistPrefix.size() - kClearSuffix.size());
        return handle_blacklist_clear(state, category_name, version);
    }
    if ((method == http::verb::post || method == http::verb::delete_) &&
        target.starts_with(kApiBlacklistPrefix)) {
        const auto category_name = std::string_view(target).substr(kApiBlacklistPrefix.size());
        return handle_blacklist_mutation(state, method, category_name, request.body(), version,
                                          acting_user);
    }
    if (method == http::verb::post && target == kApiWhitelistImport) {
        return handle_whitelist_import(state, request.body(), version, acting_user);
    }
    if (method == http::verb::delete_ && target == kApiWhitelistClear) {
        return handle_whitelist_clear(state, version);
    }
    if ((method == http::verb::post || method == http::verb::delete_) && target == kApiWhitelist) {
        return handle_whitelist_mutation(state, method, request.body(), version, acting_user);
    }
    if (method == http::verb::get) {
        return serve_static_file(config->admin.static_dir, target, version);
    }

    return error_response(http::status::method_not_allowed, "method not allowed", version);
}

template <class Stream>
awaitable<void> handle_connection(Stream stream, std::shared_ptr<AppState> state) {
    // Computed once per connection (not once per request) — mirrors
    // run_http_session's client_ip handling in listener/http_session.hpp.
    // Only used for login-history attribution; falls back to "unknown"
    // rather than failing the connection if the socket is already gone.
    std::string client_ip_text = "unknown";
    {
        beast::error_code ec;
        auto endpoint = beast::get_lowest_layer(stream).socket().remote_endpoint(ec);
        if (!ec) {
            client_ip_text = endpoint.address().to_string();
        }
    }

    try {
        for (;;) {
            // flat_buffer's single-arg constructor sets a hard max_size ceiling
            // on the I/O staging buffer itself — separate from, and in
            // addition to, parser.body_limit() below. It must be at least as
            // large as the biggest body_limit any route sets (currently the
            // geoip .mmdb upload's kGeoipUploadMaxBytes) or a large-but-under-
            // the-body-limit upload still aborts mid-transfer with a
            // buffer_overflow once the staging buffer's growth hits this cap.
            // The ceiling costs nothing until actually needed — flat_buffer
            // doesn't allocate up front — so it's safe to size for the worst
            // case on every admin connection, not just the upload route.
            beast::flat_buffer buffer(kGeoipUploadMaxBytes);
            http::request_parser<http::string_body> parser;
            // Beast validates a declared Content-Length against body_limit()
            // as soon as headers finish parsing — inside async_read_header()
            // itself, before this code gets to inspect the route and raise
            // the limit for the routes that need it. So the limit here has to
            // start at the largest value any route allows; it gets tightened
            // back down below once the route is known, for every route that
            // doesn't need it this wide.
            parser.body_limit(kGeoipUploadMaxBytes);

            beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
            co_await http::async_read_header(stream, buffer, parser, use_awaitable);

            // The geoip .mmdb upload and local .list file imports are the
            // routes with a legitimately large body (blocklists can run into
            // the tens of MB) — every other admin route is small JSON, kept
            // at kAdminMaxBodyBytes deliberately (see its definition).
            const auto& header = parser.get().base();
            const bool is_list_import = header.method() == http::verb::post &&
                                         std::string_view(header.target()).starts_with(kApiBlacklistPrefix) &&
                                         std::string_view(header.target()).ends_with(kImportSuffix);
            if (header.method() == http::verb::post &&
                (header.target() == kApiGeoipUpload || header.target() == kApiAsnUpload)) {
                beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(120));
            } else if (is_list_import) {
                parser.body_limit(kImportUrlMaxBytes);
                beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(60));
            } else {
                parser.body_limit(kAdminMaxBodyBytes);
            }

            // curl and most browsers send "Expect: 100-continue" before a large
            // body so they can bail without uploading it if the server's going
            // to reject the request anyway. Beast never sends the interim 100
            // response on its own — without this, the client sits waiting for
            // it and the upload never starts (surfaces as a hung/failed fetch
            // in the browser for any body large enough to trigger it).
            if (header[http::field::expect] == "100-continue") {
                http::response<http::empty_body> continue_response{http::status::continue_,
                                                                     header.version()};
                continue_response.prepare_payload();
                co_await http::async_write(stream, continue_response, use_awaitable);
            }

            co_await http::async_read(stream, buffer, parser, use_awaitable);

            auto request = parser.release();
            const bool keep_alive = request.keep_alive();
            const auto target = request.target();

            const bool needs_auth = std::string_view(target).starts_with("/api/") &&
                                     !is_public_api_route(target);
            std::string acting_user;
            if (needs_auth) {
                auto token = extract_session_token(request);
                auto username = token ? state->sessions->validate(*token) : std::nullopt;
                if (!username) {
                    auto response = error_response(http::status::unauthorized, "unauthorized",
                                                     request.version());
                    response.keep_alive(keep_alive);
                    response.prepare_payload();
                    co_await http::async_write(stream, response, use_awaitable);
                    if (!keep_alive) {
                        break;
                    }
                    continue;
                }
                acting_user = *username;
            }

            if (request.method() == http::verb::get && target == kApiRequestsStream) {
                co_await run_sse_session(stream, state->request_log, request_event_to_json);
                co_return;
            }

            if (request.method() == http::verb::get && target == kApiGlobeStream) {
                co_await run_sse_session(stream, state->globe_events, globe_event_to_json);
                co_return;
            }

            if (request.method() == http::verb::post &&
                std::string_view(target).starts_with(kApiBlacklistPrefix) &&
                std::string_view(target).ends_with(kImportUrlSuffix)) {
                const auto category_name = std::string_view(target).substr(
                    kApiBlacklistPrefix.size(),
                    target.size() - kApiBlacklistPrefix.size() - kImportUrlSuffix.size());
                auto response = co_await handle_blacklist_import_url(
                    *state, category_name, request.body(), request.version(), acting_user);
                response.keep_alive(keep_alive);
                response.prepare_payload();
                co_await http::async_write(stream, response, use_awaitable);
                if (!keep_alive) {
                    break;
                }
                continue;
            }

            if (request.method() == http::verb::post && target == kApiWhitelistImportUrl) {
                auto response = co_await handle_whitelist_import_url(
                    *state, request.body(), request.version(), acting_user);
                response.keep_alive(keep_alive);
                response.prepare_payload();
                co_await http::async_write(stream, response, use_awaitable);
                if (!keep_alive) {
                    break;
                }
                continue;
            }

            auto response = route(*state, request, acting_user, client_ip_text);
            response.keep_alive(keep_alive);
            response.prepare_payload();

            co_await http::async_write(stream, response, use_awaitable);
            if (!keep_alive) {
                break;
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("admin connection closed: {}", e.what());
    }

    beast::error_code ec;
    beast::get_lowest_layer(stream).socket().shutdown(tcp::socket::shutdown_both, ec);
}

awaitable<void> accept_plain(std::shared_ptr<AppState> state, tcp::acceptor& acceptor) {
    auto executor = co_await net::this_coro::executor;
    for (;;) {
        auto socket = co_await acceptor.async_accept(use_awaitable);
        co_spawn(executor, handle_connection(beast::tcp_stream(std::move(socket)), state),
                 net::detached);
    }
}

awaitable<void> accept_tls(std::shared_ptr<AppState> state, tcp::acceptor& acceptor,
                            std::shared_ptr<ssl::context> ssl_ctx) {
    auto executor = co_await net::this_coro::executor;
    for (;;) {
        auto socket = co_await acceptor.async_accept(use_awaitable);
        co_spawn(
            executor,
            [](tcp::socket socket, std::shared_ptr<AppState> state,
               std::shared_ptr<ssl::context> ssl_ctx) -> awaitable<void> {
                ssl::stream<beast::tcp_stream> tls_stream(std::move(socket), *ssl_ctx);
                beast::get_lowest_layer(tls_stream).expires_after(std::chrono::seconds(30));
                try {
                    co_await tls_stream.async_handshake(ssl::stream_base::server, use_awaitable);
                } catch (const std::exception& e) {
                    spdlog::debug("admin TLS handshake failed: {}", e.what());
                    co_return;
                }
                co_await handle_connection(std::move(tls_stream), state);
            }(std::move(socket), state, ssl_ctx),
            net::detached);
    }
}

} // namespace

awaitable<void> run_admin_server(std::shared_ptr<AppState> state) {
    auto config = state->config_store->get();
    const bool use_tls =
        !config->admin.tls_cert_file.empty() && !config->admin.tls_key_file.empty();

    boost::system::error_code addr_ec;
    auto bind_address = net::ip::make_address(config->admin.bind_host, addr_ec);
    if (addr_ec) {
        throw std::runtime_error(
            "admin.bind is not a valid address: '" + config->admin.bind_host + "'");
    }
    if (!bind_address.is_loopback() && !use_tls) {
        throw std::runtime_error(
            "admin.bind ('" + config->admin.bind_host + "') is non-loopback but no "
            "admin.tls_cert_file/tls_key_file are configured — refusing to start. Exposing the "
            "admin API beyond loopback requires TLS (so the session cookie can be marked "
            "Secure and the login can't be sniffed in plaintext) — see CLAUDE.md Admin UI & "
            "API / Authentication.");
    }

    auto executor = co_await net::this_coro::executor;
    tcp::acceptor acceptor(executor, {bind_address, config->admin.port});

    spdlog::info("admin UI/API on {}://{}:{}{}", use_tls ? "https" : "http",
                 config->admin.bind_host, config->admin.port,
                 bind_address.is_loopback() ? " (loopback only)" : " (PUBLIC — TLS-secured)");

    if (use_tls) {
        auto ssl_ctx = std::make_shared<ssl::context>(
            make_tls_server_context(config->admin.tls_cert_file, config->admin.tls_key_file));
        co_await accept_tls(state, acceptor, ssl_ctx);
    } else {
        co_await accept_plain(state, acceptor);
    }
}

} // namespace atomwall
