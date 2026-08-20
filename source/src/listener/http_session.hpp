#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <chrono>
#include <memory>
#include <optional>
#include <spdlog/spdlog.h>
#include <string>
#include <string_view>

#include "app_state.hpp"
#include "config/runtime_config.hpp"
#include "config/site_lookup.hpp"
#include "geoip/asn_service.hpp"
#include "geoip/geoip_service.hpp"
#include "history/globe_event_log.hpp"
#include "history/request_log.hpp"
#include "pipeline/checks.hpp"
#include "upstream/upstream.hpp"

namespace atomwall {

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;

namespace detail {

constexpr std::string_view kDefaultBlockedHtml =
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Blocked</title></head>"
    "<body style=\"font-family:sans-serif;text-align:center;padding:80px;background:#0f1115;"
    "color:#e6e9f0;\"><h1>403 &mdash; Blocked</h1>"
    "<p style=\"color:#8b93a7;\">Your request was blocked by this site's security rules.</p>"
    "</body></html>";

constexpr std::string_view kDefaultBannedHtml =
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Banned</title></head>"
    "<body style=\"font-family:sans-serif;text-align:center;padding:80px;background:#0f1115;"
    "color:#e6e9f0;\"><h1>403 &mdash; Temporarily Banned</h1>"
    "<p style=\"color:#8b93a7;\">Your IP has been temporarily blocked due to repeated policy "
    "violations. Try again later.</p></body></html>";

// Not admin-configurable like blocked_html/banned_html: this is a proxy/origin
// failure, not a policy decision, so it doesn't belong to the "two pages"
// granularity described in CLAUDE.md's Admin UI & API section.
constexpr std::string_view kBadGatewayHtml =
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Bad Gateway</title></head>"
    "<body style=\"font-family:sans-serif;text-align:center;padding:80px;background:#0f1115;"
    "color:#e6e9f0;\"><h1>502 &mdash; Bad Gateway</h1>"
    "<p style=\"color:#8b93a7;\">The origin server is unavailable. Try again shortly.</p>"
    "</body></html>";

inline std::string user_agent_of(const http::request_header<http::fields>& header) {
    const auto it = header.find(http::field::user_agent);
    return it == header.end() ? std::string{} : std::string(it->value());
}

inline std::string resolve_page_html(const std::string& configured, std::string_view fallback) {
    return configured.empty() ? std::string(fallback) : configured;
}

// Admin-defined per-status-code overrides (see ResponsePagesConfig::status_pages
// and CLAUDE.md's Admin UI & API / Response pages). Only the origin response's
// body is replaced when a match is found — the status code, headers, and
// overall HTTP semantics still come from the origin.
inline const std::string* find_status_page_html(const std::vector<StatusPageEntry>& status_pages,
                                                  unsigned status_code) {
    for (const auto& entry : status_pages) {
        if (entry.code == static_cast<int>(status_code)) {
            return &entry.html;
        }
    }
    return nullptr;
}

// Advertises fake_routes as Disallow entries so a well-behaved crawler
// steers clear of them; anything that requests one anyway is treated by
// evaluate_header_checks/check_fake_routes as a strong signal (see
// config/runtime_config.hpp). Only called when fake_routes is non-empty, so
// sites with none configured see no change from atomwall's default
// pass-through behavior for /robots.txt.
inline http::response<http::string_body> make_robots_txt_response(
    unsigned version, const std::vector<BlacklistEntry>& fake_routes, http::verb method) {
    std::string body = "User-agent: *\n";
    for (const auto& route : fake_routes) {
        body += "Disallow: " + route.value + "\n";
    }

    http::response<http::string_body> res{http::status::ok, version};
    res.set(http::field::server, "atomwall");
    res.set(http::field::content_type, "text/plain; charset=utf-8");
    res.keep_alive(false);
    if (method != http::verb::head) {
        res.body() = std::move(body);
    }
    res.prepare_payload();
    return res;
}

inline http::response<http::string_body> make_html_response(
    unsigned version, std::string html, http::status status = http::status::forbidden) {
    http::response<http::string_body> res{status, version};
    res.set(http::field::server, "atomwall");
    res.set(http::field::content_type, "text/html; charset=utf-8");
    res.keep_alive(false);
    res.body() = std::move(html);
    res.prepare_payload();
    return res;
}

// Adds points for `check_name` (if the ban system is enabled and that check
// has a configured score) to the IP's running total; crossing the threshold
// triggers a temporary block via ip_blocks and resets the score.
inline void award_score(const RuntimeConfig& config, ScoreTracker& scores, IpBlockTracker& ip_blocks,
                         const boost::asio::ip::address& client_ip, const std::string& client_ip_text,
                         std::string_view check_name) {
    if (!config.ban.enabled) {
        return;
    }
    auto it = config.ban.scores.find(std::string(check_name));
    if (it == config.ban.scores.end() || it->second <= 0) {
        return;
    }
    const int total = scores.add_points(client_ip_text, it->second);
    if (total >= config.ban.threshold) {
        TemporaryIpBlock block;
        block.text = client_ip_text;
        block.is_cidr = false;
        block.address = client_ip;
        block.source = "score";
        block.score_at_block = total;
        block.created_at = std::chrono::system_clock::now();
        block.expires_at = block.created_at + std::chrono::hours(config.ban.ban_duration_hours);
        ip_blocks.add(std::move(block));
        scores.reset(client_ip_text);
        spdlog::warn("auto-banned {} for {}h (score {} >= threshold {})", client_ip_text,
                     config.ban.ban_duration_hours, total, config.ban.threshold);
    }
}

// Records `event` to request_log (admin-only, full detail) and, when `geo`
// resolved, a stripped-down GlobeArcEvent (lat/lon + allow/block only — see
// history/globe_event_log.hpp) to globe_events. `event.blocked` is read
// before it's moved into request_log->record.
inline void record_events(AppState& state, const std::optional<GeoLocation>& geo,
                           RequestEvent event) {
    if (geo) {
        GlobeArcEvent arc;
        arc.timestamp = event.timestamp;
        arc.lat = geo->lat;
        arc.lon = geo->lon;
        arc.blocked = event.blocked;
        state.globe_events->record(std::move(arc));
    }
    state.request_log->record(std::move(event));
}

} // namespace detail

// Shared by the plain-HTTP (:80) and TLS (:443) listeners: read a request
// (header phase first, so cheap checks can reject before the body is
// buffered), run the pipeline, forward allowed requests upstream, loop for
// keep-alive. Any block closes the connection rather than trying to resync
// the stream after skipping an unread body. Every request — allowed or
// blocked — is recorded to request_log for the admin UI's live view/history.
template <class Stream>
net::awaitable<void> run_http_session(Stream& stream,
                                       const boost::asio::ip::address& client_ip,
                                       std::shared_ptr<AppState> state,
                                       std::string_view listener_label) {
    const std::string client_ip_text = client_ip.to_string();
    // One lookup per connection (client_ip is fixed for its lifetime), not
    // per request — matters for keep-alive connections issuing many requests.
    const std::optional<GeoLocation> geo =
        state->geoip ? state->geoip->lookup(client_ip) : std::nullopt;
    const std::string geo_country = geo ? geo->country : std::string{};
    const std::optional<AsnInfo> asn_info = state->asn ? state->asn->lookup(client_ip) : std::nullopt;
    const std::string geo_isp = asn_info ? asn_info->organization : std::string{};

    for (;;) {
        auto config = state->config_store->get();
        // Computed once per request (not once per connection, since config —
        // and so the whitelist — can change between requests on a keep-alive
        // connection). Every blocking check below is gated on this being
        // false; see is_ip_whitelisted's doc comment for why it isn't just
        // another entry in evaluate_header_checks.
        const bool is_whitelisted = is_ip_whitelisted(config->whitelist, client_ip);

        beast::flat_buffer buffer(config->limits.max_header_bytes);
        http::request_parser<http::string_body> parser;
        parser.body_limit(config->limits.max_body_bytes);

        beast::get_lowest_layer(stream).expires_after(config->limits.request_timeout);
        co_await http::async_read_header(stream, buffer, parser, net::use_awaitable);

        const unsigned version = parser.get().version();
        const auto& header = parser.get().base();
        const auto target = header.target();
        const auto path = std::string_view(target).substr(0, target.find('?'));

        RequestEvent event;
        event.timestamp = std::chrono::system_clock::now();
        event.client_ip = client_ip_text;
        event.country = geo_country.empty() ? "unknown" : geo_country;
        event.isp = geo_isp.empty() ? "unknown" : geo_isp;
        event.user_agent = detail::user_agent_of(header);
        event.method = std::string(header.method_string());
        event.path = std::string(target);
        event.listener = std::string(listener_label);

        const auto host_it = header.find(http::field::host);
        const std::string_view host_header =
            host_it == header.end() ? std::string_view{} : std::string_view(host_it->value());
        event.domain = std::string(host_header);
        const auto site = resolve_site(*config, host_header);

        if (!site.enabled) {
            event.blocked = true;
            event.block_reason = "site disabled";
            auto response = detail::make_html_response(
                version, detail::resolve_page_html(config->pages.blocked_html, detail::kDefaultBlockedHtml));
            event.bytes_transferred = response.body().size();
            event.status_code = static_cast<int>(response.result_int());
            detail::record_events(*state, geo, std::move(event));
            co_await http::async_write(stream, response, net::use_awaitable);
            co_return;
        }

        if (!is_whitelisted && state->ip_blocks->is_blocked(client_ip)) {
            event.blocked = true;
            event.block_reason = "banned: temporarily blocked (manual or score threshold)";
            auto response = detail::make_html_response(
                version, detail::resolve_page_html(config->pages.banned_html, detail::kDefaultBannedHtml));
            event.bytes_transferred = response.body().size();
            event.status_code = static_cast<int>(response.result_int());
            detail::record_events(*state, geo, std::move(event));
            co_await http::async_write(stream, response, net::use_awaitable);
            co_return;
        }

        if (auto result = check_request_rate(config->speed_check, *state->rate_tracker, client_ip,
                                              std::chrono::steady_clock::now());
            !is_whitelisted && result.blocked()) {
            spdlog::warn("blocked {} via {}: {}", client_ip_text, result.check_name, result.reason);
            event.blocked = true;
            event.block_reason = std::string(result.check_name) + ": " + result.reason;
            detail::award_score(*config, *state->scores, *state->ip_blocks, client_ip, client_ip_text,
                                 result.check_name);

            auto response = detail::make_html_response(
                version, detail::resolve_page_html(config->pages.blocked_html, detail::kDefaultBlockedHtml));
            event.bytes_transferred = response.body().size();
            event.status_code = static_cast<int>(response.result_int());
            detail::record_events(*state, geo, std::move(event));
            co_await http::async_write(stream, response, net::use_awaitable);
            co_return;
        }

        if (auto result = check_method_allowlist(config->method_check, header.method_string());
            !is_whitelisted && result.blocked()) {
            spdlog::warn("blocked {} via {}: {}", client_ip_text, result.check_name, result.reason);
            event.blocked = true;
            event.block_reason = std::string(result.check_name) + ": " + result.reason;
            detail::award_score(*config, *state->scores, *state->ip_blocks, client_ip, client_ip_text,
                                 result.check_name);

            auto response = detail::make_html_response(
                version, detail::resolve_page_html(config->pages.blocked_html, detail::kDefaultBlockedHtml));
            event.bytes_transferred = response.body().size();
            event.status_code = static_cast<int>(response.result_int());
            detail::record_events(*state, geo, std::move(event));
            co_await http::async_write(stream, response, net::use_awaitable);
            co_return;
        }

        if (auto result = evaluate_header_checks(config->blacklist, client_ip, path, header, geo_isp);
            !is_whitelisted && result.blocked()) {
            spdlog::warn("blocked {} via {}: {}", client_ip_text, result.check_name, result.reason);
            event.blocked = true;
            event.block_reason = std::string(result.check_name) + ": " + result.reason;
            detail::award_score(*config, *state->scores, *state->ip_blocks, client_ip, client_ip_text,
                                 result.check_name);

            auto response = detail::make_html_response(
                version, detail::resolve_page_html(config->pages.blocked_html, detail::kDefaultBlockedHtml));
            event.bytes_transferred = response.body().size();
            event.status_code = static_cast<int>(response.result_int());
            detail::record_events(*state, geo, std::move(event));
            co_await http::async_write(stream, response, net::use_awaitable);
            co_return;
        }

        if ((header.method() == http::verb::get || header.method() == http::verb::head) &&
            path == "/robots.txt" && !config->blacklist.fake_routes.empty()) {
            auto response = detail::make_robots_txt_response(version, config->blacklist.fake_routes,
                                                               header.method());
            event.bytes_transferred = response.body().size();
            event.status_code = static_cast<int>(response.result_int());
            detail::record_events(*state, geo, std::move(event));
            co_await http::async_write(stream, response, net::use_awaitable);
            co_return;
        }

        co_await http::async_read(stream, buffer, parser, net::use_awaitable);
        auto request = parser.release();
        const bool keep_alive = request.keep_alive();

        if (auto result = evaluate_body_checks(config->blacklist, request.body());
            !is_whitelisted && result.blocked()) {
            spdlog::warn("blocked {} via {}: {}", client_ip_text, result.check_name, result.reason);
            event.blocked = true;
            event.block_reason = std::string(result.check_name) + ": " + result.reason;
            detail::award_score(*config, *state->scores, *state->ip_blocks, client_ip, client_ip_text,
                                 result.check_name);

            auto response = detail::make_html_response(
                version, detail::resolve_page_html(config->pages.blocked_html, detail::kDefaultBlockedHtml));
            event.bytes_transferred = request.body().size() + response.body().size();
            event.status_code = static_cast<int>(response.result_int());
            detail::record_events(*state, geo, std::move(event));
            co_await http::async_write(stream, response, net::use_awaitable);
            co_return;
        }

        const std::size_t request_body_size = request.body().size();
        std::optional<http::response<http::string_body>> upstream_response;
        try {
            upstream_response = co_await forward_to_upstream(std::move(request), *site.upstream,
                                                               config->limits, client_ip_text);
        } catch (const std::exception& e) {
            spdlog::warn("upstream unreachable for {} {}: {}", event.method, event.path, e.what());
        }

        if (!upstream_response) {
            auto bad_gateway =
                detail::make_html_response(version, std::string(detail::kBadGatewayHtml),
                                            http::status::bad_gateway);
            event.bytes_transferred = request_body_size + bad_gateway.body().size();
            event.status_code = static_cast<int>(bad_gateway.result_int());
            detail::record_events(*state, geo, std::move(event));
            co_await http::async_write(stream, bad_gateway, net::use_awaitable);
            co_return;
        }

        auto response = std::move(*upstream_response);
        if (const auto* override_html =
                detail::find_status_page_html(config->pages.status_pages, response.result_int())) {
            response.body() = *override_html;
            response.set(http::field::content_type, "text/html; charset=utf-8");
        }
        response.keep_alive(keep_alive);
        response.prepare_payload();

        event.bytes_transferred = request_body_size + response.body().size();
        event.status_code = static_cast<int>(response.result_int());
        detail::record_events(*state, geo, std::move(event));

        beast::get_lowest_layer(stream).expires_after(config->limits.request_timeout);
        co_await http::async_write(stream, response, net::use_awaitable);

        if (!keep_alive) {
            co_return;
        }
    }
}

} // namespace atomwall
