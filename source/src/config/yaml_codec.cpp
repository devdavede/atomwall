#include "config/yaml_codec.hpp"

#include <boost/asio/ip/address.hpp>
#include <cstdio>
#include <ctime>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <yaml-cpp/yaml.h>

#include "pipeline/net_utils.hpp"

namespace atomwall {

namespace {

// UTC, matches admin/json_view.hpp's to_iso8601 format (kept separate since
// the config layer must not depend on the admin layer).
std::string format_timestamp(std::chrono::system_clock::time_point tp) {
    const std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

std::optional<std::chrono::system_clock::time_point> parse_timestamp(const std::string& text) {
    std::tm tm{};
    if (std::sscanf(text.c_str(), "%d-%d-%dT%d:%d:%dZ", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                     &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
        return std::nullopt;
    }
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    return std::chrono::system_clock::from_time_t(timegm(&tm));
}

// A blacklist entry can be persisted either as a bare scalar (old format, or
// hand-edited YAML) or as a {value, created_at} map (current format). Bare
// scalars get `created_at` backfilled to load time — there's no historical
// timestamp to recover for those.
struct RawEntry {
    std::string value;
    std::chrono::system_clock::time_point created_at;
    std::string created_by;
    std::string source;
};

RawEntry read_raw_entry(const YAML::Node& item) {
    const auto now = std::chrono::system_clock::now();
    if (item.IsScalar()) {
        return RawEntry{item.as<std::string>(), now, "", "manual"};
    }
    auto value = item["value"].as<std::string>();
    auto created_at = now;
    if (auto ts = item["created_at"]) {
        if (auto parsed = parse_timestamp(ts.as<std::string>())) {
            created_at = *parsed;
        }
    }
    auto created_by = item["created_by"] ? item["created_by"].as<std::string>() : std::string{};
    // Entries persisted before this field existed default to "manual".
    auto source = item["source"] ? item["source"].as<std::string>() : std::string{"manual"};
    return RawEntry{std::move(value), created_at, std::move(created_by), std::move(source)};
}

std::vector<BlacklistEntry> read_entry_list(const YAML::Node& node) {
    std::vector<BlacklistEntry> values;
    if (!node) {
        return values;
    }
    for (const auto& item : node) {
        auto raw = read_raw_entry(item);
        values.push_back(BlacklistEntry{std::move(raw.value), raw.created_at, std::move(raw.created_by),
                                         std::move(raw.source)});
    }
    return values;
}

void write_entry_list(YAML::Node& node, const std::vector<BlacklistEntry>& values) {
    for (const auto& entry : values) {
        YAML::Node item;
        item["value"] = entry.value;
        item["created_at"] = format_timestamp(entry.created_at);
        item["created_by"] = entry.created_by;
        item["source"] = entry.source;
        node.push_back(item);
    }
}

// Shared by blacklist.ips and whitelist.ips — both are a YAML sequence of
// {value, created_at, created_by, source} entries that split into an exact-IP
// list and a CIDR list depending on whether `value` contains a '/'.
void read_ip_list(const YAML::Node& node, std::vector<BlacklistEntry>& exact_out,
                   std::vector<CidrRange>& cidr_out, const char* kind) {
    if (!node) {
        return;
    }
    for (const auto& item : node) {
        auto raw = read_raw_entry(item);
        if (raw.value.find('/') != std::string::npos) {
            if (auto range = parse_cidr(raw.value)) {
                range->created_at = raw.created_at;
                range->source = raw.source;
                cidr_out.push_back(*range);
            } else {
                spdlog::warn("config: skipping invalid CIDR {} entry '{}'", kind, raw.value);
            }
        } else {
            boost::system::error_code ec;
            boost::asio::ip::make_address(raw.value, ec);
            if (ec) {
                spdlog::warn("config: skipping invalid IP {} entry '{}'", kind, raw.value);
            } else {
                exact_out.push_back(BlacklistEntry{raw.value, raw.created_at, raw.created_by, raw.source});
            }
        }
    }
}

void write_ip_list(YAML::Node& node, const std::vector<BlacklistEntry>& exact,
                    const std::vector<CidrRange>& cidrs) {
    for (const auto& entry : exact) {
        YAML::Node item;
        item["value"] = entry.value;
        item["created_at"] = format_timestamp(entry.created_at);
        item["created_by"] = entry.created_by;
        item["source"] = entry.source;
        node.push_back(item);
    }
    for (const auto& range : cidrs) {
        YAML::Node item;
        item["value"] = range.text;
        item["created_at"] = format_timestamp(range.created_at);
        item["source"] = range.source;
        node.push_back(item);
    }
}

} // namespace

RuntimeConfig parse_yaml_config(const std::string& yaml_text) {
    YAML::Node root = YAML::Load(yaml_text);
    RuntimeConfig config;

    if (auto n = root["http"]) {
        config.http.enabled = n["enabled"].as<bool>(config.http.enabled);
        config.http.bind_host = n["bind"].as<std::string>(config.http.bind_host);
        config.http.port = n["port"].as<unsigned short>(config.http.port);
    }

    if (auto n = root["https"]) {
        config.https.enabled = n["enabled"].as<bool>(config.https.enabled);
        config.https.bind_host = n["bind"].as<std::string>(config.https.bind_host);
        config.https.port = n["port"].as<unsigned short>(config.https.port);
        config.https.cert_file = n["cert_file"].as<std::string>(config.https.cert_file);
        config.https.key_file = n["key_file"].as<std::string>(config.https.key_file);
    }

    if (auto n = root["upstream"]) {
        config.upstream.host = n["host"].as<std::string>(config.upstream.host);
        config.upstream.port = n["port"].as<unsigned short>(config.upstream.port);
    }

    if (auto n = root["sites"]) {
        for (const auto& item : n) {
            SiteConfig site;
            site.domain = to_lower(item["domain"].as<std::string>(""));
            if (site.domain.empty()) {
                spdlog::warn("config: skipping sites entry with no domain");
                continue;
            }
            site.enabled = item["enabled"].as<bool>(true);
            site.cert_file = item["cert_file"].as<std::string>("");
            site.key_file = item["key_file"].as<std::string>("");
            if (auto up = item["upstream"]) {
                site.upstream.host = up["host"].as<std::string>(site.upstream.host);
                site.upstream.port = up["port"].as<unsigned short>(site.upstream.port);
            }
            config.sites.push_back(std::move(site));
        }
    }

    if (auto n = root["admin"]) {
        config.admin.enabled = n["enabled"].as<bool>(config.admin.enabled);
        config.admin.bind_host = n["bind"].as<std::string>(config.admin.bind_host);
        config.admin.port = n["port"].as<unsigned short>(config.admin.port);
        config.admin.static_dir = n["static_dir"].as<std::string>(config.admin.static_dir);
        config.admin.tls_cert_file = n["tls_cert_file"].as<std::string>(config.admin.tls_cert_file);
        config.admin.tls_key_file = n["tls_key_file"].as<std::string>(config.admin.tls_key_file);
    }

    if (auto n = root["limits"]) {
        config.limits.max_header_bytes =
            n["max_header_bytes"].as<std::size_t>(config.limits.max_header_bytes);
        config.limits.max_body_bytes =
            n["max_body_bytes"].as<std::size_t>(config.limits.max_body_bytes);
        config.limits.upstream_connect_timeout = std::chrono::seconds(
            n["upstream_connect_timeout_seconds"].as<long long>(config.limits.upstream_connect_timeout.count()));
        config.limits.request_timeout = std::chrono::seconds(
            n["request_timeout_seconds"].as<long long>(config.limits.request_timeout.count()));
    }

    if (auto n = root["blacklist"]) {
        read_ip_list(n["ips"], config.blacklist.ip_exact, config.blacklist.ip_cidrs, "blacklist");
        config.blacklist.routes = read_entry_list(n["routes"]);
        config.blacklist.countries = read_entry_list(n["countries"]);
        config.blacklist.isps = read_entry_list(n["isps"]);
        config.blacklist.user_agents = read_entry_list(n["user_agents"]);
        config.blacklist.referrers = read_entry_list(n["referrers"]);
        config.blacklist.body_patterns = read_entry_list(n["body_patterns"]);
        config.blacklist.fake_routes = read_entry_list(n["fake_routes"]);
        config.blacklist.max_body_size_bytes =
            n["max_body_size_bytes"].as<std::size_t>(config.blacklist.max_body_size_bytes);
    }

    if (auto n = root["whitelist"]) {
        read_ip_list(n["ips"], config.whitelist.ip_exact, config.whitelist.ip_cidrs, "whitelist");
    }

    if (auto n = root["ban"]) {
        config.ban.enabled = n["enabled"].as<bool>(config.ban.enabled);
        config.ban.threshold = n["threshold"].as<int>(config.ban.threshold);
        config.ban.ban_duration_hours =
            n["ban_duration_hours"].as<int>(config.ban.ban_duration_hours);
        if (auto scores = n["scores"]) {
            config.ban.scores.clear();
            for (auto it = scores.begin(); it != scores.end(); ++it) {
                config.ban.scores[it->first.as<std::string>()] = it->second.as<int>();
            }
        }
    }

    if (auto n = root["method_check"]) {
        config.method_check.enabled = n["enabled"].as<bool>(config.method_check.enabled);
        if (auto methods = n["allowed_methods"]) {
            config.method_check.allowed_methods.clear();
            for (const auto& item : methods) {
                config.method_check.allowed_methods.push_back(item.as<std::string>());
            }
        }
    }

    if (auto n = root["speed_check"]) {
        config.speed_check.enabled = n["enabled"].as<bool>(config.speed_check.enabled);
        config.speed_check.max_requests =
            n["max_requests"].as<int>(config.speed_check.max_requests);
        config.speed_check.window_seconds =
            n["window_seconds"].as<int>(config.speed_check.window_seconds);
    }

    if (auto n = root["pages"]) {
        config.pages.blocked_html = n["blocked_html"].as<std::string>(config.pages.blocked_html);
        config.pages.banned_html = n["banned_html"].as<std::string>(config.pages.banned_html);
        if (auto status_pages = n["status_pages"]) {
            config.pages.status_pages.clear();
            for (const auto& item : status_pages) {
                StatusPageEntry entry;
                entry.code = item["code"].as<int>();
                entry.html = item["html"].as<std::string>();
                if (auto ts = item["created_at"]) {
                    if (auto parsed = parse_timestamp(ts.as<std::string>())) {
                        entry.created_at = *parsed;
                    }
                }
                config.pages.status_pages.push_back(std::move(entry));
            }
        }
    }

    if (auto n = root["request_log"]) {
        config.request_log.enabled = n["enabled"].as<bool>(config.request_log.enabled);
        config.request_log.csv_path = n["csv_path"].as<std::string>(config.request_log.csv_path);
    }

    if (auto n = root["geoip"]) {
        config.geoip.mmdb_path = n["mmdb_path"].as<std::string>(config.geoip.mmdb_path);
        config.geoip.asn_mmdb_path = n["asn_mmdb_path"].as<std::string>(config.geoip.asn_mmdb_path);
    }

    if (auto n = root["globe"]) {
        config.globe.public_enabled = n["public_enabled"].as<bool>(config.globe.public_enabled);
        config.globe.public_bind_host =
            n["public_bind"].as<std::string>(config.globe.public_bind_host);
        config.globe.public_port = n["public_port"].as<unsigned short>(config.globe.public_port);
        config.globe.public_tls_cert_file =
            n["public_tls_cert_file"].as<std::string>(config.globe.public_tls_cert_file);
        config.globe.public_tls_key_file =
            n["public_tls_key_file"].as<std::string>(config.globe.public_tls_key_file);
        if (auto lat = n["server_lat"]; lat && !lat.IsNull()) {
            config.globe.server_lat = lat.as<double>();
        }
        if (auto lon = n["server_lon"]; lon && !lon.IsNull()) {
            config.globe.server_lon = lon.as<double>();
        }
        config.globe.auto_detect_server_location =
            n["auto_detect_server_location"].as<bool>(config.globe.auto_detect_server_location);
        config.globe.history_size = n["history_size"].as<std::size_t>(config.globe.history_size);
    }

    return config;
}

std::string to_yaml_config(const RuntimeConfig& config) {
    YAML::Node root;

    root["http"]["enabled"] = config.http.enabled;
    root["http"]["bind"] = config.http.bind_host;
    root["http"]["port"] = config.http.port;

    root["https"]["enabled"] = config.https.enabled;
    root["https"]["bind"] = config.https.bind_host;
    root["https"]["port"] = config.https.port;
    root["https"]["cert_file"] = config.https.cert_file;
    root["https"]["key_file"] = config.https.key_file;

    root["upstream"]["host"] = config.upstream.host;
    root["upstream"]["port"] = config.upstream.port;

    YAML::Node sites(YAML::NodeType::Sequence);
    for (const auto& site : config.sites) {
        YAML::Node item;
        item["domain"] = site.domain;
        item["enabled"] = site.enabled;
        item["cert_file"] = site.cert_file;
        item["key_file"] = site.key_file;
        item["upstream"]["host"] = site.upstream.host;
        item["upstream"]["port"] = site.upstream.port;
        sites.push_back(item);
    }
    root["sites"] = sites;

    root["admin"]["enabled"] = config.admin.enabled;
    root["admin"]["bind"] = config.admin.bind_host;
    root["admin"]["port"] = config.admin.port;
    root["admin"]["static_dir"] = config.admin.static_dir;
    root["admin"]["tls_cert_file"] = config.admin.tls_cert_file;
    root["admin"]["tls_key_file"] = config.admin.tls_key_file;

    root["limits"]["max_header_bytes"] = config.limits.max_header_bytes;
    root["limits"]["max_body_bytes"] = config.limits.max_body_bytes;
    root["limits"]["upstream_connect_timeout_seconds"] =
        static_cast<long long>(config.limits.upstream_connect_timeout.count());
    root["limits"]["request_timeout_seconds"] =
        static_cast<long long>(config.limits.request_timeout.count());

    YAML::Node ips(YAML::NodeType::Sequence);
    write_ip_list(ips, config.blacklist.ip_exact, config.blacklist.ip_cidrs);
    root["blacklist"]["ips"] = ips;

    YAML::Node routes(YAML::NodeType::Sequence);
    write_entry_list(routes, config.blacklist.routes);
    root["blacklist"]["routes"] = routes;
    root["blacklist"]["max_body_size_bytes"] = config.blacklist.max_body_size_bytes;

    YAML::Node whitelist_ips(YAML::NodeType::Sequence);
    write_ip_list(whitelist_ips, config.whitelist.ip_exact, config.whitelist.ip_cidrs);
    root["whitelist"]["ips"] = whitelist_ips;

    YAML::Node countries(YAML::NodeType::Sequence);
    write_entry_list(countries, config.blacklist.countries);
    root["blacklist"]["countries"] = countries;

    YAML::Node isps(YAML::NodeType::Sequence);
    write_entry_list(isps, config.blacklist.isps);
    root["blacklist"]["isps"] = isps;

    YAML::Node user_agents(YAML::NodeType::Sequence);
    write_entry_list(user_agents, config.blacklist.user_agents);
    root["blacklist"]["user_agents"] = user_agents;

    YAML::Node referrers(YAML::NodeType::Sequence);
    write_entry_list(referrers, config.blacklist.referrers);
    root["blacklist"]["referrers"] = referrers;

    YAML::Node body_patterns(YAML::NodeType::Sequence);
    write_entry_list(body_patterns, config.blacklist.body_patterns);
    root["blacklist"]["body_patterns"] = body_patterns;

    YAML::Node fake_routes(YAML::NodeType::Sequence);
    write_entry_list(fake_routes, config.blacklist.fake_routes);
    root["blacklist"]["fake_routes"] = fake_routes;

    root["ban"]["enabled"] = config.ban.enabled;
    root["ban"]["threshold"] = config.ban.threshold;
    root["ban"]["ban_duration_hours"] = config.ban.ban_duration_hours;
    YAML::Node scores;
    for (const auto& [name, points] : config.ban.scores) {
        scores[name] = points;
    }
    root["ban"]["scores"] = scores;

    root["speed_check"]["enabled"] = config.speed_check.enabled;
    root["speed_check"]["max_requests"] = config.speed_check.max_requests;
    root["speed_check"]["window_seconds"] = config.speed_check.window_seconds;

    root["method_check"]["enabled"] = config.method_check.enabled;
    root["method_check"]["allowed_methods"] = config.method_check.allowed_methods;

    root["pages"]["blocked_html"] = config.pages.blocked_html;
    root["pages"]["banned_html"] = config.pages.banned_html;
    YAML::Node status_pages(YAML::NodeType::Sequence);
    for (const auto& entry : config.pages.status_pages) {
        YAML::Node item;
        item["code"] = entry.code;
        item["html"] = entry.html;
        item["created_at"] = format_timestamp(entry.created_at);
        status_pages.push_back(item);
    }
    root["pages"]["status_pages"] = status_pages;

    root["request_log"]["enabled"] = config.request_log.enabled;
    root["request_log"]["csv_path"] = config.request_log.csv_path;

    root["geoip"]["mmdb_path"] = config.geoip.mmdb_path;
    root["geoip"]["asn_mmdb_path"] = config.geoip.asn_mmdb_path;

    root["globe"]["public_enabled"] = config.globe.public_enabled;
    root["globe"]["public_bind"] = config.globe.public_bind_host;
    root["globe"]["public_port"] = config.globe.public_port;
    root["globe"]["public_tls_cert_file"] = config.globe.public_tls_cert_file;
    root["globe"]["public_tls_key_file"] = config.globe.public_tls_key_file;
    root["globe"]["server_lat"] =
        config.globe.server_lat ? YAML::Node(*config.globe.server_lat) : YAML::Node(YAML::Null);
    root["globe"]["server_lon"] =
        config.globe.server_lon ? YAML::Node(*config.globe.server_lon) : YAML::Node(YAML::Null);
    root["globe"]["auto_detect_server_location"] = config.globe.auto_detect_server_location;
    root["globe"]["history_size"] = config.globe.history_size;

    YAML::Emitter emitter;
    emitter << root;
    return std::string(emitter.c_str());
}

} // namespace atomwall
