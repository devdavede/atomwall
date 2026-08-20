#include "admin/json_view.hpp"

#include <cstdio>
#include <ctime>

namespace atomwall {

std::string to_iso8601(std::chrono::system_clock::time_point tp) {
    using namespace std::chrono;
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;
    const std::time_t tt = system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>(ms.count()));
    return buf;
}

boost::json::object request_event_to_json(const RequestEvent& event) {
    boost::json::object obj;
    obj["seq"] = event.seq;
    obj["timestamp"] = to_iso8601(event.timestamp);
    obj["client_ip"] = event.client_ip;
    obj["country"] = event.country;
    obj["isp"] = event.isp;
    obj["user_agent"] = event.user_agent;
    obj["method"] = event.method;
    obj["path"] = event.path;
    obj["domain"] = event.domain;
    obj["listener"] = event.listener;
    obj["blocked"] = event.blocked;
    obj["block_reason"] = event.block_reason;
    obj["status_code"] = event.status_code;
    obj["bytes_transferred"] = event.bytes_transferred;
    return obj;
}

boost::json::array request_events_to_json(const std::vector<RequestEvent>& events) {
    boost::json::array arr;
    for (const auto& event : events) {
        arr.push_back(request_event_to_json(event));
    }
    return arr;
}

boost::json::array entry_list_to_json(const std::vector<BlacklistEntry>& values) {
    boost::json::array arr;
    for (const auto& entry : values) {
        boost::json::object obj;
        obj["value"] = entry.value;
        obj["created_at"] = to_iso8601(entry.created_at);
        obj["created_by"] = entry.created_by;
        obj["source"] = entry.source;
        arr.push_back(obj);
    }
    return arr;
}

// Shared by ip_blacklist_to_json and whitelist_to_json — both are just "a
// list of exact IPs + a list of CIDR ranges" rendered the same way.
boost::json::array ip_entries_to_json(const std::vector<BlacklistEntry>& exact,
                                       const std::vector<CidrRange>& cidrs) {
    boost::json::array arr;
    for (const auto& entry : exact) {
        boost::json::object obj;
        obj["value"] = entry.value;
        obj["created_at"] = to_iso8601(entry.created_at);
        obj["created_by"] = entry.created_by;
        obj["source"] = entry.source;
        arr.push_back(obj);
    }
    for (const auto& range : cidrs) {
        boost::json::object obj;
        obj["value"] = range.text;
        obj["created_at"] = to_iso8601(range.created_at);
        obj["source"] = range.source;
        arr.push_back(obj);
    }
    return arr;
}

boost::json::array ip_blacklist_to_json(const BlacklistConfig& blacklist) {
    return ip_entries_to_json(blacklist.ip_exact, blacklist.ip_cidrs);
}

boost::json::array whitelist_to_json(const WhitelistConfig& whitelist) {
    return ip_entries_to_json(whitelist.ip_exact, whitelist.ip_cidrs);
}

boost::json::object blacklist_to_json(const BlacklistConfig& blacklist) {
    boost::json::object obj;
    obj["ips"] = ip_blacklist_to_json(blacklist);
    obj["routes"] = entry_list_to_json(blacklist.routes);
    obj["countries"] = entry_list_to_json(blacklist.countries);
    obj["isps"] = entry_list_to_json(blacklist.isps);
    obj["user_agents"] = entry_list_to_json(blacklist.user_agents);
    obj["referrers"] = entry_list_to_json(blacklist.referrers);
    obj["body_patterns"] = entry_list_to_json(blacklist.body_patterns);
    obj["fake_routes"] = entry_list_to_json(blacklist.fake_routes);
    obj["max_body_size_bytes"] = blacklist.max_body_size_bytes;
    return obj;
}

boost::json::array blacklist_category_to_json(const BlacklistConfig& blacklist,
                                               BlacklistCategory category) {
    switch (category) {
        case BlacklistCategory::Ips: return ip_blacklist_to_json(blacklist);
        case BlacklistCategory::Routes: return entry_list_to_json(blacklist.routes);
        case BlacklistCategory::Countries: return entry_list_to_json(blacklist.countries);
        case BlacklistCategory::Isps: return entry_list_to_json(blacklist.isps);
        case BlacklistCategory::UserAgents: return entry_list_to_json(blacklist.user_agents);
        case BlacklistCategory::Referrers: return entry_list_to_json(blacklist.referrers);
        case BlacklistCategory::BodyPatterns: return entry_list_to_json(blacklist.body_patterns);
        case BlacklistCategory::FakeRoutes: return entry_list_to_json(blacklist.fake_routes);
    }
    return {};
}

boost::json::array ip_blocks_to_json(const BlacklistConfig& blacklist,
                                      const std::vector<TemporaryIpBlock>& temporary) {
    boost::json::array arr;
    for (const auto& exact : blacklist.ip_exact) {
        boost::json::object obj;
        obj["text"] = exact.value;
        obj["source"] = exact.source;
        obj["permanent"] = true;
        obj["created_at"] = to_iso8601(exact.created_at);
        obj["expires_at"] = boost::json::value(nullptr);
        arr.push_back(obj);
    }
    for (const auto& range : blacklist.ip_cidrs) {
        boost::json::object obj;
        obj["text"] = range.text;
        obj["source"] = range.source;
        obj["permanent"] = true;
        obj["created_at"] = to_iso8601(range.created_at);
        obj["expires_at"] = boost::json::value(nullptr);
        arr.push_back(obj);
    }
    for (const auto& block : temporary) {
        boost::json::object obj;
        obj["text"] = block.text;
        obj["source"] = block.source;
        obj["permanent"] = false;
        obj["created_at"] = to_iso8601(block.created_at);
        obj["expires_at"] = to_iso8601(block.expires_at);
        obj["score_at_block"] = block.score_at_block;
        arr.push_back(obj);
    }
    return arr;
}

boost::json::object site_to_json(const SiteConfig& site) {
    boost::json::object obj;
    obj["domain"] = site.domain;
    obj["enabled"] = site.enabled;
    obj["cert_file"] = site.cert_file;
    obj["key_file"] = site.key_file;
    obj["upstream_host"] = site.upstream.host;
    obj["upstream_port"] = site.upstream.port;
    return obj;
}

boost::json::object sites_to_json(const RuntimeConfig& config) {
    boost::json::object default_site;
    default_site["cert_file"] = config.https.cert_file;
    default_site["key_file"] = config.https.key_file;
    default_site["upstream_host"] = config.upstream.host;
    default_site["upstream_port"] = config.upstream.port;

    boost::json::array sites;
    for (const auto& site : config.sites) {
        sites.push_back(site_to_json(site));
    }

    boost::json::object obj;
    obj["default_site"] = default_site;
    obj["sites"] = sites;
    return obj;
}

boost::json::object ban_config_to_json(const BanConfig& ban) {
    boost::json::object obj;
    obj["enabled"] = ban.enabled;
    obj["threshold"] = ban.threshold;
    obj["ban_duration_hours"] = ban.ban_duration_hours;
    boost::json::object scores;
    for (const auto& [name, points] : ban.scores) {
        scores[name] = points;
    }
    obj["scores"] = scores;
    return obj;
}

boost::json::object speed_check_to_json(const SpeedCheckConfig& speed_check) {
    boost::json::object obj;
    obj["enabled"] = speed_check.enabled;
    obj["max_requests"] = speed_check.max_requests;
    obj["window_seconds"] = speed_check.window_seconds;
    return obj;
}

boost::json::object method_check_to_json(const MethodCheckConfig& method_check) {
    boost::json::object obj;
    obj["enabled"] = method_check.enabled;
    boost::json::array methods;
    for (const auto& method : method_check.allowed_methods) {
        methods.push_back(boost::json::value(method));
    }
    obj["allowed_methods"] = methods;
    return obj;
}

boost::json::object status_page_to_json(const StatusPageEntry& entry) {
    boost::json::object obj;
    obj["code"] = entry.code;
    obj["html"] = entry.html;
    obj["created_at"] = to_iso8601(entry.created_at);
    return obj;
}

boost::json::array status_pages_to_json(const std::vector<StatusPageEntry>& entries) {
    boost::json::array arr;
    for (const auto& entry : entries) {
        arr.push_back(status_page_to_json(entry));
    }
    return arr;
}

boost::json::object pages_to_json(const ResponsePagesConfig& pages) {
    boost::json::object obj;
    obj["blocked_html"] = pages.blocked_html;
    obj["banned_html"] = pages.banned_html;
    obj["status_pages"] = status_pages_to_json(pages.status_pages);
    return obj;
}

boost::json::object request_log_config_to_json(const RequestLogConfig& request_log) {
    boost::json::object obj;
    obj["enabled"] = request_log.enabled;
    obj["csv_path"] = request_log.csv_path;
    return obj;
}

boost::json::object geoip_config_to_json(const GeoIpConfig& geoip, bool loaded, bool asn_loaded) {
    boost::json::object obj;
    obj["mmdb_path"] = geoip.mmdb_path;
    obj["loaded"] = loaded;
    obj["asn_mmdb_path"] = geoip.asn_mmdb_path;
    obj["asn_loaded"] = asn_loaded;
    return obj;
}

boost::json::object globe_config_to_json(const GlobeConfig& globe) {
    boost::json::object obj;
    obj["public_enabled"] = globe.public_enabled;
    obj["public_bind"] = globe.public_bind_host;
    obj["public_port"] = globe.public_port;
    obj["public_tls_cert_file"] = globe.public_tls_cert_file;
    obj["public_tls_key_file"] = globe.public_tls_key_file;
    obj["server_lat"] = globe.server_lat ? boost::json::value(*globe.server_lat) : boost::json::value(nullptr);
    obj["server_lon"] = globe.server_lon ? boost::json::value(*globe.server_lon) : boost::json::value(nullptr);
    obj["auto_detect_server_location"] = globe.auto_detect_server_location;
    obj["history_size"] = globe.history_size;
    return obj;
}

boost::json::object globe_event_to_json(const GlobeArcEvent& event) {
    boost::json::object obj;
    obj["seq"] = event.seq;
    obj["timestamp"] = to_iso8601(event.timestamp);
    obj["lat"] = event.lat;
    obj["lon"] = event.lon;
    obj["blocked"] = event.blocked;
    return obj;
}

boost::json::array globe_events_to_json(const std::vector<GlobeArcEvent>& events) {
    boost::json::array arr;
    for (const auto& event : events) {
        arr.push_back(globe_event_to_json(event));
    }
    return arr;
}

boost::json::value server_location_to_json(const std::optional<GeoLocation>& location) {
    if (!location) {
        return boost::json::value(nullptr);
    }
    boost::json::object obj;
    obj["lat"] = location->lat;
    obj["lon"] = location->lon;
    return obj;
}

boost::json::array users_to_json(const std::vector<UserRecord>& users) {
    boost::json::array arr;
    for (const auto& user : users) {
        boost::json::object obj;
        obj["username"] = user.username;
        obj["created_at"] = to_iso8601(user.created_at);
        arr.push_back(obj);
    }
    return arr;
}

boost::json::object login_event_to_json(const LoginEvent& event) {
    boost::json::object obj;
    obj["timestamp"] = to_iso8601(event.timestamp);
    obj["username"] = event.username;
    obj["client_ip"] = event.client_ip;
    return obj;
}

boost::json::array login_events_to_json(const std::vector<LoginEvent>& events) {
    boost::json::array arr;
    for (const auto& event : events) {
        arr.push_back(login_event_to_json(event));
    }
    return arr;
}

boost::json::object config_to_json(const RuntimeConfig& config) {
    boost::json::object obj;

    boost::json::object http;
    http["enabled"] = config.http.enabled;
    http["bind"] = config.http.bind_host;
    http["port"] = config.http.port;
    obj["http"] = http;

    boost::json::object https;
    https["enabled"] = config.https.enabled;
    https["bind"] = config.https.bind_host;
    https["port"] = config.https.port;
    https["cert_file"] = config.https.cert_file;
    https["key_file"] = config.https.key_file;
    obj["https"] = https;

    boost::json::object upstream;
    upstream["host"] = config.upstream.host;
    upstream["port"] = config.upstream.port;
    obj["upstream"] = upstream;

    boost::json::object admin;
    admin["enabled"] = config.admin.enabled;
    admin["bind"] = config.admin.bind_host;
    admin["port"] = config.admin.port;
    obj["admin"] = admin;

    boost::json::object limits;
    limits["max_header_bytes"] = config.limits.max_header_bytes;
    limits["max_body_bytes"] = config.limits.max_body_bytes;
    limits["upstream_connect_timeout_seconds"] = config.limits.upstream_connect_timeout.count();
    limits["request_timeout_seconds"] = config.limits.request_timeout.count();
    obj["limits"] = limits;

    obj["sites"] = sites_to_json(config);
    obj["blacklist"] = blacklist_to_json(config.blacklist);
    obj["whitelist"] = whitelist_to_json(config.whitelist);
    obj["ban"] = ban_config_to_json(config.ban);
    obj["speed_check"] = speed_check_to_json(config.speed_check);
    obj["method_check"] = method_check_to_json(config.method_check);
    obj["globe"] = globe_config_to_json(config.globe);

    return obj;
}

} // namespace atomwall
