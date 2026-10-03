#include "pipeline/checks.hpp"

#include <algorithm>

#include "pipeline/net_utils.hpp"

namespace atomwall {

bool is_ip_whitelisted(const WhitelistConfig& config, const boost::asio::ip::address& client_ip) {
    const auto ip_text = client_ip.to_string();
    for (const auto& exact : config.ip_exact) {
        if (exact.value == ip_text) {
            return true;
        }
    }
    for (const auto& range : config.ip_cidrs) {
        if (address_in_cidr(client_ip, range)) {
            return true;
        }
    }
    return false;
}

bool is_route_whitelisted(const WhitelistConfig& config, std::string_view path) {
    for (const auto& pattern : config.routes) {
        if (icontains(path, pattern.value)) {
            return true;
        }
    }
    return false;
}

CheckResult check_ip_blacklist(const BlacklistConfig& config, const boost::asio::ip::address& client_ip) {
    const auto ip_text = client_ip.to_string();
    for (const auto& exact : config.ip_exact) {
        if (exact.value == ip_text) {
            return CheckResult::block("ip_blacklist", "exact match: " + exact.value);
        }
    }
    for (const auto& range : config.ip_cidrs) {
        if (address_in_cidr(client_ip, range)) {
            return CheckResult::block("ip_blacklist", "cidr match: " + range.text);
        }
    }
    return CheckResult::allow();
}

CheckResult check_route_blacklist(const BlacklistConfig& config, std::string_view path) {
    for (const auto& pattern : config.routes) {
        if (icontains(path, pattern.value)) {
            return CheckResult::block("route_blacklist", "pattern match: " + pattern.value);
        }
    }
    return CheckResult::allow();
}

CheckResult check_fake_routes(const BlacklistConfig& config, std::string_view path) {
    for (const auto& route : config.fake_routes) {
        if (istarts_with(path, route.value)) {
            return CheckResult::block("fake_route", "honeypot path: " + route.value);
        }
    }
    return CheckResult::allow();
}

CheckResult check_country_blacklist(const BlacklistConfig&, const boost::asio::ip::address&) {
    // No GeoIP/ASN data source wired in yet. Always allows
    // for now; configured country entries are inert until a lookup source is chosen.
    return CheckResult::allow();
}

CheckResult check_isp_blacklist(const BlacklistConfig& config, std::string_view isp) {
    if (isp.empty()) {
        return CheckResult::allow();
    }
    for (const auto& pattern : config.isps) {
        if (icontains(isp, pattern.value)) {
            return CheckResult::block("isp_blacklist", "pattern match: " + pattern.value);
        }
    }
    return CheckResult::allow();
}

CheckResult check_user_agent_blacklist(const BlacklistConfig& config,
                                        const http::request_header<http::fields>& header) {
    const auto it = header.find(http::field::user_agent);
    if (it == header.end()) {
        return CheckResult::allow();
    }
    const std::string_view user_agent = it->value();
    for (const auto& pattern : config.user_agents) {
        if (icontains(user_agent, pattern.value)) {
            return CheckResult::block("user_agent_blacklist", "pattern match: " + pattern.value);
        }
    }
    return CheckResult::allow();
}

CheckResult check_referrer_blacklist(const BlacklistConfig& config,
                                      const http::request_header<http::fields>& header) {
    const auto it = header.find(http::field::referer);
    if (it == header.end()) {
        return CheckResult::allow();
    }
    const std::string_view referrer = it->value();
    for (const auto& pattern : config.referrers) {
        if (icontains(referrer, pattern.value)) {
            return CheckResult::block("referrer_blacklist", "pattern match: " + pattern.value);
        }
    }
    return CheckResult::allow();
}

CheckResult check_method_allowlist(const MethodCheckConfig& config, std::string_view method) {
    if (!config.enabled) {
        return CheckResult::allow();
    }
    for (const auto& allowed : config.allowed_methods) {
        if (iequals(method, allowed)) {
            return CheckResult::allow();
        }
    }
    // Names the configured allowlist, not `method`: that's client-supplied and this
    // reason is logged. The
    // offending method is already recorded on the request itself.
    std::string allowed_list;
    for (const auto& allowed : config.allowed_methods) {
        allowed_list += allowed_list.empty() ? "" : ", ";
        allowed_list += allowed;
    }
    return CheckResult::block("method_not_allowed", "method not in allowlist [" + allowed_list + "]");
}

namespace {

// Extensions a browser only ever requests as a page's embedded resource,
// never as the address-bar navigation itself. Used as the fallback signal
// below when Sec-Fetch-Dest isn't present (older browsers, curl, bots).
bool has_static_asset_extension(std::string_view path) {
    static constexpr std::string_view kExtensions[] = {
        ".js",   ".mjs",  ".css",  ".map",  ".png",  ".jpg", ".jpeg", ".gif",
        ".svg",  ".ico",  ".webp", ".avif", ".woff", ".woff2", ".ttf", ".otf",
        ".eot",  ".mp4",  ".webm", ".mp3",  ".wav",  ".json",
    };
    const auto dot = path.find_last_of('.');
    if (dot == std::string_view::npos) {
        return false;
    }
    const auto extension = path.substr(dot);
    for (const auto& candidate : kExtensions) {
        if (iequals(extension, candidate)) {
            return true;
        }
    }
    return false;
}

} // namespace

bool is_navigation_request(const http::request_header<http::fields>& header, std::string_view path) {
    // Fetch Metadata: every modern browser sends this on every request, and
    // it's authoritative when present — "document" is exactly "the user
    // navigated here" (address bar, link, form submit, top-level redirect),
    // as opposed to "iframe", "script", "style", "image", "font", etc.
    const auto it = header.find("Sec-Fetch-Dest");
    if (it != header.end()) {
        return iequals(it->value(), "document");
    }
    return !has_static_asset_extension(path);
}

CheckResult check_request_rate(const SpeedCheckConfig& config, RequestRateTracker& tracker,
                                const boost::asio::ip::address& client_ip,
                                std::string_view path,
                                const http::request_header<http::fields>& header,
                                std::chrono::steady_clock::time_point now) {
    if (!config.enabled) {
        return CheckResult::allow();
    }
    if (!is_navigation_request(header, path)) {
        return CheckResult::allow();
    }
    const auto count =
        tracker.record(client_ip.to_string(), now, std::chrono::seconds(config.window_seconds));
    if (static_cast<int>(count) > config.max_requests) {
        return CheckResult::block(
            "speed_check", std::to_string(count) + " requests in " +
                               std::to_string(config.window_seconds) + "s exceeds limit " +
                               std::to_string(config.max_requests));
    }
    return CheckResult::allow();
}

CheckResult check_body_size(const BlacklistConfig& config, std::size_t body_size) {
    if (config.max_body_size_bytes > 0 && body_size > config.max_body_size_bytes) {
        return CheckResult::block(
            "body_size_limit",
            "body size " + std::to_string(body_size) + " exceeds limit " +
                std::to_string(config.max_body_size_bytes));
    }
    return CheckResult::allow();
}

CheckResult check_body_blacklist(const BlacklistConfig& config, std::string_view body) {
    for (const auto& pattern : config.body_patterns) {
        if (icontains(body, pattern.value)) {
            return CheckResult::block("body_blacklist", "pattern match: " + pattern.value);
        }
    }
    return CheckResult::allow();
}

CheckResult evaluate_header_checks(const BlacklistConfig& config,
                                    const boost::asio::ip::address& client_ip,
                                    std::string_view path,
                                    const http::request_header<http::fields>& header,
                                    std::string_view isp) {
    if (auto result = check_ip_blacklist(config, client_ip); result.blocked()) {
        return result;
    }
    if (auto result = check_route_blacklist(config, path); result.blocked()) {
        return result;
    }
    if (auto result = check_fake_routes(config, path); result.blocked()) {
        return result;
    }
    if (auto result = check_country_blacklist(config, client_ip); result.blocked()) {
        return result;
    }
    if (auto result = check_isp_blacklist(config, isp); result.blocked()) {
        return result;
    }
    if (auto result = check_user_agent_blacklist(config, header); result.blocked()) {
        return result;
    }
    if (auto result = check_referrer_blacklist(config, header); result.blocked()) {
        return result;
    }
    return CheckResult::allow();
}

CheckResult evaluate_body_checks(const BlacklistConfig& config, std::string_view body) {
    if (auto result = check_body_size(config, body.size()); result.blocked()) {
        return result;
    }
    if (auto result = check_body_blacklist(config, body); result.blocked()) {
        return result;
    }
    return CheckResult::allow();
}

} // namespace atomwall
