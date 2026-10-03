#include <boost/asio/ip/address.hpp>
#include <catch2/catch_test_macros.hpp>

#include "pipeline/checks.hpp"
#include "pipeline/net_utils.hpp"

using namespace atomwall;
namespace net = boost::asio;

namespace {

http::request_header<http::fields> header_with_user_agent(std::string_view ua) {
    http::request<http::empty_body> req;
    if (!ua.empty()) {
        req.set(http::field::user_agent, ua);
    }
    return req.base();
}

http::request_header<http::fields> header_with_referrer(std::string_view referrer) {
    http::request<http::empty_body> req;
    if (!referrer.empty()) {
        req.set(http::field::referer, referrer);
    }
    return req.base();
}

http::request_header<http::fields> header_with_sec_fetch_dest(std::string_view dest) {
    http::request<http::empty_body> req;
    if (!dest.empty()) {
        req.set("Sec-Fetch-Dest", dest);
    }
    return req.base();
}

const http::request_header<http::fields> kNoHeaders = header_with_sec_fetch_dest("");

} // namespace

TEST_CASE("check_ip_blacklist allows by default", "[checks]") {
    BlacklistConfig config;
    CHECK_FALSE(check_ip_blacklist(config, net::ip::make_address("203.0.113.7")).blocked());
}

TEST_CASE("check_ip_blacklist blocks an exact match", "[checks]") {
    BlacklistConfig config;
    config.ip_exact = {BlacklistEntry{"203.0.113.7"}};
    CHECK(check_ip_blacklist(config, net::ip::make_address("203.0.113.7")).blocked());
    CHECK_FALSE(check_ip_blacklist(config, net::ip::make_address("203.0.113.8")).blocked());
}

TEST_CASE("check_ip_blacklist blocks a CIDR match", "[checks]") {
    BlacklistConfig config;
    auto range = parse_cidr("198.51.100.0/24");
    REQUIRE(range.has_value());
    config.ip_cidrs = {*range};
    CHECK(check_ip_blacklist(config, net::ip::make_address("198.51.100.5")).blocked());
    CHECK_FALSE(check_ip_blacklist(config, net::ip::make_address("198.51.101.5")).blocked());
}

TEST_CASE("check_user_agent_blacklist matches case-insensitively", "[checks]") {
    BlacklistConfig config;
    config.user_agents = {BlacklistEntry{"sqlmap"}};
    CHECK(check_user_agent_blacklist(config, header_with_user_agent("SQLMap/1.6")).blocked());
    CHECK_FALSE(check_user_agent_blacklist(config, header_with_user_agent("Mozilla/5.0")).blocked());
}

TEST_CASE("check_user_agent_blacklist allows requests with no User-Agent header", "[checks]") {
    BlacklistConfig config;
    config.user_agents = {BlacklistEntry{"sqlmap"}};
    CHECK_FALSE(check_user_agent_blacklist(config, header_with_user_agent("")).blocked());
}

TEST_CASE("check_referrer_blacklist matches case-insensitively", "[checks]") {
    BlacklistConfig config;
    config.referrers = {BlacklistEntry{"spam-site.example"}};
    CHECK(check_referrer_blacklist(config, header_with_referrer("https://SPAM-SITE.example/page")).blocked());
    CHECK_FALSE(check_referrer_blacklist(config, header_with_referrer("https://good-site.example/")).blocked());
}

TEST_CASE("check_referrer_blacklist allows requests with no Referer header", "[checks]") {
    BlacklistConfig config;
    config.referrers = {BlacklistEntry{"spam-site.example"}};
    CHECK_FALSE(check_referrer_blacklist(config, header_with_referrer("")).blocked());
}

TEST_CASE("check_body_blacklist matches a configured pattern", "[checks]") {
    BlacklistConfig config;
    config.body_patterns = {BlacklistEntry{"<script>"}};
    CHECK(check_body_blacklist(config, "hello <SCRIPT>alert(1)</script> world").blocked());
    CHECK_FALSE(check_body_blacklist(config, "just plain text").blocked());
}

TEST_CASE("check_country_blacklist is stubbed to always allow", "[checks]") {
    BlacklistConfig config;
    config.countries = {BlacklistEntry{"XX"}};
    auto ip = net::ip::make_address("203.0.113.7");
    CHECK_FALSE(check_country_blacklist(config, ip).blocked());
}

TEST_CASE("check_isp_blacklist matches case-insensitively", "[checks]") {
    BlacklistConfig config;
    config.isps = {BlacklistEntry{"evil isp"}};
    CHECK(check_isp_blacklist(config, "Evil ISP Networks LLC").blocked());
    CHECK_FALSE(check_isp_blacklist(config, "Good ISP Inc").blocked());
}

TEST_CASE("check_isp_blacklist allows an empty (unresolved) isp even when isps is configured", "[checks]") {
    BlacklistConfig config;
    config.isps = {BlacklistEntry{"evil isp"}};
    CHECK_FALSE(check_isp_blacklist(config, "").blocked());
}

TEST_CASE("evaluate_header_checks short-circuits on the first block", "[checks]") {
    BlacklistConfig config;
    config.ip_exact = {BlacklistEntry{"203.0.113.7"}};
    config.user_agents = {BlacklistEntry{"sqlmap"}};

    auto blocked_ip = net::ip::make_address("203.0.113.7");
    auto result = evaluate_header_checks(config, blocked_ip, "/", header_with_user_agent("sqlmap"), "");
    REQUIRE(result.blocked());
    CHECK(result.check_name == "ip_blacklist");
}

TEST_CASE("evaluate_header_checks allows a clean request", "[checks]") {
    BlacklistConfig config;
    config.ip_exact = {BlacklistEntry{"203.0.113.7"}};
    config.user_agents = {BlacklistEntry{"sqlmap"}};

    auto clean_ip = net::ip::make_address("198.51.100.1");
    auto result = evaluate_header_checks(config, clean_ip, "/", header_with_user_agent("Mozilla/5.0"), "");
    CHECK_FALSE(result.blocked());
}

TEST_CASE("evaluate_header_checks blocks on an isp_blacklist match", "[checks]") {
    BlacklistConfig config;
    config.isps = {BlacklistEntry{"evil isp"}};
    auto ip = net::ip::make_address("198.51.100.1");
    auto result = evaluate_header_checks(config, ip, "/", header_with_user_agent(""), "Evil ISP Networks LLC");
    REQUIRE(result.blocked());
    CHECK(result.check_name == "isp_blacklist");
}

TEST_CASE("check_route_blacklist matches a configured path pattern", "[checks]") {
    BlacklistConfig config;
    config.routes = {BlacklistEntry{"/wp-admin"}};
    CHECK(check_route_blacklist(config, "/wp-admin/setup.php").blocked());
    CHECK_FALSE(check_route_blacklist(config, "/blog/index.html").blocked());
}

TEST_CASE("is_route_whitelisted matches a configured path pattern", "[checks]") {
    WhitelistConfig config;
    config.routes = {BlacklistEntry{"/healthz"}};
    CHECK(is_route_whitelisted(config, "/healthz"));
    CHECK(is_route_whitelisted(config, "/healthz/live"));
    CHECK_FALSE(is_route_whitelisted(config, "/blog/index.html"));
}

TEST_CASE("is_route_whitelisted allows by default with no configured routes", "[checks]") {
    WhitelistConfig config;
    CHECK_FALSE(is_route_whitelisted(config, "/anything"));
}

TEST_CASE("check_fake_routes matches by prefix", "[checks]") {
    BlacklistConfig config;
    config.fake_routes = {BlacklistEntry{"/wp-login-backup"}};
    CHECK(check_fake_routes(config, "/wp-login-backup").blocked());
    CHECK(check_fake_routes(config, "/wp-login-backup/extra").blocked());
    CHECK_FALSE(check_fake_routes(config, "/wp-login").blocked());
    CHECK_FALSE(check_fake_routes(config, "/").blocked());
}

TEST_CASE("check_fake_routes matches case-insensitively", "[checks]") {
    // Fake routes are published verbatim in /robots.txt (public, unauthenticated),
    // so an attacker can read the exact pattern and try to dodge detection with a
    // case variant — matching must be case-insensitive like every other blacklist
    // check (route_blacklist, user_agent_blacklist, ...) or that dodge works.
    BlacklistConfig config;
    config.fake_routes = {BlacklistEntry{"/wp-login-backup"}};
    CHECK(check_fake_routes(config, "/WP-LOGIN-BACKUP").blocked());
    CHECK(check_fake_routes(config, "/Wp-Login-Backup/extra").blocked());
}

TEST_CASE("evaluate_header_checks blocks and names a fake route hit", "[checks]") {
    BlacklistConfig config;
    config.fake_routes = {BlacklistEntry{"/secret-trap"}};
    auto ip = net::ip::make_address("198.51.100.1");
    auto result = evaluate_header_checks(config, ip, "/secret-trap", header_with_user_agent(""), "");
    REQUIRE(result.blocked());
    CHECK(result.check_name == "fake_route");
}

TEST_CASE("evaluate_header_checks strips the query string before matching routes", "[checks]") {
    BlacklistConfig config;
    config.routes = {BlacklistEntry{"/admin"}};
    auto ip = net::ip::make_address("198.51.100.1");
    // The path itself doesn't match "/admin" — only the query string does —
    // so this must NOT be blocked (route checks match path only, not query).
    auto result = evaluate_header_checks(config, ip, "/search", header_with_user_agent(""), "");
    CHECK_FALSE(result.blocked());
}

TEST_CASE("is_navigation_request trusts Sec-Fetch-Dest when present", "[checks]") {
    CHECK(is_navigation_request(header_with_sec_fetch_dest("document"), "/"));
    CHECK(is_navigation_request(header_with_sec_fetch_dest("Document"), "/anything.js")); // case-insensitive
    CHECK_FALSE(is_navigation_request(header_with_sec_fetch_dest("script"), "/"));
    CHECK_FALSE(is_navigation_request(header_with_sec_fetch_dest("image"), "/"));
    CHECK_FALSE(is_navigation_request(header_with_sec_fetch_dest("style"), "/"));
}

TEST_CASE("is_navigation_request falls back to extension sniffing without Sec-Fetch-Dest", "[checks]") {
    CHECK(is_navigation_request(kNoHeaders, "/"));
    CHECK(is_navigation_request(kNoHeaders, "/articles/hello-world"));
    CHECK_FALSE(is_navigation_request(kNoHeaders, "/static/app.js"));
    CHECK_FALSE(is_navigation_request(kNoHeaders, "/static/app.JS")); // case-insensitive
    CHECK_FALSE(is_navigation_request(kNoHeaders, "/img/logo.png"));
    CHECK_FALSE(is_navigation_request(kNoHeaders, "/fonts/regular.woff2"));
}

TEST_CASE("check_request_rate allows when disabled, regardless of volume", "[checks]") {
    SpeedCheckConfig config;
    config.enabled = false;
    config.max_requests = 1;
    RequestRateTracker tracker;
    auto ip = net::ip::make_address("203.0.113.7");
    const auto now = std::chrono::steady_clock::now();
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
}

TEST_CASE("check_request_rate allows requests within the configured rate", "[checks]") {
    SpeedCheckConfig config;
    config.enabled = true;
    config.max_requests = 3;
    config.window_seconds = 10;
    RequestRateTracker tracker;
    auto ip = net::ip::make_address("203.0.113.7");
    const auto now = std::chrono::steady_clock::now();
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
}

TEST_CASE("check_request_rate blocks once the request exceeds the configured rate", "[checks]") {
    SpeedCheckConfig config;
    config.enabled = true;
    config.max_requests = 2;
    config.window_seconds = 10;
    RequestRateTracker tracker;
    auto ip = net::ip::make_address("203.0.113.7");
    const auto now = std::chrono::steady_clock::now();
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
    auto result = check_request_rate(config, tracker, ip, "/", kNoHeaders, now);
    REQUIRE(result.blocked());
    CHECK(result.check_name == "speed_check");
}

TEST_CASE("check_request_rate tracks IPs independently", "[checks]") {
    SpeedCheckConfig config;
    config.enabled = true;
    config.max_requests = 1;
    config.window_seconds = 10;
    RequestRateTracker tracker;
    auto ip_a = net::ip::make_address("203.0.113.7");
    auto ip_b = net::ip::make_address("203.0.113.8");
    const auto now = std::chrono::steady_clock::now();
    CHECK_FALSE(check_request_rate(config, tracker, ip_a, "/", kNoHeaders, now).blocked());
    CHECK_FALSE(check_request_rate(config, tracker, ip_b, "/", kNoHeaders, now).blocked());
}

TEST_CASE("check_request_rate never counts or blocks subresource requests", "[checks]") {
    SpeedCheckConfig config;
    config.enabled = true;
    config.max_requests = 2;
    config.window_seconds = 10;
    RequestRateTracker tracker;
    auto ip = net::ip::make_address("203.0.113.7");
    const auto now = std::chrono::steady_clock::now();
    for (int i = 0; i < 10; ++i) {
        CHECK_FALSE(check_request_rate(config, tracker, ip, "/static/app.js", kNoHeaders, now).blocked());
    }
    for (int i = 0; i < 10; ++i) {
        CHECK_FALSE(
            check_request_rate(config, tracker, ip, "/", header_with_sec_fetch_dest("image"), now).blocked());
    }
    // A real navigation still starts counting from zero afterward, proving
    // none of the subresource requests above were recorded into the window.
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
    CHECK_FALSE(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
    CHECK(check_request_rate(config, tracker, ip, "/", kNoHeaders, now).blocked());
}

TEST_CASE("check_body_size allows when under the limit or when disabled", "[checks]") {
    BlacklistConfig config;
    CHECK_FALSE(check_body_size(config, 1'000'000).blocked()); // disabled (0 = no limit)
    config.max_body_size_bytes = 100;
    CHECK_FALSE(check_body_size(config, 100).blocked());
}

TEST_CASE("check_body_size blocks when over the limit", "[checks]") {
    BlacklistConfig config;
    config.max_body_size_bytes = 100;
    auto result = check_body_size(config, 101);
    REQUIRE(result.blocked());
    CHECK(result.check_name == "body_size_limit");
}

TEST_CASE("evaluate_body_checks runs size before pattern matching", "[checks]") {
    BlacklistConfig config;
    config.max_body_size_bytes = 5;
    config.body_patterns = {BlacklistEntry{"evil"}};
    auto result = evaluate_body_checks(config, "evil-but-long-body");
    REQUIRE(result.blocked());
    CHECK(result.check_name == "body_size_limit");
}

TEST_CASE("a dual-stack IPv4 client is matched by IPv4 blacklist entries once normalized", "[checks]") {
    BlacklistConfig config;
    config.ip_exact = {BlacklistEntry{"203.0.113.7"}};
    auto range = parse_cidr("198.51.100.0/24");
    REQUIRE(range.has_value());
    config.ip_cidrs = {*range};

    const auto mapped_exact = net::ip::make_address("::ffff:203.0.113.7");
    const auto mapped_cidr = net::ip::make_address("::ffff:198.51.100.9");
    // As it appears on the socket of a "::"-bound listener: the v4 rules miss it...
    CHECK_FALSE(check_ip_blacklist(config, mapped_exact).blocked());
    CHECK_FALSE(check_ip_blacklist(config, mapped_cidr).blocked());
    // ...which is why the listeners normalize before any check sees the address.
    CHECK(check_ip_blacklist(config, normalize_client_address(mapped_exact)).blocked());
    CHECK(check_ip_blacklist(config, normalize_client_address(mapped_cidr)).blocked());
}

TEST_CASE("check_method_allowlist allows anything while disabled", "[checks]") {
    MethodCheckConfig config;
    config.enabled = false;
    config.allowed_methods = {"GET"};
    CHECK_FALSE(check_method_allowlist(config, "TRACE").blocked());
}

TEST_CASE("check_method_allowlist matches methods case-insensitively", "[checks]") {
    MethodCheckConfig config;
    config.enabled = true;
    config.allowed_methods = {"GET", "POST"};
    CHECK_FALSE(check_method_allowlist(config, "GET").blocked());
    CHECK_FALSE(check_method_allowlist(config, "post").blocked());
    CHECK(check_method_allowlist(config, "DELETE").blocked());
}

TEST_CASE("check_method_allowlist's reason names the configured rule, never the client's method", "[checks]") {
    MethodCheckConfig config;
    config.enabled = true;
    config.allowed_methods = {"GET", "HEAD"};
    const auto result = check_method_allowlist(config, "X-SUPER-SECRET-VERB");
    REQUIRE(result.blocked());
    CHECK(result.check_name == "method_not_allowed");
    CHECK(result.reason == "method not in allowlist [GET, HEAD]");
    CHECK(result.reason.find("SECRET") == std::string::npos);
}
