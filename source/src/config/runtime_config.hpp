#pragma once

#include <boost/asio/ip/address.hpp>
#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace atomwall {

struct HttpListenerConfig {
    bool enabled = true;
    std::string bind_host = "0.0.0.0";
    unsigned short port = 80;
};

struct HttpsListenerConfig {
    bool enabled = true;
    std::string bind_host = "0.0.0.0";
    unsigned short port = 443;
    std::string cert_file = "certs/dev.crt";
    std::string key_file = "certs/dev.key";
};

struct UpstreamConfig {
    std::string host = "127.0.0.1";
    unsigned short port = 8000;
};

// One additional domain layered on top of the default site (the top-level
// https.cert_file/key_file + upstream.host/port). Matched by exact,
// case-insensitive equality against the Host header / TLS SNI name — never
// substring — so a request can't spoof a match (e.g. "example.com.evil.com"
// must never match "example.com"). A request whose Host doesn't match any
// entry here falls back to the default site, same as today's single-site
// behavior. `enabled=false` still completes the TLS handshake (using this
// site's own cert, so the connection doesn't fail before it can be answered)
// but is blocked at the HTTP layer once the Host header is readable — see
// listener/http_session.hpp. Blacklists, ban/scoring, and every other
// pipeline setting stay global and apply to every site, named or default.
struct SiteConfig {
    std::string domain;
    bool enabled = true;
    std::string cert_file;
    std::string key_file;
    UpstreamConfig upstream;
};

struct AdminConfig {
    bool enabled = true;
    std::string bind_host = "127.0.0.1";
    unsigned short port = 9000;
    std::string static_dir = "webui";
    // Both empty = plain HTTP, loopback-only (the default). Setting both is
    // the ONLY way admin.bind is allowed to be non-loopback — see
    // run_admin_server(). TLS is a hard precondition for exposing the admin
    // API beyond loopback.
    std::string tls_cert_file;
    std::string tls_key_file;
};

struct LimitsConfig {
    std::size_t max_header_bytes = 16 * 1024;
    std::size_t max_body_bytes = 10 * 1024 * 1024;
    std::chrono::seconds upstream_connect_timeout{5};
    std::chrono::seconds request_timeout{30};
};

struct CidrRange {
    boost::asio::ip::address prefix;
    unsigned prefix_len = 0;
    std::string text;
    std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now();
    std::string source = "manual"; // "manual" (single add) | "list" (bulk .list/URL import)
};

// A single blacklist value plus when it was added. Old configs (or entries
// created before this field existed) get `created_at` backfilled to load time
// on first read — there's no way to recover a true historical timestamp for
// those, see yaml_codec.cpp.
struct BlacklistEntry {
    std::string value;
    std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now();
    std::string created_by; // admin username, empty for entries added before this field existed
    std::string source = "manual"; // "manual" (single add) | "list" (bulk .list/URL import) —
                                    // entries from before this field existed default to "manual"
};

struct BlacklistConfig {
    // Permanent only — temporary IP/CIDR blocks (manual-with-duration or
    // score-triggered) live in the in-memory IpBlockTracker instead.
    std::vector<BlacklistEntry> ip_exact;
    std::vector<CidrRange> ip_cidrs;
    std::vector<BlacklistEntry> routes;
    std::vector<BlacklistEntry> countries;
    std::vector<BlacklistEntry> isps;
    std::vector<BlacklistEntry> user_agents;
    std::vector<BlacklistEntry> referrers;
    std::vector<BlacklistEntry> body_patterns;
    // Honeypot paths: never linked from real content, advertised only via
    // robots.txt's Disallow list (see listener/http_session.hpp and
    // pipeline/robots_txt.hpp's build_robots_txt_body, which merges these in
    // alongside RobotsTxtConfig::custom_content — extending the site's real
    // robots.txt, never replacing it). A well-behaved crawler never requests
    // one; anything that does is almost certainly ignoring robots.txt, so a
    // hit is blocked and scored via BanConfig::scores["fake_route"] rather
    // than treated as a normal route_blacklist match. Prefix-matched against
    // the request path, same as robots.txt's own Disallow semantics.
    std::vector<BlacklistEntry> fake_routes;
    // Soft, admin-configurable limit distinct from limits.max_body_bytes:
    // exceeding this scores + 403s cleanly instead of aborting the read.
    // 0 = disabled (only the hard max_body_bytes cap applies).
    std::size_t max_body_size_bytes = 0;
};

// Exact IPs or CIDR ranges that bypass every blocking check entirely — the
// temporary-block gate (IpBlockTracker), header-phase checks, and body-phase
// checks alike (see run_http_session in listener/http_session.hpp). Deliberately
// no temporary/duration variant like the IP blacklist has: a whitelist entry is
// always permanent until an admin removes it — "never blocked, no matter what"
// wouldn't hold if it could silently expire.
//
// `routes` is the same "never blocked, no matter what" contract keyed by
// request path instead of client IP — case-insensitive substring match
// against the path (same semantics as BlacklistConfig::routes), checked via
// is_route_whitelisted (pipeline/checks.hpp) and OR'd into the same
// is_whitelisted gate as the IP whitelist in run_http_session. A route here
// bypasses every check for every visitor, not just a specific IP — meant for
// things like a health-check endpoint that must never 403, regardless of who
// or what is polling it.
struct WhitelistConfig {
    std::vector<BlacklistEntry> ip_exact;
    std::vector<CidrRange> ip_cidrs;
    std::vector<BlacklistEntry> routes;
};

// Upper bound for any temporary-ban duration. Anything longer is what the
// permanent (YAML) blacklist is for, and an unbounded hours count isn't just
// silly: added to system_clock::now() it overflows the clock's int64 tick
// arithmetic (~292 years in nanoseconds), wrapping the expiry into the past so
// a "very long" ban silently becomes no ban at all.
constexpr int kMaxBanDurationHours = 24 * 365 * 10;

// Per-check-name point values, a threshold, and how long a threshold-crossing
// ban lasts. Checks not present in `scores` (or scored 0) don't contribute.
struct BanConfig {
    bool enabled = false;
    int threshold = 100;
    int ban_duration_hours = 24;
    std::map<std::string, int> scores = {
        {"route_blacklist", 50},   {"user_agent_blacklist", 100}, {"body_blacklist", 75},
        {"body_size_limit", 60},   {"country_blacklist", 25},     {"isp_blacklist", 25},
        {"speed_check", 40},       {"referrer_blacklist", 50},    {"fake_route", 100},
        {"method_not_allowed", 50},
    };
};

// Off by default. When enabled, any request whose method isn't in
// `allowed_methods` (case-insensitive, e.g. "GET", "POST") is blocked and
// scored (score name "method_not_allowed", see BanConfig above) — same
// block-and-score pattern as every other check. An empty allowed_methods
// list with enabled=true blocks every method, so the UI should refuse to
// save that combination.
struct MethodCheckConfig {
    bool enabled = false;
    std::vector<std::string> allowed_methods = {"GET", "POST", "HEAD"};
};

// Flags a client IP as navigating too fast: more than `max_requests` requests
// within a sliding `window_seconds` window. Off by default. Stateful (unlike
// the header/body blacklist checks) — see history/request_rate_tracker.hpp.
// Only page navigations count (see is_navigation_request in pipeline/checks.hpp),
// not the subresources a page pulls in. That classification rests on the
// client-supplied Sec-Fetch-Dest header, so a scripted client that lies about it
// isn't counted: this catches fast browsing, not a determined non-browser abuser.
struct SpeedCheckConfig {
    bool enabled = false;
    int max_requests = 20;
    int window_seconds = 10;
};

// Site-wide kill switch. Off by default. When enabled, every request on the
// public HTTP/HTTPS listeners gets a blank HTML page — checked first in
// run_http_session, before the temporary-block gate, the whitelist, and
// every other pipeline check, since "take the protected site offline" is
// meant to override all of them, not compete with them. Never touches the
// admin UI/API — that's a separate listener/port entirely, so admins can always still reach it to flip this back off.
struct EmergencyOffConfig {
    bool enabled = false;
};

// One admin-defined status-code page override, see ResponsePagesConfig::status_pages.
struct StatusPageEntry {
    int code = 0;
    std::string html;
    std::chrono::system_clock::time_point created_at = std::chrono::system_clock::now();
};

// Empty string = use the built-in default page (see listener/http_session.hpp).
struct ResponsePagesConfig {
    std::string blocked_html;
    std::string banned_html;
    // Admin-defined HTML overrides keyed by HTTP status code (e.g. 404, 503),
    // applied when the *upstream's* response carries that status — replacing
    // only the body, never the status code itself, so the origin's original
    // HTTP semantics still reach the client. Distinct from blocked_html/
    // banned_html above, which are atomwall's own policy-decision pages, not
    // origin-response overrides — see listener/http_session.hpp.
    std::vector<StatusPageEntry> status_pages;
};

// Empty custom_content = atomwall passes /robots.txt straight through to the
// origin untouched (when there are also no fake_routes to advertise — see
// listener/http_session.hpp's build_robots_txt_body) — the same "no honeypot
// routes configured, no change to default behavior" contract as before this
// field existed. A non-empty value is the admin's own robots.txt text (they
// paste in whatever their site already serves), which atomwall then extends
// with a Disallow line per configured fake_route rather than ever discarding
// it — "extend the real file," never "replace it with just the honeypot
// entries" (the previous, since-fixed behavior).
struct RobotsTxtConfig {
    std::string custom_content;
};

// Off by default. When enabled, every RequestEvent recorded to the in-memory
// RequestLog ring buffer is also appended to `csv_path` so request history
// survives a restart (the ring buffer itself doesn't). Writes are batched (100 events per flush) and happen on a
// dedicated background thread inside RequestLog, never on the io_context
// thread handling the request.
struct RequestLogConfig {
    bool enabled = false;
    std::string csv_path = "config/requests.csv";
};

// Empty mmdb_path = GeoIP disabled: lookups return nullopt, country stays
// "unknown" in RequestLog, and no globe arcs are recorded (see geoip/geoip_service.hpp).
struct GeoIpConfig {
    std::string mmdb_path;
    // Separate ASN/ISP database (e.g. GeoLite2-ASN, DB-IP ASN Lite) — a
    // different product from the City database above, MaxMind and DB-IP
    // both ship it as its own .mmdb file. Empty = ISP stays "unknown", same
    // degrade-gracefully behavior as mmdb_path above.
    std::string asn_mmdb_path;
};

// Live visitor globe.
// Two independent surfaces read the same anonymized GlobeEventLog: the
// loopback admin API (always available) and this optional dedicated public
// listener, deliberately separate from both the public :80/:443 listeners
// and the loopback-only admin port.
struct GlobeConfig {
    bool public_enabled = false;
    std::string public_bind_host = "0.0.0.0";
    unsigned short public_port = 9443;
    // Both empty = plain HTTP. Embedding on an HTTPS page requires setting
    // these or the browser blocks the embed as mixed content.
    std::string public_tls_cert_file;
    std::string public_tls_key_file;
    // Manual override; if unset and auto_detect_server_location is true, a
    // one-time startup lookup fills these in (see main.cpp's
    // resolve_server_location) — never overwrites a manually-set value.
    std::optional<double> server_lat;
    std::optional<double> server_lon;
    bool auto_detect_server_location = true;
    std::size_t history_size = 500;
};

// Off by default (mirrors ban.enabled). When true, every user must have TOTP
// or a passkey enrolled before they can use anything in the admin API beyond
// auth/enrollment endpoints — see admin_server.cpp's needs_auth gate and
// SessionStore's needs_mfa_setup flag. A passwordless passkey login already
// satisfies this on its own; only a password login needs a follow-up
// second-factor step.
struct SecurityConfig {
    bool require_2fa = false;
};

struct RuntimeConfig {
    HttpListenerConfig http;
    HttpsListenerConfig https;
    UpstreamConfig upstream;
    std::vector<SiteConfig> sites;
    AdminConfig admin;
    LimitsConfig limits;
    BlacklistConfig blacklist;
    WhitelistConfig whitelist;
    BanConfig ban;
    SpeedCheckConfig speed_check;
    MethodCheckConfig method_check;
    EmergencyOffConfig emergency_off;
    ResponsePagesConfig pages;
    RequestLogConfig request_log;
    RobotsTxtConfig robots_txt;
    GeoIpConfig geoip;
    GlobeConfig globe;
    SecurityConfig security;
};

} // namespace atomwall
