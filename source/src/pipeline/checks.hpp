#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/beast/http.hpp>
#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>

#include "config/runtime_config.hpp"
#include "history/request_rate_tracker.hpp"

namespace atomwall {

namespace http = boost::beast::http;

enum class Verdict { Allow, Block };

struct CheckResult {
    Verdict verdict = Verdict::Allow;
    std::string_view check_name;
    std::string reason;

    static CheckResult allow() { return CheckResult{Verdict::Allow, {}, {}}; }
    static CheckResult block(std::string_view check_name, std::string reason) {
        return CheckResult{Verdict::Block, check_name, std::move(reason)};
    }
    bool blocked() const { return verdict == Verdict::Block; }
};

// Exact-or-CIDR match against WhitelistConfig — see its doc comment in
// runtime_config.hpp. Callers must check this before any blocking check runs
// (temp-block gate included) and skip all of them entirely on a match; it's
// intentionally not folded into evaluate_header_checks/CheckResult, since
// "allow, bypassing everything else" isn't representable by a single
// short-circuiting Allow/Block check in that pipeline.
bool is_ip_whitelisted(const WhitelistConfig& config, const boost::asio::ip::address& client_ip);

// Run in order against the request line + headers only, before the body is read.
CheckResult check_ip_blacklist(const BlacklistConfig& config, const boost::asio::ip::address& client_ip);
CheckResult check_route_blacklist(const BlacklistConfig& config, std::string_view path);
// Prefix match against `config.fake_routes` — same semantics as robots.txt's
// own Disallow directive (see listener/http_session.hpp, which advertises
// these paths there). A hit means something requested a path that's never
// linked from real content and was only ever named in robots.txt, so it's
// treated as a strong signal, not a normal route_blacklist match.
CheckResult check_fake_routes(const BlacklistConfig& config, std::string_view path);
CheckResult check_country_blacklist(const BlacklistConfig& config, const boost::asio::ip::address& client_ip);
// Matched against the ASN lookup's organization string (see
// geoip/asn_service.hpp), not the client IP directly — substring,
// case-insensitive, same semantics as check_user_agent_blacklist. An empty
// `isp` (ASN db not configured, or lookup miss for this client) never
// matches, same degrade-to-allow behavior as an unresolved country.
CheckResult check_isp_blacklist(const BlacklistConfig& config, std::string_view isp);
CheckResult check_user_agent_blacklist(const BlacklistConfig& config,
                                        const http::request_header<http::fields>& header);
CheckResult check_referrer_blacklist(const BlacklistConfig& config,
                                      const http::request_header<http::fields>& header);

// Stateful, unlike the checks above: tracks a sliding window of request
// timestamps per IP (via `tracker`) against `config`'s N-requests-per-M-seconds
// limit. `now` is passed in explicitly (rather than read from the clock inside)
// so this stays deterministic and testable. Not part of evaluate_header_checks
// since it needs the shared tracker, not just the static blacklist config.
CheckResult check_request_rate(const SpeedCheckConfig& config, RequestRateTracker& tracker,
                                const boost::asio::ip::address& client_ip,
                                std::chrono::steady_clock::time_point now);

// Off by default (see MethodCheckConfig). Case-insensitive membership check
// against config.allowed_methods, e.g. rejecting TRACE/CONNECT/arbitrary
// verbs a site never expects.
CheckResult check_method_allowlist(const MethodCheckConfig& config, std::string_view method);

// Run only once the header-phase checks all pass, against the fully-read body.
CheckResult check_body_size(const BlacklistConfig& config, std::size_t body_size);
CheckResult check_body_blacklist(const BlacklistConfig& config, std::string_view body);

// Runs the header-phase checks in cheap-first order, short-circuiting on the first block.
// `path` is the request-target without the query string. `isp` is the
// caller's already-resolved ASN organization string (see check_isp_blacklist
// above) — empty if unresolved.
CheckResult evaluate_header_checks(const BlacklistConfig& config,
                                    const boost::asio::ip::address& client_ip,
                                    std::string_view path,
                                    const http::request_header<http::fields>& header,
                                    std::string_view isp);

// Runs the body-phase checks (size first — cheap — then pattern match).
CheckResult evaluate_body_checks(const BlacklistConfig& config, std::string_view body);

} // namespace atomwall
