#include "admin/url_fetch.hpp"

#include <array>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include "pipeline/net_utils.hpp"

namespace atomwall {

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using net::awaitable;
using net::use_awaitable;
using net::ip::tcp;

namespace {

struct ParsedUrl {
    bool https = false;
    std::string host;
    std::string port;
    std::string target;
};

std::optional<ParsedUrl> parse_url(const std::string& url) {
    std::string_view view(url);
    bool https = false;
    if (view.substr(0, 7) == "http://") {
        view.remove_prefix(7);
    } else if (view.substr(0, 8) == "https://") {
        https = true;
        view.remove_prefix(8);
    } else {
        return std::nullopt;
    }

    const auto slash = view.find('/');
    auto authority = view.substr(0, slash);
    auto target = slash == std::string_view::npos ? std::string("/") : std::string(view.substr(slash));
    if (target.empty()) {
        target = "/";
    }
    if (authority.empty()) {
        return std::nullopt;
    }

    // No userinfo ("user:pass@host") support — an admin-supplied import URL
    // has no business carrying credentials, and skipping it avoids parsing
    // ambiguity with the port separator below.
    if (authority.find('@') != std::string_view::npos) {
        return std::nullopt;
    }

    ParsedUrl result;
    result.https = https;
    result.target = std::move(target);

    if (!authority.empty() && authority.front() == '[') {
        // IPv6 literal: [::1]:8080
        const auto close = authority.find(']');
        if (close == std::string_view::npos) {
            return std::nullopt;
        }
        result.host = std::string(authority.substr(1, close - 1));
        auto rest = authority.substr(close + 1);
        if (!rest.empty() && rest.front() == ':') {
            result.port = std::string(rest.substr(1));
        }
    } else {
        const auto colon = authority.find(':');
        if (colon == std::string_view::npos) {
            result.host = std::string(authority);
        } else {
            result.host = std::string(authority.substr(0, colon));
            result.port = std::string(authority.substr(colon + 1));
        }
    }

    if (result.host.empty()) {
        return std::nullopt;
    }
    if (result.port.empty()) {
        result.port = https ? "443" : "80";
    }
    return result;
}

// An IPv4-mapped IPv6 address (::ffff:a.b.c.d) is IPv6-typed as far as
// address::is_v4()/is_v6() and address_in_cidr() are concerned, so without
// this it sails straight past every IPv4 entry in kDeniedRanges below *and*
// past address_v6::is_loopback() (which only matches the literal ::1, not
// the mapped form) — e.g. "http://[::ffff:127.0.0.1]/" or
// "http://[::ffff:169.254.169.254]/" would otherwise reach loopback/link-local
// unfiltered. Unwrapping to the real IPv4 address first lets every check
// below see what the address actually is.
net::ip::address unwrap_v4_mapped(const net::ip::address& address) {
    if (address.is_v6()) {
        const auto v6 = address.to_v6();
        if (v6.is_v4_mapped()) {
            return net::ip::address(net::ip::make_address_v4(net::ip::v4_mapped, v6));
        }
    }
    return address;
}

// Denies loopback, link-local, multicast, unspecified, and the RFC1918 /
// CGNAT / unique-local private ranges — the same "this proxy must not be
// tricked into hitting its own internal network" guard applies to
// admin-supplied import URLs as to any other hostile input (see
// CLAUDE.md Security posture).
bool is_disallowed_address(const net::ip::address& raw_address) {
    const auto address = unwrap_v4_mapped(raw_address);
    if (address.is_loopback() || address.is_multicast() || address.is_unspecified()) {
        return true;
    }
    static const std::array<std::string_view, 8> kDeniedRanges = {
        "10.0.0.0/8",     "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "100.64.0.0/10",  "0.0.0.0/8",     "fc00::/7",       "fe80::/10",
    };
    for (const auto& text : kDeniedRanges) {
        if (auto range = parse_cidr(text); range && address_in_cidr(address, *range)) {
            return true;
        }
    }
    return false;
}

template <typename Stream>
awaitable<UrlFetchResult> read_response(Stream& stream, std::size_t max_bytes) {
    beast::flat_buffer buffer;
    http::response_parser<http::string_body> parser;
    parser.body_limit(max_bytes);
    beast::error_code ec;
    co_await http::async_read(stream, buffer, parser, net::redirect_error(use_awaitable, ec));

    UrlFetchResult result;
    if (ec == http::error::body_limit) {
        result.error = "response exceeded " + std::to_string(max_bytes) + " byte limit";
        co_return result;
    }
    if (ec) {
        result.error = ec.message();
        co_return result;
    }

    auto response = parser.release();
    if (response.result_int() / 100 == 3) {
        result.error = "server returned a redirect (" + std::to_string(response.result_int()) +
                        ") — redirects aren't followed, paste the final URL directly";
        co_return result;
    }
    if (response.result_int() / 100 != 2) {
        result.error = "server returned HTTP " + std::to_string(response.result_int());
        co_return result;
    }

    result.ok = true;
    result.body = std::move(response.body());
    co_return result;
}

} // namespace

awaitable<UrlFetchResult> fetch_url(std::string url, std::size_t max_bytes,
                                     std::chrono::seconds timeout) {
    UrlFetchResult result;

    auto parsed = parse_url(url);
    if (!parsed) {
        result.error = "expected an http:// or https:// URL";
        co_return result;
    }

    auto executor = co_await net::this_coro::executor;
    tcp::resolver resolver(executor);

    boost::system::error_code resolve_ec;
    auto endpoints = co_await resolver.async_resolve(
        parsed->host, parsed->port, net::redirect_error(use_awaitable, resolve_ec));
    if (resolve_ec) {
        result.error = "could not resolve host: " + resolve_ec.message();
        co_return result;
    }

    tcp::resolver::results_type filtered;
    for (const auto& entry : endpoints) {
        if (is_disallowed_address(entry.endpoint().address())) {
            continue;
        }
        filtered = decltype(filtered)::create(entry.endpoint(), parsed->host, parsed->port);
        break;
    }
    if (filtered.empty()) {
        result.error = "refusing to fetch from a loopback/private/internal address";
        co_return result;
    }

    http::request<http::empty_body> request{http::verb::get, parsed->target, 11};
    request.set(http::field::host, parsed->host);
    request.set(http::field::user_agent, "atomwall-admin/1.0");
    request.set(http::field::connection, "close");

    beast::tcp_stream stream(executor);
    stream.expires_after(timeout);
    boost::system::error_code connect_ec;
    co_await stream.async_connect(filtered, net::redirect_error(use_awaitable, connect_ec));
    if (connect_ec) {
        result.error = "could not connect: " + connect_ec.message();
        co_return result;
    }

    if (!parsed->https) {
        boost::system::error_code write_ec;
        co_await http::async_write(stream, request, net::redirect_error(use_awaitable, write_ec));
        if (write_ec) {
            result.error = write_ec.message();
            co_return result;
        }
        result = co_await read_response(stream, max_bytes);
        beast::error_code shutdown_ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, shutdown_ec);
        co_return result;
    }

    ssl::context ssl_ctx(ssl::context::tls_client);
    ssl_ctx.set_default_verify_paths();
    ssl_ctx.set_verify_mode(ssl::verify_peer);
    ssl::stream<beast::tcp_stream&> tls_stream(stream, ssl_ctx);
    if (!SSL_set_tlsext_host_name(tls_stream.native_handle(), parsed->host.c_str())) {
        result.error = "failed to set SNI hostname";
        co_return result;
    }

    boost::system::error_code handshake_ec;
    co_await tls_stream.async_handshake(ssl::stream_base::client,
                                         net::redirect_error(use_awaitable, handshake_ec));
    if (handshake_ec) {
        result.error = "TLS handshake failed: " + handshake_ec.message();
        co_return result;
    }

    boost::system::error_code write_ec;
    co_await http::async_write(tls_stream, request, net::redirect_error(use_awaitable, write_ec));
    if (write_ec) {
        result.error = write_ec.message();
        co_return result;
    }
    result = co_await read_response(tls_stream, max_bytes);

    // The remote end usually closes without a clean TLS shutdown once the
    // body's been sent — that surfaces as stream_truncated, which is
    // expected here and not worth surfacing as a fetch failure.
    boost::system::error_code shutdown_ec;
    co_await tls_stream.async_shutdown(net::redirect_error(use_awaitable, shutdown_ec));
    co_return result;
}

} // namespace atomwall
