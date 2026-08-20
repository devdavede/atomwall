#include "upstream/upstream.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>

namespace atomwall {

namespace net = boost::asio;
namespace beast = boost::beast;
using net::awaitable;
using net::use_awaitable;
using net::ip::tcp;

awaitable<http::response<http::string_body>> forward_to_upstream(
    http::request<http::string_body> request,
    const UpstreamConfig& upstream,
    const LimitsConfig& limits,
    const std::string& client_ip) {
    const bool is_head = request.method() == http::verb::head;
    request.set(http::field::x_forwarded_for, client_ip);
    request.set(http::field::x_forwarded_proto, "http");
    request.keep_alive(false);
    request.prepare_payload();

    auto executor = co_await net::this_coro::executor;
    tcp::resolver resolver(executor);
    beast::tcp_stream stream(executor);

    auto endpoints = co_await resolver.async_resolve(
        upstream.host, std::to_string(upstream.port), use_awaitable);

    stream.expires_after(limits.upstream_connect_timeout);
    co_await stream.async_connect(endpoints, use_awaitable);

    stream.expires_after(limits.request_timeout);
    co_await http::async_write(stream, request, use_awaitable);

    beast::flat_buffer buffer(limits.max_header_bytes);
    http::response_parser<http::string_body> parser;
    // A HEAD response carries the Content-Length/Transfer-Encoding the
    // matching GET would have had, but no body — without this, the parser
    // waits for body bytes that never come and reports a partial message.
    parser.skip(is_head);
    parser.body_limit(limits.max_body_bytes);
    co_await http::async_read(stream, buffer, parser, use_awaitable);

    beast::error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    co_return parser.release();
}

} // namespace atomwall
