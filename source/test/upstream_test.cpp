#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <catch2/catch_test_macros.hpp>

#include "upstream/upstream.hpp"

using namespace atomwall;
namespace net = boost::asio;
namespace beast = boost::beast;
using net::ip::tcp;

namespace {

struct ReceivedHeaders {
    std::string forwarded_proto;
    std::string forwarded_for;
};

// Accepts one connection, records the forwarding headers, answers 200.
net::awaitable<void> fake_origin(tcp::acceptor& acceptor, ReceivedHeaders& received) {
    auto socket = co_await acceptor.async_accept(net::use_awaitable);
    beast::flat_buffer buffer;
    http::request<http::string_body> request;
    co_await http::async_read(socket, buffer, request, net::use_awaitable);
    received.forwarded_proto = std::string(request[http::field::x_forwarded_proto]);
    received.forwarded_for = std::string(request[http::field::x_forwarded_for]);

    http::response<http::string_body> response{http::status::ok, request.version()};
    response.body() = "ok";
    response.prepare_payload();
    co_await http::async_write(socket, response, net::use_awaitable);
}

ReceivedHeaders forward_once(std::string_view client_scheme, const std::string& spoofed_proto = {}) {
    net::io_context io;
    tcp::acceptor acceptor(io, {net::ip::make_address("127.0.0.1"), 0});
    UpstreamConfig upstream;
    upstream.host = "127.0.0.1";
    upstream.port = acceptor.local_endpoint().port();

    ReceivedHeaders received;
    net::co_spawn(io, fake_origin(acceptor, received), net::detached);

    http::request<http::string_body> request{http::verb::get, "/", 11};
    request.set(http::field::host, "example.com");
    request.set(http::field::x_forwarded_for, "6.6.6.6"); // client-supplied, must not survive
    if (!spoofed_proto.empty()) {
        request.set(http::field::x_forwarded_proto, spoofed_proto);
    }

    bool completed = false;
    net::co_spawn(
        io,
        [&]() -> net::awaitable<void> {
            LimitsConfig limits;
            auto response = co_await forward_to_upstream(std::move(request), upstream, limits,
                                                          "203.0.113.7", client_scheme);
            completed = response.result() == http::status::ok;
        },
        net::detached);
    io.run();
    REQUIRE(completed);
    return received;
}

} // namespace

TEST_CASE("forward_to_upstream tells origin the client connected over https", "[upstream]") {
    const auto received = forward_once("https");
    CHECK(received.forwarded_proto == "https");
    CHECK(received.forwarded_for == "203.0.113.7");
}

TEST_CASE("forward_to_upstream tells origin the client connected over plain http", "[upstream]") {
    CHECK(forward_once("http").forwarded_proto == "http");
}

TEST_CASE("forward_to_upstream doesn't trust a client-supplied X-Forwarded-Proto", "[upstream]") {
    CHECK(forward_once("http", "https").forwarded_proto == "http");
}
