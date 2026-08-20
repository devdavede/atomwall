#include "listener/listener.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <spdlog/spdlog.h>

#include "listener/http_session.hpp"

namespace atomwall {

namespace net = boost::asio;
namespace beast = boost::beast;
using net::awaitable;
using net::use_awaitable;
using net::ip::tcp;

namespace {

boost::asio::ip::address client_address_of(const tcp::socket& socket) {
    beast::error_code ec;
    auto endpoint = socket.remote_endpoint(ec);
    return ec ? net::ip::make_address("0.0.0.0") : endpoint.address();
}

awaitable<void> handle_connection(tcp::socket socket, std::shared_ptr<AppState> state) {
    const auto client_ip = client_address_of(socket);
    beast::tcp_stream stream(std::move(socket));

    try {
        co_await run_http_session(stream, client_ip, state, "http");
    } catch (const std::exception& e) {
        spdlog::debug("connection from {} closed: {}", client_ip.to_string(), e.what());
    }

    beast::error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);
}

} // namespace

awaitable<void> run_http_listener(std::shared_ptr<AppState> state) {
    auto config = state->config_store->get();
    auto executor = co_await net::this_coro::executor;
    tcp::acceptor acceptor(
        executor, {net::ip::make_address(config->http.bind_host), config->http.port});

    spdlog::info("http listener on {}:{}, forwarding to {}:{}",
                 config->http.bind_host, config->http.port,
                 config->upstream.host, config->upstream.port);

    for (;;) {
        auto socket = co_await acceptor.async_accept(use_awaitable);
        co_spawn(executor, handle_connection(std::move(socket), state), net::detached);
    }
}

} // namespace atomwall
