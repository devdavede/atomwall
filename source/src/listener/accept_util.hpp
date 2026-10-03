#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>
#include <chrono>
#include <spdlog/spdlog.h>

namespace atomwall {

// async_accept fails on plenty of recoverable conditions — fd exhaustion (which
// a remote client can provoke just by opening enough connections), ENOBUFS/
// ENOMEM, a client resetting before accept completes. An exception escaping an
// accept-loop coroutine reaches main.cpp's fatal_on_error and ends the whole
// process, taking every other listener and in-flight connection with it, so
// transient failures are retried after a pause (a bare retry would busy-spin
// while the condition persists). Only operation_aborted — the acceptor being
// closed — is treated as terminal.
inline boost::asio::awaitable<boost::asio::ip::tcp::socket> accept_next(
    boost::asio::ip::tcp::acceptor& acceptor,
    std::chrono::milliseconds retry_delay = std::chrono::milliseconds(100)) {
    boost::asio::steady_timer timer(co_await boost::asio::this_coro::executor);
    bool already_logged = false;
    for (;;) {
        boost::system::error_code ec;
        auto socket = co_await acceptor.async_accept(
            boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (!ec) {
            co_return socket;
        }
        if (ec == boost::asio::error::operation_aborted) {
            throw boost::system::system_error(ec);
        }
        if (!already_logged) {
            spdlog::warn("accept failed, retrying: {}", ec.message());
            already_logged = true;
        } else {
            spdlog::debug("accept failed, retrying: {}", ec.message());
        }
        timer.expires_after(retry_delay);
        co_await timer.async_wait(boost::asio::use_awaitable);
    }
}

} // namespace atomwall
