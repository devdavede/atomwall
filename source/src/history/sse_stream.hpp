#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/json.hpp>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace atomwall {

// Takes over `stream`: writes an SSE header block, then polls `log` (any
// ring buffer exposing latest_seq()/events_since(seq), e.g. RequestLog or
// GlobeEventLog) for new events every 500ms and pushes them as
// `data: {...}\n\n` frames via `to_json`, until the write fails (client
// disconnected) or the connection idles out. A comment ping keeps idle
// connections (and any intermediary proxy) alive.
//
// `extra_headers`, if non-empty, is appended verbatim after the standard SSE
// header lines, before the blank line ending the header block — used by the
// public globe server to add a CORS header the loopback admin server has no
// need for.
template <class Stream, class Log, class ToJson>
boost::asio::awaitable<void> run_sse_session(Stream& stream, std::shared_ptr<Log> log,
                                              ToJson to_json, std::string_view extra_headers = {}) {
    namespace net = boost::asio;
    namespace beast = boost::beast;
    using net::use_awaitable;

    std::string header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n";
    header.append(extra_headers);
    header += "\r\n";
    co_await net::async_write(stream, net::buffer(header), use_awaitable);

    std::uint64_t last_seq = log->latest_seq();
    net::steady_timer timer(co_await net::this_coro::executor);

    for (;;) {
        timer.expires_after(std::chrono::milliseconds(500));
        co_await timer.async_wait(use_awaitable);
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(60));

        auto events = log->events_since(last_seq);
        if (events.empty()) {
            static constexpr std::string_view kPing = ": ping\n\n";
            co_await net::async_write(stream, net::buffer(kPing), use_awaitable);
            continue;
        }
        for (const auto& event : events) {
            const std::string frame = "data: " + boost::json::serialize(to_json(event)) + "\n\n";
            co_await net::async_write(stream, net::buffer(frame), use_awaitable);
            last_seq = event.seq;
        }
    }
}

} // namespace atomwall
