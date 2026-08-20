#include "globe/globe_server.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>
#include <stdexcept>

#include "admin/http_util.hpp"
#include "admin/json_view.hpp"
#include "admin/static_files.hpp"
#include "history/sse_stream.hpp"
#include "listener/tls_context.hpp"

namespace atomwall {

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using net::awaitable;
using net::use_awaitable;
using net::ip::tcp;

namespace {

constexpr std::size_t kGlobeMaxBodyBytes = 8 * 1024; // this server is GET-only, no meaningful body expected
constexpr std::size_t kDefaultSnapshotLimit = 200;
constexpr std::string_view kEmbedScriptFile = "/globe-embed.js"; // served under the public /globe.js route
constexpr std::string_view kVendorPrefix = "/vendor/";
constexpr std::string_view kCorsExtraHeader = "Access-Control-Allow-Origin: *\r\n";

// Every response from this server carries CORS "allow any origin" — safe
// because there are no cookies/credentials anywhere on this listener and the
// data returned is anonymized by construction (see globe_server.hpp).
template <class Body>
void add_cors_header(http::response<Body>& res) {
    res.set(http::field::access_control_allow_origin, "*");
}

http::response<http::string_body> handle_embed_script(const std::filesystem::path& static_dir,
                                                        unsigned version) {
    auto resolved = resolve_static_path(static_dir, kEmbedScriptFile);
    if (!resolved) {
        auto res = error_response(http::status::not_found, "globe embed script not found", version);
        add_cors_header(res);
        return res;
    }

    std::ifstream file(*resolved, std::ios::binary);
    std::ostringstream buffer;
    buffer << file.rdbuf();

    http::response<http::string_body> res{http::status::ok, version};
    res.set(http::field::server, "atomwall-globe");
    res.set(http::field::content_type, "text/javascript; charset=utf-8");
    add_cors_header(res);
    res.body() = buffer.str();
    res.prepare_payload();
    return res;
}

// Serves webui/vendor/* (the locally-vendored globe.gl + three.js + earth
// textures — see webui/globe-embed.js) so the public embed works standalone
// without reaching into the loopback-only admin static server. Deliberately
// scoped to just this one prefix, not a general static-file fallback for the
// whole static_dir — the admin UI's own HTML/JS/CSS must stay unreachable
// from this unauthenticated public listener.
http::response<http::string_body> handle_vendor_asset(const std::filesystem::path& static_dir,
                                                        std::string_view target, unsigned version) {
    auto resolved = resolve_static_path(static_dir, target);
    if (!resolved) {
        auto res = error_response(http::status::not_found, "not found", version);
        add_cors_header(res);
        return res;
    }

    std::ifstream file(*resolved, std::ios::binary);
    std::ostringstream buffer;
    buffer << file.rdbuf();

    http::response<http::string_body> res{http::status::ok, version};
    res.set(http::field::server, "atomwall-globe");
    res.set(http::field::content_type, std::string(mime_type_for(*resolved)));
    add_cors_header(res);
    res.body() = buffer.str();
    res.prepare_payload();
    return res;
}

http::response<http::string_body> handle_snapshot(AppState& state, std::string_view target,
                                                    unsigned version) {
    const auto limit = query_param_size_t(target, "limit", kDefaultSnapshotLimit);
    boost::json::object obj;
    obj["events"] = globe_events_to_json(state.globe_events->recent(limit));
    obj["server_location"] = server_location_to_json(state.server_location->get());
    obj["geoip_ready"] = state.geoip && state.geoip->loaded();
    auto res = json_response(http::status::ok, obj, version);
    add_cors_header(res);
    return res;
}

http::response<http::string_body> route(AppState& state,
                                         const http::request<http::string_body>& request) {
    const auto target = request.target();
    const auto version = request.version();
    const auto method = request.method();
    auto config = state.config_store->get();

    if (method != http::verb::get) {
        auto res = error_response(http::status::method_not_allowed, "method not allowed", version);
        add_cors_header(res);
        return res;
    }

    if (target == "/globe.js") {
        return handle_embed_script(config->admin.static_dir, version);
    }
    if (std::string_view(target).starts_with(kVendorPrefix)) {
        return handle_vendor_asset(config->admin.static_dir, target, version);
    }
    if (std::string_view(target).substr(0, std::string_view("/globe/snapshot").size()) ==
        "/globe/snapshot") {
        return handle_snapshot(state, target, version);
    }

    auto res = error_response(http::status::not_found, "not found", version);
    add_cors_header(res);
    return res;
}

// Shared by the plain-HTTP and (optional) TLS variants below: read requests,
// route GET /globe.js and GET /globe/snapshot as ordinary responses, and
// hand GET /globe/stream over to the shared SSE poller. No auth check here
// at all — see globe_server.hpp for why that's safe on this listener.
template <class Stream>
awaitable<void> handle_connection(Stream stream, std::shared_ptr<AppState> state) {
    try {
        for (;;) {
            beast::flat_buffer buffer(16 * 1024);
            http::request_parser<http::string_body> parser;
            parser.body_limit(kGlobeMaxBodyBytes);

            beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
            co_await http::async_read(stream, buffer, parser, use_awaitable);

            auto request = parser.release();
            const bool keep_alive = request.keep_alive();
            const auto target = request.target();

            if (request.method() == http::verb::get && target == "/globe/stream") {
                co_await run_sse_session(stream, state->globe_events, globe_event_to_json,
                                          kCorsExtraHeader);
                co_return;
            }

            auto response = route(*state, request);
            response.keep_alive(keep_alive);
            response.prepare_payload();

            co_await http::async_write(stream, response, use_awaitable);
            if (!keep_alive) {
                break;
            }
        }
    } catch (const std::exception& e) {
        spdlog::debug("globe connection closed: {}", e.what());
    }

    beast::error_code ec;
    beast::get_lowest_layer(stream).socket().shutdown(tcp::socket::shutdown_both, ec);
}

awaitable<void> accept_plain(std::shared_ptr<AppState> state, tcp::acceptor& acceptor) {
    auto executor = co_await net::this_coro::executor;
    for (;;) {
        auto socket = co_await acceptor.async_accept(use_awaitable);
        net::co_spawn(executor, handle_connection(beast::tcp_stream(std::move(socket)), state),
                       net::detached);
    }
}

awaitable<void> accept_tls(std::shared_ptr<AppState> state, tcp::acceptor& acceptor,
                            std::shared_ptr<ssl::context> ssl_ctx) {
    auto executor = co_await net::this_coro::executor;
    for (;;) {
        auto socket = co_await acceptor.async_accept(use_awaitable);
        net::co_spawn(
            executor,
            [](tcp::socket socket, std::shared_ptr<AppState> state,
               std::shared_ptr<ssl::context> ssl_ctx) -> awaitable<void> {
                ssl::stream<beast::tcp_stream> tls_stream(std::move(socket), *ssl_ctx);
                beast::get_lowest_layer(tls_stream).expires_after(std::chrono::seconds(30));
                try {
                    co_await tls_stream.async_handshake(ssl::stream_base::server, use_awaitable);
                } catch (const std::exception& e) {
                    spdlog::debug("globe TLS handshake failed: {}", e.what());
                    co_return;
                }
                co_await handle_connection(std::move(tls_stream), state);
            }(std::move(socket), state, ssl_ctx),
            net::detached);
    }
}

} // namespace

awaitable<void> run_globe_server(std::shared_ptr<AppState> state) {
    auto config = state->config_store->get();
    const bool use_tls = !config->globe.public_tls_cert_file.empty() &&
                          !config->globe.public_tls_key_file.empty();

    boost::system::error_code addr_ec;
    auto bind_address = net::ip::make_address(config->globe.public_bind_host, addr_ec);
    if (addr_ec) {
        throw std::runtime_error("globe.public_bind is not a valid address: '" +
                                  config->globe.public_bind_host + "'");
    }

    auto executor = co_await net::this_coro::executor;
    tcp::acceptor acceptor(executor, {bind_address, config->globe.public_port});

    spdlog::warn(
        "public globe listener on {}://{}:{} — UNAUTHENTICATED by design (anonymized data "
        "only, see CLAUDE.md Live Visitor Globe)",
        use_tls ? "https" : "http", config->globe.public_bind_host, config->globe.public_port);

    if (use_tls) {
        auto ssl_ctx = std::make_shared<ssl::context>(
            make_tls_server_context(config->globe.public_tls_cert_file, config->globe.public_tls_key_file));
        co_await accept_tls(state, acceptor, ssl_ctx);
    } else {
        co_await accept_plain(state, acceptor);
    }
}

} // namespace atomwall
