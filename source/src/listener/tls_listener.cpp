#include "listener/tls_listener.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <spdlog/spdlog.h>

#include <openssl/ssl.h>

#include "listener/http_session.hpp"
#include "listener/tls_context.hpp"
#include "pipeline/net_utils.hpp"

namespace atomwall {

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
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

ssl::context make_ssl_context(const HttpsListenerConfig& config) {
    return make_tls_server_context(config.cert_file, config.key_file);
}

// TLS SNI dispatch for multi-domain sites (see config/site_lookup.hpp /
// runtime_config.hpp's SiteConfig): the certificate must be picked during the
// handshake, before any HTTP header (and thus the Host header) exists, so
// this is driven off the SNI server name instead. `arg` is the AppState*
// passed to SSL_CTX_set_tlsext_servername_arg below; it outlives every
// handshake since it's kept alive by the listener coroutine's `state`
// shared_ptr for as long as the listener runs. No match (or no SNI at all,
// e.g. a bare-IP TLS client) leaves the handshake on the base/default
// context — identical to today's single-cert behavior.
extern "C" int select_tls_context_for_sni(SSL* ssl, int* /*alert*/, void* arg) {
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername) {
        return SSL_TLSEXT_ERR_OK;
    }

    auto* state = static_cast<AppState*>(arg);
    auto config = state->config_store->get();
    auto contexts = state->tls_sites->current(config);
    if (auto it = contexts->find(to_lower(servername)); it != contexts->end()) {
        SSL_set_SSL_CTX(ssl, it->second->native_handle());
    }
    return SSL_TLSEXT_ERR_OK;
}

awaitable<void> handle_connection(tcp::socket socket, std::shared_ptr<AppState> state,
                                   std::shared_ptr<ssl::context> ssl_ctx) {
    const auto client_ip = client_address_of(socket);
    ssl::stream<beast::tcp_stream> stream(std::move(socket), *ssl_ctx);

    try {
        auto config = state->config_store->get();
        beast::get_lowest_layer(stream).expires_after(config->limits.request_timeout);
        co_await stream.async_handshake(ssl::stream_base::server, use_awaitable);

        co_await run_http_session(stream, client_ip, state, "https");
    } catch (const std::exception& e) {
        spdlog::debug("tls connection from {} closed: {}", client_ip.to_string(), e.what());
    }

    beast::error_code ec;
    beast::get_lowest_layer(stream).socket().shutdown(tcp::socket::shutdown_both, ec);
}

} // namespace

awaitable<void> run_tls_listener(std::shared_ptr<AppState> state) {
    auto config = state->config_store->get();
    auto ssl_ctx = std::make_shared<ssl::context>(make_ssl_context(config->https));
    SSL_CTX_set_tlsext_servername_callback(ssl_ctx->native_handle(), select_tls_context_for_sni);
    SSL_CTX_set_tlsext_servername_arg(ssl_ctx->native_handle(), state.get());

    auto executor = co_await net::this_coro::executor;
    tcp::acceptor acceptor(
        executor, {net::ip::make_address(config->https.bind_host), config->https.port});

    spdlog::info("https listener on {}:{} (cert: {}), forwarding to {}:{}",
                 config->https.bind_host, config->https.port, config->https.cert_file,
                 config->upstream.host, config->upstream.port);

    for (;;) {
        auto socket = co_await acceptor.async_accept(use_awaitable);
        co_spawn(executor, handle_connection(std::move(socket), state, ssl_ctx), net::detached);
    }
}

} // namespace atomwall
