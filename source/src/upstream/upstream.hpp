#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/beast/http.hpp>
#include <string>
#include <string_view>

#include "config/runtime_config.hpp"

namespace atomwall {

namespace http = boost::beast::http;

// No connection pooling yet: each call pays a fresh TCP handshake to origin.
// `client_scheme` is what the *client* connected with ("http"/"https"), sent to
// origin as X-Forwarded-Proto — the hop to origin itself is always plaintext,
// but origins key secure-cookie/redirect/HSTS decisions off what the visitor's
// connection was, not off this internal hop.
boost::asio::awaitable<http::response<http::string_body>> forward_to_upstream(
    http::request<http::string_body> request,
    const UpstreamConfig& upstream,
    const LimitsConfig& limits,
    const std::string& client_ip,
    std::string_view client_scheme);

} // namespace atomwall
