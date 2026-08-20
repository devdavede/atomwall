#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/beast/http.hpp>
#include <string>

#include "config/runtime_config.hpp"

namespace atomwall {

namespace http = boost::beast::http;

// No connection pooling yet: each call pays a fresh TCP handshake to origin.
boost::asio::awaitable<http::response<http::string_body>> forward_to_upstream(
    http::request<http::string_body> request,
    const UpstreamConfig& upstream,
    const LimitsConfig& limits,
    const std::string& client_ip);

} // namespace atomwall
