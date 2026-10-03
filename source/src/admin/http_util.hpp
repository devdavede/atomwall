#pragma once

#include <boost/beast/http.hpp>
#include <boost/json.hpp>
#include <cstddef>
#include <string_view>

namespace atomwall {

// Shared by admin_server.cpp and globe/globe_server.cpp — both are small
// JSON-over-HTTP servers with the same handful of response-shaping needs.
std::size_t query_param_size_t(std::string_view target, std::string_view key, std::size_t fallback);

boost::beast::http::response<boost::beast::http::string_body> json_response(
    boost::beast::http::status status, const boost::json::value& body, unsigned version);

boost::beast::http::response<boost::beast::http::string_body> error_response(
    boost::beast::http::status status, std::string_view message, unsigned version);

} // namespace atomwall
