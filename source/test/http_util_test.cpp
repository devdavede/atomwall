#include <catch2/catch_test_macros.hpp>

#include "admin/http_util.hpp"

using namespace atomwall;
namespace http = boost::beast::http;

TEST_CASE("json_response marks API bodies nosniff and uncacheable", "[http_util]") {
    const auto res = json_response(http::status::ok, boost::json::object{{"a", 1}}, 11);
    CHECK(res[http::field::content_type] == "application/json");
    CHECK(res["X-Content-Type-Options"] == "nosniff");
    CHECK(res[http::field::cache_control] == "no-store");
}

TEST_CASE("error_response carries the same protections", "[http_util]") {
    const auto res = error_response(http::status::unauthorized, "unauthorized", 11);
    CHECK(res.result() == http::status::unauthorized);
    CHECK(res["X-Content-Type-Options"] == "nosniff");
    CHECK(res[http::field::cache_control] == "no-store");
}
