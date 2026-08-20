#include <boost/asio/ip/address.hpp>
#include <catch2/catch_test_macros.hpp>

#include "pipeline/net_utils.hpp"

using namespace atomwall;
namespace net = boost::asio;

TEST_CASE("parse_cidr rejects input without a slash", "[net_utils]") {
    REQUIRE_FALSE(parse_cidr("203.0.113.7").has_value());
}

TEST_CASE("parse_cidr rejects an invalid address", "[net_utils]") {
    REQUIRE_FALSE(parse_cidr("not-an-ip/24").has_value());
}

TEST_CASE("parse_cidr rejects a prefix length beyond the address width", "[net_utils]") {
    REQUIRE_FALSE(parse_cidr("203.0.113.0/33").has_value());
    REQUIRE_FALSE(parse_cidr("::1/129").has_value());
}

TEST_CASE("parse_cidr accepts a valid IPv4 range", "[net_utils]") {
    auto range = parse_cidr("198.51.100.0/24");
    REQUIRE(range.has_value());
    CHECK(range->prefix_len == 24);
    CHECK(range->text == "198.51.100.0/24");
}

TEST_CASE("address_in_cidr matches IPv4 addresses inside the range", "[net_utils]") {
    auto range = parse_cidr("198.51.100.0/24");
    REQUIRE(range.has_value());
    CHECK(address_in_cidr(net::ip::make_address("198.51.100.42"), *range));
    CHECK_FALSE(address_in_cidr(net::ip::make_address("198.51.101.1"), *range));
}

TEST_CASE("address_in_cidr respects non-byte-aligned prefix lengths", "[net_utils]") {
    // 203.0.113.0/26 covers 203.0.113.0 - 203.0.113.63
    auto range = parse_cidr("203.0.113.0/26");
    REQUIRE(range.has_value());
    CHECK(address_in_cidr(net::ip::make_address("203.0.113.63"), *range));
    CHECK_FALSE(address_in_cidr(net::ip::make_address("203.0.113.64"), *range));
}

TEST_CASE("address_in_cidr matches IPv6 addresses", "[net_utils]") {
    auto range = parse_cidr("2001:db8::/32");
    REQUIRE(range.has_value());
    CHECK(address_in_cidr(net::ip::make_address("2001:db8::1"), *range));
    CHECK_FALSE(address_in_cidr(net::ip::make_address("2001:db9::1"), *range));
}

TEST_CASE("address_in_cidr never matches across address families", "[net_utils]") {
    auto range = parse_cidr("0.0.0.0/0");
    REQUIRE(range.has_value());
    CHECK_FALSE(address_in_cidr(net::ip::make_address("::1"), *range));
}

TEST_CASE("icontains is case-insensitive and substring-based", "[net_utils]") {
    CHECK(icontains("Mozilla/5.0 sqlMap/1.0", "SQLMAP"));
    CHECK_FALSE(icontains("Mozilla/5.0", "sqlmap"));
    CHECK(icontains("anything", ""));
}

TEST_CASE("istarts_with is case-insensitive and prefix-based", "[net_utils]") {
    CHECK(istarts_with("/Wp-Login-Backup/extra", "/wp-login-backup"));
    CHECK_FALSE(istarts_with("/wp-login", "/wp-login-backup"));
    CHECK_FALSE(istarts_with("/other", "/wp-login-backup"));
    CHECK(istarts_with("anything", ""));
}

TEST_CASE("iequals is case-insensitive but exact, never substring", "[net_utils]") {
    CHECK(iequals("Example.COM", "example.com"));
    CHECK_FALSE(iequals("example.com", "example.com.evil.com"));
    CHECK_FALSE(iequals("evil-example.com", "example.com"));
    CHECK_FALSE(iequals("example.co", "example.com"));
}

TEST_CASE("to_lower ASCII-lowercases text", "[net_utils]") {
    CHECK(to_lower("Example.COM") == "example.com");
    CHECK(to_lower("already-lower") == "already-lower");
}
