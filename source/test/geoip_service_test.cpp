#include <catch2/catch_test_macros.hpp>

#include <boost/asio/ip/address.hpp>

#include "geoip/geoip_service.hpp"

using namespace atomwall;

// A real GeoLite2-City .mmdb requires a MaxMind account to download and
// isn't vendored in this repo, so DB-hit lookups aren't covered here — see
// CLAUDE.md's Live Visitor Globe section. What's covered: GeoIpService must
// never throw or crash on a missing/unset database, and must degrade to
// "no data" rather than block startup.

TEST_CASE("GeoIpService with an empty path is not loaded and never throws", "[geoip]") {
    GeoIpService service("");
    CHECK_FALSE(service.loaded());
    CHECK_FALSE(service.lookup(boost::asio::ip::make_address("8.8.8.8")).has_value());
}

TEST_CASE("GeoIpService with a missing file is not loaded and never throws", "[geoip]") {
    GeoIpService service("/nonexistent/path/does-not-exist.mmdb");
    CHECK_FALSE(service.loaded());
    CHECK_FALSE(service.lookup(boost::asio::ip::make_address("8.8.8.8")).has_value());
}

TEST_CASE("GeoIpService lookup works for both IPv4 and IPv6 addresses when unloaded", "[geoip]") {
    GeoIpService service("");
    CHECK_FALSE(service.lookup(boost::asio::ip::make_address("203.0.113.7")).has_value());
    CHECK_FALSE(service.lookup(boost::asio::ip::make_address("2001:db8::1")).has_value());
}
