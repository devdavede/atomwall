#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include "config/yaml_codec.hpp"
#include "pipeline/net_utils.hpp"

using namespace atomwall;

TEST_CASE("to_yaml_config then parse_yaml_config round-trips", "[yaml_codec]") {
    RuntimeConfig original;
    original.http.port = 8080;
    original.https.port = 8443;
    original.upstream.host = "10.0.0.5";
    original.upstream.port = 3000;
    original.admin.port = 9100;
    original.blacklist.ip_exact = {BlacklistEntry{"203.0.113.7"}};
    original.blacklist.ip_cidrs = {*parse_cidr("198.51.100.0/24")};
    original.blacklist.user_agents = {BlacklistEntry{"sqlmap"}};
    original.blacklist.referrers = {BlacklistEntry{"spam-site.example"}};
    original.blacklist.body_patterns = {BlacklistEntry{"<script>"}};
    original.pages.status_pages = {StatusPageEntry{404, "<h1>not found</h1>"}};
    original.speed_check.enabled = true;
    original.speed_check.max_requests = 30;
    original.speed_check.window_seconds = 5;
    original.request_log.enabled = true;
    original.request_log.csv_path = "data/requests.csv";
    original.geoip.mmdb_path = "/etc/atomwall/GeoLite2-City.mmdb";
    original.globe.public_enabled = true;
    original.globe.public_port = 9444;
    original.globe.server_lat = 50.1109;
    original.globe.server_lon = 8.6821;
    original.globe.auto_detect_server_location = false;
    original.globe.history_size = 1234;
    SiteConfig site;
    site.domain = "Example.com";
    site.enabled = false;
    site.cert_file = "certs/example.com.crt";
    site.key_file = "certs/example.com.key";
    site.upstream.host = "127.0.0.1";
    site.upstream.port = 9001;
    original.sites.push_back(site);

    auto roundtripped = parse_yaml_config(to_yaml_config(original));

    CHECK(roundtripped.http.port == 8080);
    CHECK(roundtripped.https.port == 8443);
    CHECK(roundtripped.upstream.host == "10.0.0.5");
    CHECK(roundtripped.upstream.port == 3000);
    CHECK(roundtripped.admin.port == 9100);
    // to_yaml_config persists created_at with 1-second resolution, so compare
    // with floor(seconds) rather than exact time_point equality.
    auto to_seconds = [](std::chrono::system_clock::time_point tp) {
        return std::chrono::floor<std::chrono::seconds>(tp);
    };

    REQUIRE(roundtripped.blacklist.ip_exact.size() == 1);
    CHECK(roundtripped.blacklist.ip_exact[0].value == "203.0.113.7");
    CHECK(to_seconds(roundtripped.blacklist.ip_exact[0].created_at) ==
          to_seconds(original.blacklist.ip_exact[0].created_at));
    REQUIRE(roundtripped.blacklist.ip_cidrs.size() == 1);
    CHECK(roundtripped.blacklist.ip_cidrs[0].text == "198.51.100.0/24");
    CHECK(to_seconds(roundtripped.blacklist.ip_cidrs[0].created_at) ==
          to_seconds(original.blacklist.ip_cidrs[0].created_at));
    REQUIRE(roundtripped.blacklist.user_agents.size() == 1);
    CHECK(roundtripped.blacklist.user_agents[0].value == "sqlmap");
    REQUIRE(roundtripped.blacklist.referrers.size() == 1);
    CHECK(roundtripped.blacklist.referrers[0].value == "spam-site.example");
    REQUIRE(roundtripped.blacklist.body_patterns.size() == 1);
    CHECK(roundtripped.blacklist.body_patterns[0].value == "<script>");
    REQUIRE(roundtripped.pages.status_pages.size() == 1);
    CHECK(roundtripped.pages.status_pages[0].code == 404);
    CHECK(roundtripped.pages.status_pages[0].html == "<h1>not found</h1>");
    CHECK(roundtripped.speed_check.enabled == true);
    CHECK(roundtripped.speed_check.max_requests == 30);
    CHECK(roundtripped.speed_check.window_seconds == 5);

    CHECK(roundtripped.request_log.enabled == true);
    CHECK(roundtripped.request_log.csv_path == "data/requests.csv");
    CHECK(roundtripped.geoip.mmdb_path == "/etc/atomwall/GeoLite2-City.mmdb");
    CHECK(roundtripped.globe.public_enabled == true);
    CHECK(roundtripped.globe.public_port == 9444);
    REQUIRE(roundtripped.globe.server_lat.has_value());
    CHECK(*roundtripped.globe.server_lat == Catch::Approx(50.1109));
    REQUIRE(roundtripped.globe.server_lon.has_value());
    CHECK(*roundtripped.globe.server_lon == Catch::Approx(8.6821));
    CHECK(roundtripped.globe.auto_detect_server_location == false);
    CHECK(roundtripped.globe.history_size == 1234);

    REQUIRE(roundtripped.sites.size() == 1);
    // Domains are normalized to lowercase on load, see yaml_codec.cpp.
    CHECK(roundtripped.sites[0].domain == "example.com");
    CHECK(roundtripped.sites[0].enabled == false);
    CHECK(roundtripped.sites[0].cert_file == "certs/example.com.crt");
    CHECK(roundtripped.sites[0].key_file == "certs/example.com.key");
    CHECK(roundtripped.sites[0].upstream.host == "127.0.0.1");
    CHECK(roundtripped.sites[0].upstream.port == 9001);
}

TEST_CASE("globe server_lat/server_lon round-trip as unset when not configured", "[yaml_codec]") {
    RuntimeConfig original;
    auto roundtripped = parse_yaml_config(to_yaml_config(original));
    CHECK_FALSE(roundtripped.globe.server_lat.has_value());
    CHECK_FALSE(roundtripped.globe.server_lon.has_value());
}

TEST_CASE("parse_yaml_config falls back to defaults for missing sections", "[yaml_codec]") {
    auto config = parse_yaml_config("http:\n  port: 9999\n");
    CHECK(config.http.port == 9999);
    CHECK(config.https.port == 443); // default, section absent
}

TEST_CASE("parse_yaml_config skips invalid blacklist IP entries instead of throwing", "[yaml_codec]") {
    auto config = parse_yaml_config(
        "blacklist:\n"
        "  ips:\n"
        "    - \"203.0.113.7\"\n"
        "    - \"not-an-ip\"\n"
        "    - \"198.51.100.0/24\"\n"
        "    - \"198.51.100.0/99\"\n");
    REQUIRE(config.blacklist.ip_exact.size() == 1);
    CHECK(config.blacklist.ip_exact[0].value == "203.0.113.7");
    REQUIRE(config.blacklist.ip_cidrs.size() == 1);
    CHECK(config.blacklist.ip_cidrs[0].text == "198.51.100.0/24");
}

TEST_CASE("parse_yaml_config accepts old plain-scalar blacklist entries (no created_at)",
          "[yaml_codec]") {
    auto config = parse_yaml_config(
        "blacklist:\n"
        "  routes:\n"
        "    - /wp-admin\n"
        "    - /phpmyadmin\n");
    REQUIRE(config.blacklist.routes.size() == 2);
    CHECK(config.blacklist.routes[0].value == "/wp-admin");
    CHECK(config.blacklist.routes[1].value == "/phpmyadmin");
}
