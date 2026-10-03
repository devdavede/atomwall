#include <catch2/catch_test_macros.hpp>

#include "config/site_lookup.hpp"

using namespace atomwall;

namespace {

RuntimeConfig config_with_one_site() {
    RuntimeConfig config;
    config.upstream.host = "127.0.0.1";
    config.upstream.port = 8000;

    SiteConfig site;
    site.domain = "example.com";
    site.enabled = true;
    site.cert_file = "certs/example.com.crt";
    site.key_file = "certs/example.com.key";
    site.upstream.host = "127.0.0.1";
    site.upstream.port = 9001;
    config.sites.push_back(site);

    return config;
}

} // namespace

TEST_CASE("resolve_site matches a configured domain case-insensitively", "[site_lookup]") {
    auto config = config_with_one_site();
    auto resolved = resolve_site(config, "Example.COM");
    CHECK(resolved.matched);
    CHECK(resolved.enabled);
    REQUIRE(resolved.upstream != nullptr);
    CHECK(resolved.upstream->port == 9001);
}

TEST_CASE("resolve_site strips a trailing port before matching", "[site_lookup]") {
    auto config = config_with_one_site();
    auto resolved = resolve_site(config, "example.com:443");
    CHECK(resolved.matched);
    CHECK(resolved.upstream->port == 9001);
}

TEST_CASE("resolve_site never matches by substring", "[site_lookup]") {
    auto config = config_with_one_site();
    CHECK_FALSE(resolve_site(config, "example.com.evil.com").matched);
    CHECK_FALSE(resolve_site(config, "evil-example.com").matched);
}

TEST_CASE("resolve_site falls back to the default site when unmatched", "[site_lookup]") {
    auto config = config_with_one_site();
    auto resolved = resolve_site(config, "other.example");
    CHECK_FALSE(resolved.matched);
    CHECK(resolved.enabled);
    REQUIRE(resolved.upstream != nullptr);
    CHECK(resolved.upstream->port == 8000);
}

TEST_CASE("resolve_site falls back to the default site when sites is empty", "[site_lookup]") {
    RuntimeConfig config;
    config.upstream.port = 8000;
    auto resolved = resolve_site(config, "anything.example");
    CHECK_FALSE(resolved.matched);
    CHECK(resolved.upstream->port == 8000);
}

TEST_CASE("resolve_site reports a disabled site as not enabled", "[site_lookup]") {
    auto config = config_with_one_site();
    config.sites[0].enabled = false;
    auto resolved = resolve_site(config, "example.com");
    CHECK(resolved.matched);
    CHECK_FALSE(resolved.enabled);
}
