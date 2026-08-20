#include <catch2/catch_test_macros.hpp>

#include "config/site_ops.hpp"

using namespace atomwall;

TEST_CASE("add_site adds a lowercased domain", "[site_ops]") {
    RuntimeConfig config;
    SiteConfig site;
    site.domain = "Example.COM";
    site.upstream.host = "127.0.0.1";
    site.upstream.port = 9001;
    add_site(config, site);

    REQUIRE(config.sites.size() == 1);
    CHECK(config.sites[0].domain == "example.com");
}

TEST_CASE("add_site rejects an empty domain", "[site_ops]") {
    RuntimeConfig config;
    SiteConfig site;
    site.domain = "";
    CHECK_THROWS_AS(add_site(config, site), std::invalid_argument);
}

TEST_CASE("add_site rejects a domain that looks like a URL", "[site_ops]") {
    RuntimeConfig config;
    SiteConfig site;
    site.domain = "https://example.com/";
    CHECK_THROWS_AS(add_site(config, site), std::invalid_argument);
}

TEST_CASE("add_site rejects a duplicate domain, case-insensitively", "[site_ops]") {
    RuntimeConfig config;
    SiteConfig site;
    site.domain = "example.com";
    add_site(config, site);

    SiteConfig duplicate;
    duplicate.domain = "EXAMPLE.com";
    CHECK_THROWS_AS(add_site(config, duplicate), std::invalid_argument);
}

TEST_CASE("update_site applies only the provided fields", "[site_ops]") {
    RuntimeConfig config;
    SiteConfig site;
    site.domain = "example.com";
    site.upstream.port = 9001;
    add_site(config, site);

    SiteUpdate update;
    update.enabled = false;
    update_site(config, "example.com", update);

    REQUIRE(config.sites.size() == 1);
    CHECK(config.sites[0].enabled == false);
    CHECK(config.sites[0].upstream.port == 9001); // untouched
}

TEST_CASE("update_site throws for an unknown domain", "[site_ops]") {
    RuntimeConfig config;
    SiteUpdate update;
    CHECK_THROWS_AS(update_site(config, "missing.example", update), std::invalid_argument);
}

TEST_CASE("remove_site removes a matching domain, case-insensitively", "[site_ops]") {
    RuntimeConfig config;
    SiteConfig site;
    site.domain = "example.com";
    add_site(config, site);

    remove_site(config, "EXAMPLE.COM");
    CHECK(config.sites.empty());
}

TEST_CASE("remove_site throws for an unknown domain", "[site_ops]") {
    RuntimeConfig config;
    CHECK_THROWS_AS(remove_site(config, "missing.example"), std::invalid_argument);
}
