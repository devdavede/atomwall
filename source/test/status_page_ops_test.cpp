#include <catch2/catch_test_macros.hpp>

#include "config/status_page_ops.hpp"

using namespace atomwall;

TEST_CASE("add_status_page adds an entry", "[status_page_ops]") {
    RuntimeConfig config;
    add_status_page(config, 404, "<h1>not found</h1>");

    REQUIRE(config.pages.status_pages.size() == 1);
    CHECK(config.pages.status_pages[0].code == 404);
    CHECK(config.pages.status_pages[0].html == "<h1>not found</h1>");
}

TEST_CASE("add_status_page rejects an out-of-range code", "[status_page_ops]") {
    RuntimeConfig config;
    CHECK_THROWS_AS(add_status_page(config, 42, "x"), std::invalid_argument);
    CHECK_THROWS_AS(add_status_page(config, 600, "x"), std::invalid_argument);
}

TEST_CASE("add_status_page rejects a duplicate code", "[status_page_ops]") {
    RuntimeConfig config;
    add_status_page(config, 404, "first");
    CHECK_THROWS_AS(add_status_page(config, 404, "second"), std::invalid_argument);
}

TEST_CASE("update_status_page replaces the html for an existing code", "[status_page_ops]") {
    RuntimeConfig config;
    add_status_page(config, 503, "old");
    update_status_page(config, 503, "new");

    REQUIRE(config.pages.status_pages.size() == 1);
    CHECK(config.pages.status_pages[0].html == "new");
}

TEST_CASE("update_status_page throws for an unknown code", "[status_page_ops]") {
    RuntimeConfig config;
    CHECK_THROWS_AS(update_status_page(config, 404, "x"), std::invalid_argument);
}

TEST_CASE("remove_status_page removes a matching code", "[status_page_ops]") {
    RuntimeConfig config;
    add_status_page(config, 404, "x");
    remove_status_page(config, 404);
    CHECK(config.pages.status_pages.empty());
}

TEST_CASE("remove_status_page throws for an unknown code", "[status_page_ops]") {
    RuntimeConfig config;
    CHECK_THROWS_AS(remove_status_page(config, 404), std::invalid_argument);
}
