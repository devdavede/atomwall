#include <catch2/catch_test_macros.hpp>

#include <chrono>

#include "config/blacklist_ops.hpp"

using namespace atomwall;

TEST_CASE("parse_blacklist_category round-trips known names", "[blacklist_ops]") {
    for (auto category : {BlacklistCategory::Ips, BlacklistCategory::Countries,
                           BlacklistCategory::Isps, BlacklistCategory::UserAgents,
                           BlacklistCategory::Referrers, BlacklistCategory::BodyPatterns,
                           BlacklistCategory::FakeRoutes}) {
        auto name = blacklist_category_name(category);
        auto parsed = parse_blacklist_category(name);
        REQUIRE(parsed.has_value());
        CHECK(*parsed == category);
    }
}

TEST_CASE("parse_blacklist_category rejects unknown names", "[blacklist_ops]") {
    CHECK_FALSE(parse_blacklist_category("not_a_category").has_value());
}

TEST_CASE("add_blacklist_entry adds an exact IP", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::Ips, "203.0.113.7");
    REQUIRE(config.blacklist.ip_exact.size() == 1);
    CHECK(config.blacklist.ip_exact[0].value == "203.0.113.7");
}

TEST_CASE("add_blacklist_entry stamps a created_at on the new entry", "[blacklist_ops]") {
    RuntimeConfig config;
    const auto before = std::chrono::system_clock::now();
    add_blacklist_entry(config, BlacklistCategory::UserAgents, "sqlmap");
    const auto after = std::chrono::system_clock::now();
    REQUIRE(config.blacklist.user_agents.size() == 1);
    CHECK(config.blacklist.user_agents[0].created_at >= before);
    CHECK(config.blacklist.user_agents[0].created_at <= after);
}

TEST_CASE("add_blacklist_entry adding the same IP twice is a no-op", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::Ips, "203.0.113.7");
    add_blacklist_entry(config, BlacklistCategory::Ips, "203.0.113.7");
    CHECK(config.blacklist.ip_exact.size() == 1);
}

TEST_CASE("add_blacklist_entry adds a CIDR range", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::Ips, "198.51.100.0/24");
    REQUIRE(config.blacklist.ip_cidrs.size() == 1);
    CHECK(config.blacklist.ip_cidrs[0].text == "198.51.100.0/24");
    CHECK(config.blacklist.ip_exact.empty());
}

TEST_CASE("add_blacklist_entry throws on an invalid IP", "[blacklist_ops]") {
    RuntimeConfig config;
    CHECK_THROWS_AS(add_blacklist_entry(config, BlacklistCategory::Ips, "not-an-ip"),
                     std::invalid_argument);
}

TEST_CASE("add_blacklist_entry throws on an invalid CIDR", "[blacklist_ops]") {
    RuntimeConfig config;
    CHECK_THROWS_AS(add_blacklist_entry(config, BlacklistCategory::Ips, "203.0.113.0/99"),
                     std::invalid_argument);
}

TEST_CASE("add_blacklist_entry throws on an empty value", "[blacklist_ops]") {
    RuntimeConfig config;
    CHECK_THROWS_AS(add_blacklist_entry(config, BlacklistCategory::UserAgents, ""),
                     std::invalid_argument);
}

TEST_CASE("add_blacklist_entry adding the same value twice keeps the original created_at",
          "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::Routes, "/wp-admin");
    const auto first_created_at = config.blacklist.routes[0].created_at;
    add_blacklist_entry(config, BlacklistCategory::Routes, "/wp-admin");
    REQUIRE(config.blacklist.routes.size() == 1);
    CHECK(config.blacklist.routes[0].created_at == first_created_at);
}

TEST_CASE("remove_blacklist_entry removes an exact IP and a CIDR range", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::Ips, "203.0.113.7");
    add_blacklist_entry(config, BlacklistCategory::Ips, "198.51.100.0/24");

    remove_blacklist_entry(config, BlacklistCategory::Ips, "203.0.113.7");
    CHECK(config.blacklist.ip_exact.empty());
    CHECK(config.blacklist.ip_cidrs.size() == 1);

    remove_blacklist_entry(config, BlacklistCategory::Ips, "198.51.100.0/24");
    CHECK(config.blacklist.ip_cidrs.empty());
}

TEST_CASE("clear_blacklist_category empties a generic category", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::UserAgents, "sqlmap");
    add_blacklist_entry(config, BlacklistCategory::UserAgents, "nikto");
    clear_blacklist_category(config, BlacklistCategory::UserAgents);
    CHECK(config.blacklist.user_agents.empty());
}

TEST_CASE("clear_blacklist_category empties both ip_exact and ip_cidrs for Ips", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::Ips, "203.0.113.7");
    add_blacklist_entry(config, BlacklistCategory::Ips, "198.51.100.0/24");
    clear_blacklist_category(config, BlacklistCategory::Ips);
    CHECK(config.blacklist.ip_exact.empty());
    CHECK(config.blacklist.ip_cidrs.empty());
}

TEST_CASE("clear_blacklist_category only clears the named category", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::Routes, "/wp-admin");
    add_blacklist_entry(config, BlacklistCategory::UserAgents, "sqlmap");
    clear_blacklist_category(config, BlacklistCategory::Routes);
    CHECK(config.blacklist.routes.empty());
    CHECK(config.blacklist.user_agents.size() == 1);
}

TEST_CASE("add_blacklist_entry adds a fake route", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::FakeRoutes, "/wp-login-backup");
    REQUIRE(config.blacklist.fake_routes.size() == 1);
    CHECK(config.blacklist.fake_routes[0].value == "/wp-login-backup");
}

TEST_CASE("add_blacklist_entry rejects a fake route not starting with '/'", "[blacklist_ops]") {
    RuntimeConfig config;
    CHECK_THROWS_AS(add_blacklist_entry(config, BlacklistCategory::FakeRoutes, "wp-login-backup"),
                     std::invalid_argument);
}

TEST_CASE("remove_blacklist_entry on a missing value is a no-op", "[blacklist_ops]") {
    RuntimeConfig config;
    remove_blacklist_entry(config, BlacklistCategory::UserAgents, "never-added");
    CHECK(config.blacklist.user_agents.empty());
}

TEST_CASE("add/remove_blacklist_entry work for a non-IP category", "[blacklist_ops]") {
    RuntimeConfig config;
    add_blacklist_entry(config, BlacklistCategory::BodyPatterns, "<script>");
    REQUIRE(config.blacklist.body_patterns.size() == 1);
    remove_blacklist_entry(config, BlacklistCategory::BodyPatterns, "<script>");
    CHECK(config.blacklist.body_patterns.empty());
}

namespace {

std::vector<std::string> values_of(const std::vector<BlacklistEntry>& entries) {
    std::vector<std::string> values;
    for (const auto& entry : entries) {
        values.push_back(entry.value);
    }
    return values;
}

} // namespace

TEST_CASE("import_blacklist_entries adds one entry per line", "[blacklist_ops]") {
    RuntimeConfig config;
    auto result = import_blacklist_entries(config, BlacklistCategory::UserAgents,
                                            "sqlmap\nnikto\ncurl\n");
    CHECK(result.added == 3);
    CHECK(result.skipped == 0);
    CHECK(values_of(config.blacklist.user_agents) == std::vector<std::string>{"sqlmap", "nikto", "curl"});
}

TEST_CASE("import_blacklist_entries skips blank lines, comments, and trims whitespace/CRLF",
          "[blacklist_ops]") {
    RuntimeConfig config;
    auto result = import_blacklist_entries(config, BlacklistCategory::Routes,
                                            "/wp-admin\r\n\n  # a comment\n  /phpmyadmin  \r\n");
    CHECK(result.added == 2);
    CHECK(result.skipped == 0);
    CHECK(values_of(config.blacklist.routes) == std::vector<std::string>{"/wp-admin", "/phpmyadmin"});
}

TEST_CASE("import_blacklist_entries handles a final line with no trailing newline",
          "[blacklist_ops]") {
    RuntimeConfig config;
    auto result = import_blacklist_entries(config, BlacklistCategory::Routes, "/a\n/b");
    CHECK(result.added == 2);
    CHECK(values_of(config.blacklist.routes) == std::vector<std::string>{"/a", "/b"});
}

TEST_CASE("import_blacklist_entries counts invalid IP lines as skipped, not thrown",
          "[blacklist_ops]") {
    RuntimeConfig config;
    auto result = import_blacklist_entries(config, BlacklistCategory::Ips,
                                            "203.0.113.7\nnot-an-ip\n198.51.100.0/24\n");
    CHECK(result.added == 2);
    CHECK(result.skipped == 1);
    CHECK(values_of(config.blacklist.ip_exact) == std::vector<std::string>{"203.0.113.7"});
    REQUIRE(config.blacklist.ip_cidrs.size() == 1);
    CHECK(config.blacklist.ip_cidrs[0].text == "198.51.100.0/24");
}
