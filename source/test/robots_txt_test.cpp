#include <catch2/catch_test_macros.hpp>

#include "pipeline/robots_txt.hpp"

using namespace atomwall;

namespace {
std::vector<BlacklistEntry> routes(std::initializer_list<std::string> values) {
    std::vector<BlacklistEntry> out;
    for (const auto& v : values) {
        out.push_back(BlacklistEntry{v});
    }
    return out;
}
} // namespace

TEST_CASE("build_robots_txt_body returns base unchanged when there are no fake_routes",
          "[robots_txt]") {
    CHECK(build_robots_txt_body("User-agent: *\nAllow: /\n", {}) == "User-agent: *\nAllow: /\n");
    CHECK(build_robots_txt_body("", {}).empty());
}

TEST_CASE("build_robots_txt_body creates a wildcard group when base is empty", "[robots_txt]") {
    auto body = build_robots_txt_body("", routes({"/wp-login-backup", "/secret-trap"}));
    CHECK(body == "User-agent: *\nDisallow: /wp-login-backup\nDisallow: /secret-trap\n");
}

TEST_CASE("build_robots_txt_body merges into an existing wildcard group rather than appending "
          "a second one",
          "[robots_txt]") {
    const std::string base =
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /imprint.html\n"
        "\n"
        "User-agent: ia_archiver\n"
        "Disallow: /\n";
    auto body = build_robots_txt_body(base, routes({"/wp-login-backup"}));

    // The real content survives...
    CHECK(body.find("Allow: /\n") != std::string::npos);
    CHECK(body.find("Disallow: /imprint.html") != std::string::npos);
    CHECK(body.find("User-agent: ia_archiver") != std::string::npos);
    // ...and the honeypot line lands inside the FIRST "User-agent: *" group,
    // not in a new group appended after ia_archiver's (which most crawlers
    // would never read, since they stop at their first matching group).
    auto wildcard_pos = body.find("User-agent: *");
    auto honeypot_pos = body.find("Disallow: /wp-login-backup");
    auto archiver_pos = body.find("User-agent: ia_archiver");
    REQUIRE(wildcard_pos != std::string::npos);
    REQUIRE(honeypot_pos != std::string::npos);
    REQUIRE(archiver_pos != std::string::npos);
    CHECK(wildcard_pos < honeypot_pos);
    CHECK(honeypot_pos < archiver_pos);
    // Only one "User-agent: *" group exists — it was extended, not duplicated.
    CHECK(body.find("User-agent: *", wildcard_pos + 1) == std::string::npos);
}

TEST_CASE("build_robots_txt_body appends a new wildcard group when base has none", "[robots_txt]") {
    const std::string base = "User-agent: ia_archiver\nDisallow: /\n";
    auto body = build_robots_txt_body(base, routes({"/trap"}));
    CHECK(body.find("User-agent: ia_archiver") != std::string::npos);
    CHECK(body.find("User-agent: *") != std::string::npos);
    CHECK(body.find("Disallow: /trap") != std::string::npos);
    // The ia_archiver group is untouched (still followed by exactly its own line).
    CHECK(body.find("User-agent: ia_archiver\nDisallow: /\n") != std::string::npos);
}

TEST_CASE("build_robots_txt_body matches \"User-agent: *\" case-insensitively and with extra spacing",
          "[robots_txt]") {
    auto body = build_robots_txt_body("user-agent:    *\nAllow: /\n", routes({"/trap"}));
    // Merged into the existing (lowercase, oddly-spaced) group — original
    // line preserved as-is, honeypot line inserted right after it, and no
    // second wildcard group appended.
    CHECK(body == "user-agent:    *\nDisallow: /trap\nAllow: /\n");
}
