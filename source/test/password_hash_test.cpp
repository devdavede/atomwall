#include <catch2/catch_test_macros.hpp>

#include "auth/password_hash.hpp"

using namespace atomwall;

TEST_CASE("hash_password then verify_password succeeds for the right password", "[password_hash]") {
    auto hashed = hash_password("correct horse battery staple");
    CHECK(verify_password("correct horse battery staple", hashed));
}

TEST_CASE("verify_password fails for the wrong password", "[password_hash]") {
    auto hashed = hash_password("correct horse battery staple");
    CHECK_FALSE(verify_password("wrong password", hashed));
}

TEST_CASE("hash_password produces a different salt each time", "[password_hash]") {
    auto a = hash_password("same password");
    auto b = hash_password("same password");
    CHECK(a.salt_hex != b.salt_hex);
    CHECK(a.hash_hex != b.hash_hex);
    CHECK(verify_password("same password", a));
    CHECK(verify_password("same password", b));
}
