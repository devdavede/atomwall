#include <catch2/catch_test_macros.hpp>

#include "auth/totp.hpp"

using namespace atomwall;

// RFC 6238 Appendix B test vector, adapted to a 20-byte SHA1 key (the ASCII
// string "12345678901234567890") and 6 digits instead of the RFC's 8, since
// that's the shape every real authenticator app / this codebase uses. Known
// values: at T=59 (counter 1) the code is 287082; at T=1111111109 (counter
// 37037036) it's 081804.
TEST_CASE("verify_totp accepts the RFC 6238 reference code at its exact time step", "[totp]") {
    // Base32("12345678901234567890") — computed once and pinned as a fixture.
    const std::string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    CHECK(verify_totp(secret, "287082", 59));
    CHECK(verify_totp(secret, "081804", 1111111109));
}

TEST_CASE("verify_totp reports which counter step matched", "[totp]") {
    const std::string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    std::int64_t matched_step = -1;
    REQUIRE(verify_totp(secret, "287082", 59, &matched_step));
    CHECK(matched_step == 1); // T=59 -> floor(59/30) == 1
}

TEST_CASE("verify_totp rejects a code far outside the drift window", "[totp]") {
    const std::string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    CHECK_FALSE(verify_totp(secret, "287082", 59 + 3600));
}

TEST_CASE("verify_totp tolerates one step of clock drift on either side", "[totp]") {
    // Same RFC 6238 fixture secret as above, at counter 100 (a clean 30s step
    // boundary: unix_time = 100*30 = 3000) — computed once with an
    // independent Python HOTP implementation and pinned here, so every
    // offset below maps to an exact, unambiguous counter shift.
    const std::string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const std::string code = "295165";
    const std::int64_t step = 3000;

    CHECK(verify_totp(secret, code, step));          // exact step
    CHECK(verify_totp(secret, code, step - 30));      // one step early (clock behind)
    CHECK(verify_totp(secret, code, step + 30));      // one step late (clock ahead)
    CHECK_FALSE(verify_totp(secret, code, step - 90)); // three steps early — outside window
    CHECK_FALSE(verify_totp(secret, code, step + 90)); // three steps late — outside window
}

TEST_CASE("verify_totp rejects malformed codes without throwing", "[totp]") {
    auto secret = generate_totp_secret_base32();
    CHECK_FALSE(verify_totp(secret, "12345", 0));
    CHECK_FALSE(verify_totp(secret, "abcdef", 0));
    CHECK_FALSE(verify_totp(secret, "", 0));
}

TEST_CASE("verify_totp rejects a well-formed code against a garbage secret", "[totp]") {
    CHECK_FALSE(verify_totp("not-valid-base32!!!", "123456", 0));
}

TEST_CASE("generate_totp_secret_base32 produces a different secret each time", "[totp]") {
    CHECK(generate_totp_secret_base32() != generate_totp_secret_base32());
}

TEST_CASE("totp_provisioning_uri embeds the secret and escapes the username", "[totp]") {
    auto uri = totp_provisioning_uri("ABCD1234", "alice smith", "atomwall");
    CHECK(uri.find("secret=ABCD1234") != std::string::npos);
    CHECK(uri.find("alice%20smith") != std::string::npos);
    CHECK(uri.find("otpauth://totp/atomwall:alice%20smith") == 0);
}
