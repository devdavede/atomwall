#include <algorithm>
#include <catch2/catch_test_macros.hpp>

#include "auth/backup_codes.hpp"

using namespace atomwall;

TEST_CASE("generate_backup_codes produces the requested count of distinct codes", "[backup_codes]") {
    auto codes = generate_backup_codes(10);
    CHECK(codes.size() == 10);
    for (const auto& code : codes) {
        CHECK(code.size() == 9); // "XXXX-XXXX"
        CHECK(code[4] == '-');
    }
    std::vector<std::string> sorted = codes;
    std::sort(sorted.begin(), sorted.end());
    CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end());
}

TEST_CASE("consume_backup_code accepts a valid code exactly once", "[backup_codes]") {
    auto plaintext = generate_backup_codes(3);
    auto hashed = hash_backup_codes(plaintext);

    CHECK(consume_backup_code(hashed, plaintext[1]));
    CHECK(hashed[1].used);
    CHECK_FALSE(consume_backup_code(hashed, plaintext[1])); // already used
}

TEST_CASE("consume_backup_code rejects a code that was never issued", "[backup_codes]") {
    auto plaintext = generate_backup_codes(3);
    auto hashed = hash_backup_codes(plaintext);
    CHECK_FALSE(consume_backup_code(hashed, "ZZZZ-ZZZZ"));
    for (const auto& code : hashed) {
        CHECK_FALSE(code.used);
    }
}

TEST_CASE("consume_backup_code rejects wrong-shaped candidates without consuming anything", "[backup_codes]") {
    auto plaintext = generate_backup_codes(3);
    auto hashed = hash_backup_codes(plaintext);
    const std::string valid = plaintext[0];

    CHECK_FALSE(consume_backup_code(hashed, ""));
    CHECK_FALSE(consume_backup_code(hashed, valid.substr(0, 8)));
    CHECK_FALSE(consume_backup_code(hashed, valid + "X"));
    CHECK_FALSE(consume_backup_code(hashed, std::string(1'000'000, 'A')));
    CHECK_FALSE(consume_backup_code(hashed, valid.substr(0, 4) + "_" + valid.substr(5)));
    CHECK_FALSE(consume_backup_code(hashed, "AAAA-AA0A")); // '0' isn't in the alphabet
    for (const auto& code : hashed) {
        CHECK_FALSE(code.used);
    }
    CHECK(consume_backup_code(hashed, valid));
}
