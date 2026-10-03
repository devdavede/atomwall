#include "auth/totp.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace atomwall {

namespace {

constexpr std::string_view kBase32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
constexpr int kDigits = 6;
constexpr std::int64_t kStepSeconds = 30;
constexpr int kSecretBytes = 20; // 160 bits, RFC 4226's recommended HMAC-SHA1 key size

std::string base32_encode(const std::vector<unsigned char>& data) {
    std::string out;
    int buffer = 0;
    int bits_left = 0;
    for (unsigned char byte : data) {
        buffer = (buffer << 8) | byte;
        bits_left += 8;
        while (bits_left >= 5) {
            bits_left -= 5;
            out.push_back(kBase32Alphabet[(buffer >> bits_left) & 0x1F]);
        }
    }
    if (bits_left > 0) {
        out.push_back(kBase32Alphabet[(buffer << (5 - bits_left)) & 0x1F]);
    }
    return out;
}

// Tolerates lowercase, padding, and stray whitespace/hyphens (easy to pick up
// when a secret is copy-pasted rather than scanned) — anything else is
// rejected outright rather than silently ignored, since silently dropping
// unexpected bytes could turn an attacker-influenced string into a
// different, still-valid-looking secret.
std::vector<unsigned char> base32_decode(const std::string& input) {
    std::vector<unsigned char> out;
    int buffer = 0;
    int bits_left = 0;
    for (char raw : input) {
        if (raw == '=' || raw == ' ' || raw == '-') {
            continue;
        }
        char upper = static_cast<char>(std::toupper(static_cast<unsigned char>(raw)));
        auto pos = kBase32Alphabet.find(upper);
        if (pos == std::string_view::npos) {
            throw std::invalid_argument("invalid base32 character in TOTP secret");
        }
        buffer = (buffer << 5) | static_cast<int>(pos);
        bits_left += 5;
        if (bits_left >= 8) {
            bits_left -= 8;
            out.push_back(static_cast<unsigned char>((buffer >> bits_left) & 0xFF));
        }
    }
    return out;
}

std::uint32_t hotp(const std::vector<unsigned char>& key, std::uint64_t counter) {
    std::array<unsigned char, 8> counter_be{};
    for (int i = 7; i >= 0; --i) {
        counter_be[static_cast<std::size_t>(i)] = static_cast<unsigned char>(counter & 0xFF);
        counter >>= 8;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), counter_be.data(),
              counter_be.size(), digest, &digest_len)) {
        throw std::runtime_error("HMAC-SHA1 failed");
    }

    const unsigned char offset = digest[digest_len - 1] & 0x0F;
    const std::uint32_t binary =
        (static_cast<std::uint32_t>(digest[offset] & 0x7F) << 24) |
        (static_cast<std::uint32_t>(digest[offset + 1] & 0xFF) << 16) |
        (static_cast<std::uint32_t>(digest[offset + 2] & 0xFF) << 8) |
        static_cast<std::uint32_t>(digest[offset + 3] & 0xFF);

    std::uint32_t divisor = 1;
    for (int i = 0; i < kDigits; ++i) {
        divisor *= 10;
    }
    return binary % divisor;
}

std::string format_code(std::uint32_t value) {
    std::string out = std::to_string(value);
    if (out.size() < kDigits) {
        out.insert(0, kDigits - out.size(), '0');
    }
    return out;
}

bool constant_time_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace

std::string generate_totp_secret_base32() {
    std::vector<unsigned char> buf(kSecretBytes);
    if (!RAND_bytes(buf.data(), static_cast<int>(buf.size()))) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return base32_encode(buf);
}

std::string totp_provisioning_uri(const std::string& secret_base32, const std::string& username,
                                   const std::string& issuer) {
    // Username/issuer are admin-controlled (not attacker input at the point
    // this is called), but URL-encode the handful of characters that would
    // otherwise break the URI anyway.
    auto encode = [](const std::string& value) {
        std::string out;
        for (char c : value) {
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.') {
                out.push_back(c);
            } else {
                char buf[4];
                std::snprintf(buf, sizeof(buf), "%%%02X", static_cast<unsigned char>(c));
                out += buf;
            }
        }
        return out;
    };
    return "otpauth://totp/" + encode(issuer) + ":" + encode(username) +
           "?secret=" + secret_base32 + "&issuer=" + encode(issuer) +
           "&algorithm=SHA1&digits=6&period=30";
}

bool verify_totp(const std::string& secret_base32, const std::string& code,
                  std::int64_t unix_time_seconds, std::int64_t* matched_step) {
    if (code.size() != kDigits ||
        !std::all_of(code.begin(), code.end(), [](char c) { return std::isdigit(static_cast<unsigned char>(c)); })) {
        return false;
    }

    std::vector<unsigned char> key;
    try {
        key = base32_decode(secret_base32);
    } catch (const std::invalid_argument&) {
        return false;
    }
    if (key.empty()) {
        return false;
    }

    const std::uint64_t counter = static_cast<std::uint64_t>(unix_time_seconds / kStepSeconds);
    for (std::int64_t drift = -1; drift <= 1; ++drift) {
        const std::uint64_t step = static_cast<std::uint64_t>(static_cast<std::int64_t>(counter) + drift);
        if (constant_time_equal(format_code(hotp(key, step)), code)) {
            if (matched_step) {
                *matched_step = static_cast<std::int64_t>(step);
            }
            return true;
        }
    }
    return false;
}

} // namespace atomwall
