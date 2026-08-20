#pragma once

#include <string>

namespace atomwall {

struct PasswordHash {
    std::string salt_hex;
    std::string hash_hex;
    int iterations = 0;
};

// PBKDF2-HMAC-SHA256 with a fresh random 16-byte salt (via OpenSSL RAND_bytes).
PasswordHash hash_password(const std::string& password);

bool verify_password(const std::string& password, const PasswordHash& stored);

} // namespace atomwall
