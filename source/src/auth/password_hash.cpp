#include "auth/password_hash.hpp"

#include <array>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace atomwall {

namespace {

constexpr int kIterations = 210000;
constexpr int kSaltBytes = 16;
constexpr int kKeyBytes = 32;

std::string to_hex(const unsigned char* data, std::size_t len) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0F]);
    }
    return out;
}

std::vector<unsigned char> from_hex(const std::string& hex) {
    std::vector<unsigned char> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::vector<unsigned char> derive(const std::string& password, const std::vector<unsigned char>& salt,
                                   int iterations) {
    std::vector<unsigned char> key(kKeyBytes);
    if (!PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt.data(),
                            static_cast<int>(salt.size()), iterations, EVP_sha256(), kKeyBytes,
                            key.data())) {
        throw std::runtime_error("PBKDF2 derivation failed");
    }
    return key;
}

} // namespace

PasswordHash hash_password(const std::string& password) {
    std::array<unsigned char, kSaltBytes> salt{};
    if (!RAND_bytes(salt.data(), static_cast<int>(salt.size()))) {
        throw std::runtime_error("RAND_bytes failed");
    }
    std::vector<unsigned char> salt_vec(salt.begin(), salt.end());
    auto key = derive(password, salt_vec, kIterations);

    PasswordHash result;
    result.salt_hex = to_hex(salt_vec.data(), salt_vec.size());
    result.hash_hex = to_hex(key.data(), key.size());
    result.iterations = kIterations;
    return result;
}

bool verify_password(const std::string& password, const PasswordHash& stored) {
    auto salt = from_hex(stored.salt_hex);
    auto key = derive(password, salt, stored.iterations > 0 ? stored.iterations : kIterations);
    auto expected = from_hex(stored.hash_hex);
    if (key.size() != expected.size()) {
        return false;
    }
    return CRYPTO_memcmp(key.data(), expected.data(), key.size()) == 0;
}

} // namespace atomwall
