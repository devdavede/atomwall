#include "auth/backup_codes.hpp"

#include <openssl/rand.h>
#include <stdexcept>
#include <string_view>

namespace atomwall {

namespace {

// No 0/O/1/I/L — meant to be read off a printed page and typed by hand.
constexpr std::string_view kAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";

std::string random_code_group(std::size_t length) {
    std::string out;
    out.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        unsigned char byte = 0;
        if (!RAND_bytes(&byte, 1)) {
            throw std::runtime_error("RAND_bytes failed");
        }
        out.push_back(kAlphabet[byte % kAlphabet.size()]);
    }
    return out;
}

constexpr std::size_t kGroupLength = 4;
constexpr std::size_t kCodeLength = kGroupLength * 2 + 1;

bool has_backup_code_shape(std::string_view candidate) {
    if (candidate.size() != kCodeLength || candidate[kGroupLength] != '-') {
        return false;
    }
    for (std::size_t i = 0; i < candidate.size(); ++i) {
        if (i != kGroupLength && kAlphabet.find(candidate[i]) == std::string_view::npos) {
            return false;
        }
    }
    return true;
}

} // namespace

std::vector<std::string> generate_backup_codes(int count) {
    std::vector<std::string> codes;
    codes.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        codes.push_back(random_code_group(kGroupLength) + "-" + random_code_group(kGroupLength));
    }
    return codes;
}

std::vector<BackupCode> hash_backup_codes(const std::vector<std::string>& plaintext_codes) {
    std::vector<BackupCode> out;
    out.reserve(plaintext_codes.size());
    for (const auto& code : plaintext_codes) {
        out.push_back(BackupCode{hash_password(code), false});
    }
    return out;
}

bool consume_backup_code(std::vector<BackupCode>& codes, const std::string& candidate) {
    // Each verify_password below is a full 210k-iteration PBKDF2, run once per
    // unused stored code — so an attacker-chosen candidate must be rejected
    // on shape alone first, or every junk guess costs ~10 PBKDF2 runs (plus
    // HMAC setup over however large a "code" the request body allowed).
    if (!has_backup_code_shape(candidate)) {
        return false;
    }
    // Deliberately checks every unused code rather than returning on the
    // first match, so the response time doesn't vary with how many stored
    // codes the candidate happens to be close to.
    int match_index = -1;
    for (std::size_t i = 0; i < codes.size(); ++i) {
        if (codes[i].used) {
            continue;
        }
        if (verify_password(candidate, codes[i].hash) && match_index < 0) {
            match_index = static_cast<int>(i);
        }
    }
    if (match_index < 0) {
        return false;
    }
    codes[static_cast<std::size_t>(match_index)].used = true;
    return true;
}

} // namespace atomwall
