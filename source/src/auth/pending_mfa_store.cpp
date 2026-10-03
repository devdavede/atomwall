#include "auth/pending_mfa_store.hpp"

#include <openssl/rand.h>
#include <stdexcept>
#include <vector>

namespace atomwall {

namespace {

std::string random_token_hex(std::size_t bytes = 32) {
    std::vector<unsigned char> buf(bytes);
    if (!RAND_bytes(buf.data(), static_cast<int>(buf.size()))) {
        throw std::runtime_error("RAND_bytes failed");
    }
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (auto b : buf) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

} // namespace

std::string PendingMfaStore::create(const std::string& username, std::chrono::minutes ttl) {
    auto token = random_token_hex();
    const auto now = std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    // Entries are otherwise only dropped when a 2FA verify succeeds, so
    // abandoned challenges would accumulate until restart.
    std::erase_if(pending_, [now](const auto& entry) { return now > entry.second.expires_at; });
    pending_[token] = Entry{username, now + ttl};
    return token;
}

std::optional<std::string> PendingMfaStore::validate(const std::string& token) const {
    std::lock_guard lock(mutex_);
    auto it = pending_.find(token);
    if (it == pending_.end()) {
        return std::nullopt;
    }
    if (std::chrono::system_clock::now() > it->second.expires_at) {
        return std::nullopt;
    }
    return it->second.username;
}

void PendingMfaStore::invalidate(const std::string& token) {
    std::lock_guard lock(mutex_);
    pending_.erase(token);
}

std::size_t PendingMfaStore::size() const {
    std::lock_guard lock(mutex_);
    return pending_.size();
}

} // namespace atomwall
