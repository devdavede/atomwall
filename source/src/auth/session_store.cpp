#include "auth/session_store.hpp"

#include <array>
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

std::string SessionStore::create(const std::string& username, bool needs_mfa_setup,
                                  std::chrono::hours ttl) {
    auto token = random_token_hex();
    const auto now = std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    // Expired entries are otherwise only ever dropped by an explicit logout,
    // so a client that logs in repeatedly without logging out would grow this
    // map until restart. Sweeping on insert bounds it by ttl x login rate
    // (and login is PBKDF2-gated).
    std::erase_if(sessions_, [now](const auto& entry) { return now > entry.second.expires_at; });
    sessions_[token] = Session{username, needs_mfa_setup, now + ttl};
    return token;
}

std::optional<SessionInfo> SessionStore::validate(const std::string& token) const {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(token);
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    if (std::chrono::system_clock::now() > it->second.expires_at) {
        return std::nullopt;
    }
    return SessionInfo{it->second.username, it->second.needs_mfa_setup};
}

void SessionStore::invalidate(const std::string& token) {
    std::lock_guard lock(mutex_);
    sessions_.erase(token);
}

void SessionStore::mark_mfa_satisfied(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(token);
    if (it != sessions_.end()) {
        it->second.needs_mfa_setup = false;
    }
}

std::size_t SessionStore::size() const {
    std::lock_guard lock(mutex_);
    return sessions_.size();
}

} // namespace atomwall
