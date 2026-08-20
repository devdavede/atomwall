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

std::string SessionStore::create(const std::string& username, std::chrono::hours ttl) {
    auto token = random_token_hex();
    std::lock_guard lock(mutex_);
    sessions_[token] = Session{username, std::chrono::system_clock::now() + ttl};
    return token;
}

std::optional<std::string> SessionStore::validate(const std::string& token) const {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(token);
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    if (std::chrono::system_clock::now() > it->second.expires_at) {
        return std::nullopt;
    }
    return it->second.username;
}

void SessionStore::invalidate(const std::string& token) {
    std::lock_guard lock(mutex_);
    sessions_.erase(token);
}

} // namespace atomwall
