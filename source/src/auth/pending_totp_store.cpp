#include "auth/pending_totp_store.hpp"

namespace atomwall {

void PendingTotpStore::start(const std::string& username, const std::string& secret_base32,
                              std::chrono::minutes ttl) {
    std::lock_guard lock(mutex_);
    pending_[username] = Entry{secret_base32, std::chrono::system_clock::now() + ttl};
}

std::optional<std::string> PendingTotpStore::secret_for(const std::string& username) const {
    std::lock_guard lock(mutex_);
    auto it = pending_.find(username);
    if (it == pending_.end()) {
        return std::nullopt;
    }
    if (std::chrono::system_clock::now() > it->second.expires_at) {
        return std::nullopt;
    }
    return it->second.secret_base32;
}

void PendingTotpStore::clear(const std::string& username) {
    std::lock_guard lock(mutex_);
    pending_.erase(username);
}

} // namespace atomwall
