#include "auth/webauthn/challenge_store.hpp"

namespace atomwall {

void ChallengeStore::start(const std::string& key, std::vector<std::uint8_t> challenge,
                            std::chrono::minutes ttl) {
    const auto now = std::chrono::system_clock::now();
    const auto expires_at = now + ttl;
    std::lock_guard lock(mutex_);
    entries_[key] = Entry{std::move(challenge), expires_at};
    order_.push_back(Stamp{key, expires_at});

    while (!order_.empty() && (order_.size() > kMaxEntries || order_.front().expires_at <= now)) {
        const auto& oldest = order_.front();
        if (auto it = entries_.find(oldest.key);
            it != entries_.end() && it->second.expires_at == oldest.expires_at) {
            entries_.erase(it);
        }
        order_.pop_front();
    }
}

std::optional<std::vector<std::uint8_t>> ChallengeStore::consume(const std::string& key) {
    const auto now = std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end()) {
        return std::nullopt;
    }
    Entry entry = std::move(it->second);
    entries_.erase(it);
    if (now > entry.expires_at) {
        return std::nullopt;
    }
    return std::move(entry.challenge);
}

std::size_t ChallengeStore::size() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
}

} // namespace atomwall
