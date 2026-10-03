#pragma once

#include <chrono>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace atomwall {

// Holds "password was correct, a second factor is still owed" state between
// POST /api/auth/login and the follow-up 2FA verify call. Deliberately a
// distinct type from SessionStore (not a "partial session" flag on it) so
// there is no code path where a pending-MFA token could be mistaken for, or
// accidentally accepted as, an authenticated session — see admin_server.cpp's
// needs_auth gate, which never even looks at this store.
//
// In-memory, lost on restart (same pattern as SessionStore/RequestLog) — an
// interrupted login just has to be retried from the password step, which is
// harmless since nothing else was ever granted.
class PendingMfaStore {
public:
    std::string create(const std::string& username, std::chrono::minutes ttl = std::chrono::minutes(5));

    std::optional<std::string> validate(const std::string& token) const;

    void invalidate(const std::string& token);

    std::size_t size() const;

private:
    struct Entry {
        std::string username;
        std::chrono::system_clock::time_point expires_at;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Entry> pending_;
};

} // namespace atomwall
