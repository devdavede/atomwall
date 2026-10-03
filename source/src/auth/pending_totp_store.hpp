#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace atomwall {

// Holds a freshly-generated TOTP secret between POST /api/auth/2fa/totp/setup
// and .../confirm, keyed by username rather than a token (only one
// in-progress enrollment per user makes sense; starting a new one discards
// any prior unconfirmed attempt). Never touches disk — an abandoned setup
// must not leave a half-configured secret in users.yaml, only
// UserStore::set_totp (called from the confirm handler) persists one.
class PendingTotpStore {
public:
    // Overwrites any existing pending secret for this user.
    void start(const std::string& username, const std::string& secret_base32,
               std::chrono::minutes ttl = std::chrono::minutes(10));

    std::optional<std::string> secret_for(const std::string& username) const;

    void clear(const std::string& username);

private:
    struct Entry {
        std::string secret_base32;
        std::chrono::system_clock::time_point expires_at;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Entry> pending_;
};

} // namespace atomwall
