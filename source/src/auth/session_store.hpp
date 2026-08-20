#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace atomwall {

// In-memory session tokens (lost on restart — matches RequestLog/trackers).
// Session cookies are HttpOnly + SameSite=Strict; see CLAUDE.md Security posture
// for why plain HTTP loopback-only is the accepted trust boundary here.
class SessionStore {
public:
    std::string create(const std::string& username, std::chrono::hours ttl = std::chrono::hours(12));

    std::optional<std::string> validate(const std::string& token) const;

    void invalidate(const std::string& token);

private:
    struct Session {
        std::string username;
        std::chrono::system_clock::time_point expires_at;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Session> sessions_;
};

} // namespace atomwall
