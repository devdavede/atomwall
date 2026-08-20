#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

namespace atomwall {

struct LoginEvent {
    std::uint64_t seq = 0;
    std::chrono::system_clock::time_point timestamp;
    std::string username;
    std::string client_ip;
};

// In-memory ring buffer of successful admin logins — same shape/pattern as
// history/globe_event_log.hpp's GlobeEventLog. Not persisted, resets on
// restart, same as SessionStore itself (see CLAUDE.md Authentication).
// First-run setup counts as a login too, since it creates a session the same
// way handle_auth_login does.
class LoginHistory {
public:
    explicit LoginHistory(std::size_t capacity = 200);

    void record(LoginEvent event);

    // Most recent `limit` events, oldest first (same convention as
    // RequestLog/GlobeEventLog — callers reverse for a newest-first view).
    std::vector<LoginEvent> recent(std::size_t limit) const;

private:
    mutable std::mutex mutex_;
    std::deque<LoginEvent> buffer_;
    std::size_t capacity_;
    std::uint64_t next_seq_ = 1;
};

} // namespace atomwall
