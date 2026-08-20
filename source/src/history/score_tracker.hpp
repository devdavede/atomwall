#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

namespace atomwall {

// Per-IP running score for the ban system. No decay: points accumulate until
// either the threshold is crossed (caller resets via `reset`) or the process
// restarts. In-memory only.
class ScoreTracker {
public:
    int add_points(const std::string& ip, int points);
    void reset(const std::string& ip);
    int current(const std::string& ip) const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, int> scores_;
};

} // namespace atomwall
