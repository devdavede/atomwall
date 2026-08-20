#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace atomwall {

// Per-IP sliding window of recent request timestamps, backing the speed
// check's "N requests per M seconds" rule. In-memory only, lost on restart —
// same lifetime as ScoreTracker/IpBlockTracker.
class RequestRateTracker {
public:
    // Records a request for `ip` at `now`, discards timestamps older than
    // `window`, and returns the number of requests within the window
    // (including this one).
    std::size_t record(const std::string& ip, std::chrono::steady_clock::time_point now,
                        std::chrono::seconds window);

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> history_;
};

} // namespace atomwall
