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
//
// Keyed by client IP, which a remote party controls (any IPv6 /64 is 2^64 of
// them), so an IP's entry must not outlive its usefulness: record() only
// trims the timestamps of the IP it's called for, so without a sweep every
// distinct IP ever seen would stay in the map forever. Once per window, the
// whole map is swept of entries with nothing left inside the window, which
// bounds memory by request rate x window rather than by how long the process
// has been up.
class RequestRateTracker {
public:
    // Records a request for `ip` at `now`, discards timestamps older than
    // `window`, and returns the number of requests within the window
    // (including this one).
    std::size_t record(const std::string& ip, std::chrono::steady_clock::time_point now,
                        std::chrono::seconds window);

    std::size_t tracked_ips() const;

private:
    void sweep_locked(std::chrono::steady_clock::time_point cutoff);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> history_;
    std::chrono::steady_clock::time_point last_sweep_{};
};

} // namespace atomwall
