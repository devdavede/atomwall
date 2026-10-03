#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace atomwall {

// Per-IP running score for the ban system. No decay: points accumulate until
// either the threshold is crossed (caller resets via `reset`) or the process
// restarts. In-memory only.
//
// Keyed by client IP, which a remote party controls, and an IP that scores but
// never reaches the threshold is otherwise never removed — so the number of
// tracked IPs is capped and, past the cap, the oldest-tracked IP's score is
// dropped (it starts again from zero if it reoffends). That bounds memory
// without adding decay semantics; an IP has to be among the most recent
// `max_tracked_ips` scorers to keep accumulating.
class ScoreTracker {
public:
    static constexpr std::size_t kDefaultMaxTrackedIps = 100'000;

    explicit ScoreTracker(std::size_t max_tracked_ips = kDefaultMaxTrackedIps)
        : max_tracked_ips_(std::max<std::size_t>(1, max_tracked_ips)) {}

    int add_points(const std::string& ip, int points);
    void reset(const std::string& ip);
    int current(const std::string& ip) const;
    std::size_t tracked_ips() const;

private:
    struct Entry {
        int score = 0;
        std::uint64_t seq = 0; // matches the queue item that tracks this entry's age
    };

    const std::size_t max_tracked_ips_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Entry> scores_;
    // Insertion order. Holds stale items for IPs since reset or re-inserted;
    // those are skipped on pop because their seq no longer matches.
    std::deque<std::pair<std::string, std::uint64_t>> order_;
    std::uint64_t next_seq_ = 0;
};

} // namespace atomwall
