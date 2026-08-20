#include "history/request_rate_tracker.hpp"

namespace atomwall {

std::size_t RequestRateTracker::record(const std::string& ip,
                                        std::chrono::steady_clock::time_point now,
                                        std::chrono::seconds window) {
    std::lock_guard lock(mutex_);
    auto& timestamps = history_[ip];
    timestamps.push_back(now);
    const auto cutoff = now - window;
    while (!timestamps.empty() && timestamps.front() < cutoff) {
        timestamps.pop_front();
    }
    return timestamps.size();
}

} // namespace atomwall
