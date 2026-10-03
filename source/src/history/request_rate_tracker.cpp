#include "history/request_rate_tracker.hpp"

namespace atomwall {

std::size_t RequestRateTracker::record(const std::string& ip,
                                        std::chrono::steady_clock::time_point now,
                                        std::chrono::seconds window) {
    std::lock_guard lock(mutex_);
    const auto cutoff = now - window;
    if (now - last_sweep_ >= window) {
        sweep_locked(cutoff);
        last_sweep_ = now;
    }
    auto& timestamps = history_[ip];
    timestamps.push_back(now);
    while (!timestamps.empty() && timestamps.front() < cutoff) {
        timestamps.pop_front();
    }
    return timestamps.size();
}

std::size_t RequestRateTracker::tracked_ips() const {
    std::lock_guard lock(mutex_);
    return history_.size();
}

void RequestRateTracker::sweep_locked(std::chrono::steady_clock::time_point cutoff) {
    for (auto it = history_.begin(); it != history_.end();) {
        if (it->second.empty() || it->second.back() < cutoff) {
            it = history_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace atomwall
