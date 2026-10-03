#include "history/score_tracker.hpp"

#include <algorithm>
#include <limits>

namespace atomwall {

int ScoreTracker::add_points(const std::string& ip, int points) {
    std::lock_guard lock(mutex_);
    auto [it, inserted] = scores_.try_emplace(ip);
    if (inserted) {
        it->second.seq = next_seq_++;
        order_.emplace_back(ip, it->second.seq);
        // max_tracked_ips_ >= 1, so the entry just added (at the back) is never
        // what gets evicted here, and `it` stays valid: erasing other elements
        // doesn't invalidate references to this one.
        while (order_.size() > max_tracked_ips_) {
            const auto& oldest = order_.front();
            if (auto found = scores_.find(oldest.first);
                found != scores_.end() && found->second.seq == oldest.second) {
                scores_.erase(found);
            }
            order_.pop_front();
        }
    }
    int& total = it->second.score;
    // Point values are admin-configured and can be huge; a plain `+=` would
    // wrap a large total negative (signed overflow), silently un-banning an IP
    // that should have crossed the threshold long ago.
    const long long sum = static_cast<long long>(total) + points;
    total = static_cast<int>(std::clamp<long long>(sum, std::numeric_limits<int>::min(),
                                                     std::numeric_limits<int>::max()));
    return total;
}

void ScoreTracker::reset(const std::string& ip) {
    std::lock_guard lock(mutex_);
    scores_.erase(ip);
}

int ScoreTracker::current(const std::string& ip) const {
    std::lock_guard lock(mutex_);
    auto it = scores_.find(ip);
    return it == scores_.end() ? 0 : it->second.score;
}

std::size_t ScoreTracker::tracked_ips() const {
    std::lock_guard lock(mutex_);
    return scores_.size();
}

} // namespace atomwall
