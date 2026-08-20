#include "history/score_tracker.hpp"

namespace atomwall {

int ScoreTracker::add_points(const std::string& ip, int points) {
    std::lock_guard lock(mutex_);
    return scores_[ip] += points;
}

void ScoreTracker::reset(const std::string& ip) {
    std::lock_guard lock(mutex_);
    scores_.erase(ip);
}

int ScoreTracker::current(const std::string& ip) const {
    std::lock_guard lock(mutex_);
    auto it = scores_.find(ip);
    return it == scores_.end() ? 0 : it->second;
}

} // namespace atomwall
