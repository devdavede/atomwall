#include "history/globe_event_log.hpp"

#include <algorithm>

namespace atomwall {

GlobeEventLog::GlobeEventLog(std::size_t capacity) : capacity_(capacity) {}

void GlobeEventLog::record(GlobeArcEvent event) {
    std::lock_guard lock(mutex_);
    event.seq = next_seq_++;
    buffer_.push_back(std::move(event));
    while (buffer_.size() > capacity_) {
        buffer_.pop_front();
    }
}

std::vector<GlobeArcEvent> GlobeEventLog::recent(std::size_t limit) const {
    std::lock_guard lock(mutex_);
    const std::size_t count = std::min(limit, buffer_.size());
    return std::vector<GlobeArcEvent>(buffer_.end() - static_cast<std::ptrdiff_t>(count), buffer_.end());
}

std::vector<GlobeArcEvent> GlobeEventLog::events_since(std::uint64_t since_seq, std::size_t limit) const {
    std::lock_guard lock(mutex_);
    std::vector<GlobeArcEvent> result;
    for (const auto& event : buffer_) {
        if (event.seq > since_seq) {
            result.push_back(event);
            if (result.size() >= limit) {
                break;
            }
        }
    }
    return result;
}

std::uint64_t GlobeEventLog::latest_seq() const {
    std::lock_guard lock(mutex_);
    return next_seq_ - 1;
}

void ServerLocationCache::set(GeoLocation location) {
    std::lock_guard lock(mutex_);
    location_ = std::move(location);
}

std::optional<GeoLocation> ServerLocationCache::get() const {
    std::lock_guard lock(mutex_);
    return location_;
}

} // namespace atomwall
