#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <vector>

#include "geoip/geoip_service.hpp"

namespace atomwall {

// Deliberately minimal: lat/lon + allow/block only. No IP, User-Agent, path,
// or country/city name field exists on this type — see CLAUDE.md's Live
// Visitor Globe section. That's the actual privacy guarantee: it's
// structurally impossible for any endpoint built on top of this type to leak
// a visitor's identity, not something enforced by remembering to omit a
// field at serialization time.
struct GlobeArcEvent {
    std::uint64_t seq = 0;
    std::chrono::system_clock::time_point timestamp;
    double lat = 0;
    double lon = 0;
    bool blocked = false;
};

// In-memory ring buffer of recent anonymized arc events, same shape as
// history/request_log.hpp's RequestLog. Not persisted — resets on restart.
class GlobeEventLog {
public:
    explicit GlobeEventLog(std::size_t capacity = 500);

    void record(GlobeArcEvent event);

    std::vector<GlobeArcEvent> recent(std::size_t limit) const;
    std::vector<GlobeArcEvent> events_since(std::uint64_t since_seq, std::size_t limit = 500) const;
    std::uint64_t latest_seq() const;

private:
    mutable std::mutex mutex_;
    std::deque<GlobeArcEvent> buffer_;
    std::size_t capacity_;
    std::uint64_t next_seq_ = 1;
};

// Server's own GPS position for the globe's arc endpoint. Written once at
// startup (see main.cpp's resolve_server_location — manual config value, or
// a one-time auto-detect fallback), read on every /globe/snapshot request
// thereafter. Mutex-guarded because the write and reads run on different
// io_context threads, even though the write happens exactly once.
class ServerLocationCache {
public:
    void set(GeoLocation location);
    std::optional<GeoLocation> get() const;

private:
    mutable std::mutex mutex_;
    std::optional<GeoLocation> location_;
};

} // namespace atomwall
