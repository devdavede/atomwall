#pragma once

#include <boost/asio/ip/address.hpp>
#include <maxminddb.h>
#include <optional>
#include <string>

namespace atomwall {

struct GeoLocation {
    double lat = 0;
    double lon = 0;
    std::string country; // ISO country code, e.g. "US"; empty if not present in the DB
};

// Thin wrapper around a MaxMind GeoLite2-City .mmdb file. Opened once at
// construction; libmaxminddb lookups are safe for concurrent read-only use
// afterward, so no locking is needed on the hot path (see CLAUDE.md
// Performance posture).
//
// An empty path, missing file, or malformed DB leaves the service
// "unloaded" — lookup() always returns nullopt in that case rather than
// throwing, so a misconfigured/absent GeoIP DB degrades to today's
// no-GeoIP behavior instead of crashing the proxy.
class GeoIpService {
public:
    explicit GeoIpService(const std::string& mmdb_path);
    ~GeoIpService();

    GeoIpService(const GeoIpService&) = delete;
    GeoIpService& operator=(const GeoIpService&) = delete;

    bool loaded() const { return loaded_; }

    std::optional<GeoLocation> lookup(const boost::asio::ip::address& address) const;

private:
    MMDB_s db_{};
    bool loaded_ = false;
};

} // namespace atomwall
