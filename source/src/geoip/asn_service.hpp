#pragma once

#include <boost/asio/ip/address.hpp>
#include <cstdint>
#include <maxminddb.h>
#include <optional>
#include <string>

namespace atomwall {

struct AsnInfo {
    std::uint32_t asn = 0;
    std::string organization; // e.g. "Amazon.com, Inc.", "Deutsche Telekom AG"
};

// Same shape as GeoIpService (geoip/geoip_service.hpp), but for a separate
// ASN/ISP database (GeoLite2-ASN, DB-IP ASN Lite, ...) — a different MaxMind
// DB product from the City database, not a different view of the same file.
// Field names aren't fully standardized across vendors, so lookup() tries a
// short list of common key names rather than assuming one vendor's schema.
class AsnService {
public:
    explicit AsnService(const std::string& mmdb_path);
    ~AsnService();

    AsnService(const AsnService&) = delete;
    AsnService& operator=(const AsnService&) = delete;

    bool loaded() const { return loaded_; }

    std::optional<AsnInfo> lookup(const boost::asio::ip::address& address) const;

private:
    MMDB_s db_{};
    bool loaded_ = false;
};

} // namespace atomwall
