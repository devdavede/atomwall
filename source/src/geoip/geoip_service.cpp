#include "geoip/geoip_service.hpp"

#include <spdlog/spdlog.h>

namespace atomwall {

namespace {

std::optional<double> entry_as_double(MMDB_entry_data_s& entry) {
    if (!entry.has_data) {
        return std::nullopt;
    }
    if (entry.type == MMDB_DATA_TYPE_DOUBLE) {
        return entry.double_value;
    }
    if (entry.type == MMDB_DATA_TYPE_FLOAT) {
        return static_cast<double>(entry.float_value);
    }
    return std::nullopt;
}

} // namespace

GeoIpService::GeoIpService(const std::string& mmdb_path) {
    if (mmdb_path.empty()) {
        return;
    }
    const int status = MMDB_open(mmdb_path.c_str(), MMDB_MODE_MMAP, &db_);
    if (status != MMDB_SUCCESS) {
        spdlog::warn("geoip: failed to open '{}': {}", mmdb_path, MMDB_strerror(status));
        return;
    }
    loaded_ = true;
    spdlog::info("geoip: loaded database from '{}'", mmdb_path);
}

GeoIpService::~GeoIpService() {
    if (loaded_) {
        MMDB_close(&db_);
    }
}

std::optional<GeoLocation> GeoIpService::lookup(const boost::asio::ip::address& address) const {
    if (!loaded_) {
        return std::nullopt;
    }

    // MMDB_lookup_sockaddr wants a sockaddr; going via the string form is the
    // simplest correct path for both v4/v6 without hand-building sockaddr
    // structs (this runs off the hottest part of the hot path — once per
    // request, not per byte — so the extra parse is a non-issue).
    int gai_error = 0;
    int mmdb_error = 0;
    MMDB_lookup_result_s result =
        MMDB_lookup_string(&db_, address.to_string().c_str(), &gai_error, &mmdb_error);
    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) {
        return std::nullopt;
    }

    MMDB_entry_data_s lat_entry{};
    MMDB_entry_data_s lon_entry{};
    MMDB_get_value(&result.entry, &lat_entry, "location", "latitude", nullptr);
    MMDB_get_value(&result.entry, &lon_entry, "location", "longitude", nullptr);
    auto lat = entry_as_double(lat_entry);
    auto lon = entry_as_double(lon_entry);
    if (!lat || !lon) {
        return std::nullopt;
    }

    GeoLocation location;
    location.lat = *lat;
    location.lon = *lon;

    MMDB_entry_data_s country_entry{};
    MMDB_get_value(&result.entry, &country_entry, "country", "iso_code", nullptr);
    if (country_entry.has_data && country_entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
        location.country =
            std::string(country_entry.utf8_string, country_entry.data_size);
    }

    return location;
}

} // namespace atomwall
