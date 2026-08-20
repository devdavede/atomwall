#include "geoip/asn_service.hpp"

#include <spdlog/spdlog.h>

namespace atomwall {

namespace {

// Tries each path in order (outer list = alternate top-level key names used
// by different vendors) and returns the first that resolves to data of the
// expected type.
std::optional<std::string> string_from_first_match(MMDB_entry_s& entry,
                                                     std::initializer_list<const char*> keys) {
    for (const char* key : keys) {
        MMDB_entry_data_s data{};
        MMDB_get_value(&entry, &data, key, nullptr);
        if (data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            return std::string(data.utf8_string, data.data_size);
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> uint32_from_first_match(MMDB_entry_s& entry,
                                                       std::initializer_list<const char*> keys) {
    for (const char* key : keys) {
        MMDB_entry_data_s data{};
        MMDB_get_value(&entry, &data, key, nullptr);
        if (!data.has_data) {
            continue;
        }
        if (data.type == MMDB_DATA_TYPE_UINT32) {
            return data.uint32;
        }
        if (data.type == MMDB_DATA_TYPE_UINT16) {
            return data.uint16;
        }
    }
    return std::nullopt;
}

} // namespace

AsnService::AsnService(const std::string& mmdb_path) {
    if (mmdb_path.empty()) {
        return;
    }
    const int status = MMDB_open(mmdb_path.c_str(), MMDB_MODE_MMAP, &db_);
    if (status != MMDB_SUCCESS) {
        spdlog::warn("asn: failed to open '{}': {}", mmdb_path, MMDB_strerror(status));
        return;
    }
    loaded_ = true;
    spdlog::info("asn: loaded database from '{}'", mmdb_path);
}

AsnService::~AsnService() {
    if (loaded_) {
        MMDB_close(&db_);
    }
}

std::optional<AsnInfo> AsnService::lookup(const boost::asio::ip::address& address) const {
    if (!loaded_) {
        return std::nullopt;
    }

    int gai_error = 0;
    int mmdb_error = 0;
    MMDB_lookup_result_s result =
        MMDB_lookup_string(&db_, address.to_string().c_str(), &gai_error, &mmdb_error);
    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) {
        return std::nullopt;
    }

    // GeoLite2-ASN uses "autonomous_system_organization"/"_number"; DB-IP's
    // ASN products vary by release ("as_org"/"as_number", "org"/"asn"). Try
    // the common spellings rather than betting on one vendor's schema.
    auto organization = string_from_first_match(
        result.entry, {"autonomous_system_organization", "as_org", "org", "isp", "organization"});
    auto asn = uint32_from_first_match(result.entry,
                                        {"autonomous_system_number", "as_number", "asn"});
    if (!organization && !asn) {
        return std::nullopt;
    }

    AsnInfo info;
    info.organization = organization.value_or("");
    info.asn = asn.value_or(0);
    return info;
}

} // namespace atomwall
