#pragma once

#include <boost/json.hpp>
#include <optional>

#include "auth/user_store.hpp"
#include "config/blacklist_ops.hpp"
#include "config/runtime_config.hpp"
#include "geoip/geoip_service.hpp"
#include "history/globe_event_log.hpp"
#include "history/ip_block_tracker.hpp"
#include "history/login_history.hpp"
#include "history/request_log.hpp"

namespace atomwall {

boost::json::array entry_list_to_json(const std::vector<BlacklistEntry>& values);
boost::json::array ip_blacklist_to_json(const BlacklistConfig& blacklist);
boost::json::object blacklist_to_json(const BlacklistConfig& blacklist);
boost::json::array whitelist_to_json(const WhitelistConfig& whitelist);
boost::json::object config_to_json(const RuntimeConfig& config);
boost::json::array blacklist_category_to_json(const BlacklistConfig& blacklist,
                                               BlacklistCategory category);

std::string to_iso8601(std::chrono::system_clock::time_point tp);
boost::json::object request_event_to_json(const RequestEvent& event);
boost::json::array request_events_to_json(const std::vector<RequestEvent>& events);

// Unified view combining the permanent (YAML) IP/CIDR blacklist with the
// temporary (in-memory) tracker — each entry tagged with source/permanence.
boost::json::array ip_blocks_to_json(const BlacklistConfig& blacklist,
                                      const std::vector<TemporaryIpBlock>& temporary);

// The default site (top-level https/upstream) plus every named entry in
// `sites`, each tagged so the admin UI can tell them apart (the default
// site has no domain/enabled toggle of its own — see config/site_lookup.hpp).
boost::json::object sites_to_json(const RuntimeConfig& config);
boost::json::object site_to_json(const SiteConfig& site);

boost::json::object ban_config_to_json(const BanConfig& ban);
boost::json::object speed_check_to_json(const SpeedCheckConfig& speed_check);
boost::json::object method_check_to_json(const MethodCheckConfig& method_check);
boost::json::object pages_to_json(const ResponsePagesConfig& pages);
boost::json::object status_page_to_json(const StatusPageEntry& entry);
boost::json::array status_pages_to_json(const std::vector<StatusPageEntry>& entries);
boost::json::object request_log_config_to_json(const RequestLogConfig& request_log);
boost::json::array users_to_json(const std::vector<UserRecord>& users);
boost::json::object login_event_to_json(const LoginEvent& event);
boost::json::array login_events_to_json(const std::vector<LoginEvent>& events);

boost::json::object geoip_config_to_json(const GeoIpConfig& geoip, bool loaded, bool asn_loaded);
boost::json::object globe_config_to_json(const GlobeConfig& globe);
boost::json::object globe_event_to_json(const GlobeArcEvent& event);
boost::json::array globe_events_to_json(const std::vector<GlobeArcEvent>& events);
boost::json::value server_location_to_json(const std::optional<GeoLocation>& location);

} // namespace atomwall
