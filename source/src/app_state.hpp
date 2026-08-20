#pragma once

#include <memory>

#include "auth/session_store.hpp"
#include "auth/user_store.hpp"
#include "config/config_store.hpp"
#include "geoip/asn_service.hpp"
#include "geoip/geoip_service.hpp"
#include "history/globe_event_log.hpp"
#include "history/ip_block_tracker.hpp"
#include "history/login_history.hpp"
#include "history/request_log.hpp"
#include "history/request_rate_tracker.hpp"
#include "history/score_tracker.hpp"
#include "listener/tls_site_contexts.hpp"

namespace atomwall {

// Bundles every shared, long-lived service the listeners and admin server
// need. Passed as one shared_ptr rather than threading each service through
// every function signature individually.
struct AppState {
    std::shared_ptr<ConfigStore> config_store;
    std::shared_ptr<RequestLog> request_log;
    std::shared_ptr<IpBlockTracker> ip_blocks;
    std::shared_ptr<ScoreTracker> scores;
    std::shared_ptr<RequestRateTracker> rate_tracker;
    std::shared_ptr<UserStore> users;
    std::shared_ptr<SessionStore> sessions;
    std::shared_ptr<LoginHistory> login_history;
    std::shared_ptr<GeoIpService> geoip;
    std::shared_ptr<AsnService> asn;
    std::shared_ptr<GlobeEventLog> globe_events;
    std::shared_ptr<ServerLocationCache> server_location;
    std::shared_ptr<TlsSiteContexts> tls_sites;
};

} // namespace atomwall
