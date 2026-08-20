#pragma once

#include <boost/asio/awaitable.hpp>
#include <memory>

#include "app_state.hpp"

namespace atomwall {

// A dedicated public listener for the live-visitor-globe embed, separate
// from both the public :80/:443 proxy listeners and the loopback-only admin
// port (see CLAUDE.md's Live Visitor Globe section). Unlike admin_server,
// this server has NO authentication — that's safe by construction because
// GlobeEventLog (see history/globe_event_log.hpp) never carries an IP or any
// other identifying field, so there's nothing here for an unauthenticated
// caller to learn beyond "roughly where recent visitors were and whether
// they were blocked". Only started when config->globe.public_enabled is true.
boost::asio::awaitable<void> run_globe_server(std::shared_ptr<AppState> state);

} // namespace atomwall
