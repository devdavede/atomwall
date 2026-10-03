#pragma once

#include <boost/asio/awaitable.hpp>
#include <memory>

#include "app_state.hpp"

namespace atomwall {

// Binds to http.bind/http.port from the config at the time this is called —
// listener bind address/port are not hot-reloadable (only blacklist/upstream
// config is, per-request, via state->config_store). Restart to change them.
boost::asio::awaitable<void> run_http_listener(std::shared_ptr<AppState> state);

} // namespace atomwall
