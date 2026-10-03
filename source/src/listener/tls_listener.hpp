#pragma once

#include <boost/asio/awaitable.hpp>
#include <memory>

#include "app_state.hpp"

namespace atomwall {

// Binds to https.bind/https.port and loads https.cert_file/key_file at the
// time this is called — same hot-reload limitation as run_http_listener.
boost::asio::awaitable<void> run_tls_listener(std::shared_ptr<AppState> state);

} // namespace atomwall
