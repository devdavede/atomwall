#pragma once

#include <boost/asio/awaitable.hpp>
#include <memory>

#include "app_state.hpp"

namespace atomwall {

// Serves the admin JSON API + static UI assets. Defaults to loopback-only,
// plain HTTP. Binding non-loopback is refused unless admin.tls_cert_file/
// tls_key_file are both set — TLS is a hard precondition for exposing this
// beyond loopback, since it also gates whether the session cookie is marked
// Secure — see CLAUDE.md Admin UI & API / Authentication for why.
boost::asio::awaitable<void> run_admin_server(std::shared_ptr<AppState> state);

} // namespace atomwall
