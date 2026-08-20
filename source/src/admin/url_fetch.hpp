#pragma once

#include <boost/asio/awaitable.hpp>
#include <chrono>
#include <cstddef>
#include <string>

namespace atomwall {

struct UrlFetchResult {
    bool ok = false;
    std::string body;
    std::string error;
};

// Fetches a plain-text list from an admin-supplied URL (http/https only, no
// redirects followed — see url_fetch.cpp for why). Resolves the host and
// refuses to connect to loopback/private/link-local addresses so the admin
// API can't be used to make the proxy probe its own internal network
// (SSRF) — see CLAUDE.md Security posture: treat all inbound-adjacent input
// (including admin-supplied URLs) as hostile.
boost::asio::awaitable<UrlFetchResult> fetch_url(std::string url, std::size_t max_bytes,
                                                   std::chrono::seconds timeout);

} // namespace atomwall
