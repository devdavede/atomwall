#pragma once

#include <string_view>

#include "config/runtime_config.hpp"

namespace atomwall {

// Resolved routing/cert target for a request, derived from its Host header
// (HTTP) or TLS SNI server name (HTTPS) — see listener/http_session.hpp and
// listener/tls_listener.cpp. Pointers are into the RuntimeConfig snapshot
// passed to resolve_site, so they're valid exactly as long as that snapshot
// is held.
struct ResolvedSite {
    const UpstreamConfig* upstream = nullptr;
    const std::string* cert_file = nullptr; // nullptr => use the default https.cert_file
    const std::string* key_file = nullptr;
    bool enabled = true;
    bool matched = false; // false = fell back to the default site
};

// Strips a trailing ":port" from `host_or_sni`, then compares case-
// insensitively (see pipeline/net_utils.hpp's iequals) by EXACT equality
// against each configured SiteConfig::domain — substring/prefix matching
// would let a request spoof a match (e.g. "example.com.evil.com" must never
// match "example.com"). No match, or an empty `sites` list, resolves to the
// default site (config.https/config.upstream).
ResolvedSite resolve_site(const RuntimeConfig& config, std::string_view host_or_sni);

} // namespace atomwall
