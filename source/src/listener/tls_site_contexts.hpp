#pragma once

#include <boost/asio/ssl.hpp>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "config/runtime_config.hpp"

namespace atomwall {

// Per-domain TLS contexts for SNI dispatch (see the servername callback in
// listener/tls_listener.cpp). Cert/key files are only read from disk when
// the RuntimeConfig snapshot actually changes, never per-connection —
// loading them on the hot path would be blocking disk I/O, see CLAUDE.md
// Performance posture. Keyed by lowercased domain, matching how
// yaml_codec/site_ops normalize SiteConfig::domain on write.
class TlsSiteContexts {
public:
    using ContextMap = std::map<std::string, std::shared_ptr<boost::asio::ssl::context>>;

    // Returns the current domain -> ssl::context map, rebuilding it first if
    // `config` is a newer snapshot than the one it was last built from. A
    // site whose cert fails to load is skipped (logged), not fatal — same
    // "missing/bad optional resource never crashes startup" precedent as
    // GeoIpService elsewhere in this codebase.
    std::shared_ptr<const ContextMap> current(const std::shared_ptr<const RuntimeConfig>& config);

private:
    std::mutex mutex_;
    std::shared_ptr<const RuntimeConfig> built_from_;
    std::shared_ptr<const ContextMap> contexts_;
};

} // namespace atomwall
