#pragma once

#include <boost/asio/ssl.hpp>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "config/runtime_config.hpp"

namespace atomwall {

// Per-domain TLS contexts for SNI dispatch (see the servername callback in
// listener/tls_listener.cpp). current() runs inside TLS handshakes on
// io_context threads, so it must never make them queue behind disk I/O:
//
//  - The map is only rebuilt when something it's actually built from changed:
//    a site's domain/cert path/key path, or the modification time of either
//    file (so a renewed cert dropped in place is still picked up). An
//    unrelated config change — blocking an IP, say — costs a couple of stat()
//    calls, not a re-read and re-parse of every site's cert.
//  - The rebuild is single-flight and happens outside the lock: while one
//    handshake reloads certs, every other handshake keeps using the previous
//    map instead of blocking on it. (A site added or removed a moment ago is
//    briefly served by the previous map, i.e. the default cert if it's new.)
//  - run_tls_listener calls current() once before accepting, so the first
//    build isn't done lazily inside a handshake.
//
// Keyed by lowercased domain, matching how yaml_codec/site_ops normalize
// SiteConfig::domain on write.
class TlsSiteContexts {
public:
    using ContextMap = std::map<std::string, std::shared_ptr<boost::asio::ssl::context>>;

    // Returns the current domain -> ssl::context map, reloading first if the
    // TLS-relevant parts of `config` changed since it was last built. A site
    // whose cert fails to load is skipped (logged), not fatal — same
    // "missing/bad optional resource never crashes startup" precedent as
    // GeoIpService elsewhere in this codebase.
    std::shared_ptr<const ContextMap> current(const std::shared_ptr<const RuntimeConfig>& config);

private:
    struct SiteFingerprint {
        std::string domain;
        std::string cert_file;
        std::string key_file;
        std::filesystem::file_time_type cert_mtime;
        std::filesystem::file_time_type key_mtime;
        bool operator==(const SiteFingerprint&) const = default;
    };
    using Fingerprint = std::vector<SiteFingerprint>;

    static Fingerprint fingerprint_of(const RuntimeConfig& config);
    static std::shared_ptr<const ContextMap> build(const RuntimeConfig& config);

    // Guards only the fields below, and is never held across file I/O.
    std::mutex mutex_;
    std::shared_ptr<const RuntimeConfig> checked_config_; // last snapshot compared against built_fingerprint_
    Fingerprint built_fingerprint_;
    std::shared_ptr<const ContextMap> contexts_;
    const std::shared_ptr<const ContextMap> empty_ = std::make_shared<const ContextMap>();
    bool refreshing_ = false;
};

} // namespace atomwall
