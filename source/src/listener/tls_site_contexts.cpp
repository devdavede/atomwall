#include "listener/tls_site_contexts.hpp"

#include <spdlog/spdlog.h>
#include <stdexcept>

#include "listener/tls_context.hpp"

namespace atomwall {

namespace {

bool has_own_cert(const SiteConfig& site) {
    return !site.cert_file.empty() && !site.key_file.empty();
}

} // namespace

TlsSiteContexts::Fingerprint TlsSiteContexts::fingerprint_of(const RuntimeConfig& config) {
    Fingerprint fingerprint;
    for (const auto& site : config.sites) {
        if (!has_own_cert(site)) {
            continue;
        }
        std::error_code ec; // a missing file yields file_time_type::min(), stable until it appears
        fingerprint.push_back(SiteFingerprint{site.domain, site.cert_file, site.key_file,
                                               std::filesystem::last_write_time(site.cert_file, ec),
                                               std::filesystem::last_write_time(site.key_file, ec)});
    }
    return fingerprint;
}

std::shared_ptr<const TlsSiteContexts::ContextMap> TlsSiteContexts::build(const RuntimeConfig& config) {
    auto built = std::make_shared<ContextMap>();
    for (const auto& site : config.sites) {
        if (!has_own_cert(site)) {
            continue;
        }
        try {
            (*built)[site.domain] = std::make_shared<boost::asio::ssl::context>(
                make_tls_server_context(site.cert_file, site.key_file));
        } catch (const std::exception& e) {
            spdlog::error("tls: failed to load cert for site '{}': {}", site.domain, e.what());
        }
    }
    return built;
}

std::shared_ptr<const TlsSiteContexts::ContextMap> TlsSiteContexts::current(
    const std::shared_ptr<const RuntimeConfig>& config) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (checked_config_ == config && contexts_) {
            return contexts_;
        }
        if (refreshing_) {
            return contexts_ ? contexts_ : empty_;
        }
        refreshing_ = true;
    }

    // Only this thread is refreshing; the lock is not held across any of the
    // file I/O below.
    struct RefreshGuard {
        TlsSiteContexts& self;
        ~RefreshGuard() {
            std::lock_guard<std::mutex> lock(self.mutex_);
            self.refreshing_ = false;
        }
    } guard{*this};

    auto fingerprint = fingerprint_of(*config);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (contexts_ && fingerprint == built_fingerprint_) {
            checked_config_ = config;
            return contexts_;
        }
    }

    auto built = build(*config);
    std::lock_guard<std::mutex> lock(mutex_);
    contexts_ = built;
    built_fingerprint_ = std::move(fingerprint);
    checked_config_ = config;
    return contexts_;
}

} // namespace atomwall
