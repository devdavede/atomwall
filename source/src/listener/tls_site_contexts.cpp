#include "listener/tls_site_contexts.hpp"

#include <spdlog/spdlog.h>
#include <stdexcept>

#include "listener/tls_context.hpp"

namespace atomwall {

std::shared_ptr<const TlsSiteContexts::ContextMap> TlsSiteContexts::current(
    const std::shared_ptr<const RuntimeConfig>& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (contexts_ && built_from_ == config) {
        return contexts_;
    }

    auto built = std::make_shared<ContextMap>();
    for (const auto& site : config->sites) {
        if (site.cert_file.empty() || site.key_file.empty()) {
            continue;
        }
        try {
            (*built)[site.domain] = std::make_shared<boost::asio::ssl::context>(
                make_tls_server_context(site.cert_file, site.key_file));
        } catch (const std::exception& e) {
            spdlog::error("tls: failed to load cert for site '{}': {}", site.domain, e.what());
        }
    }

    built_from_ = config;
    contexts_ = built;
    return contexts_;
}

} // namespace atomwall
