#include "config/site_ops.hpp"

#include <algorithm>
#include <stdexcept>

#include "pipeline/net_utils.hpp"

namespace atomwall {

namespace {

auto find_site(std::vector<SiteConfig>& sites, const std::string& domain) {
    return std::find_if(sites.begin(), sites.end(),
                         [&](const SiteConfig& site) { return iequals(site.domain, domain); });
}

} // namespace

void add_site(RuntimeConfig& config, SiteConfig site) {
    if (site.domain.empty() || site.domain.find_first_of(" \t/") != std::string::npos) {
        throw std::invalid_argument("site domain must be a bare hostname, e.g. 'example.com'");
    }
    site.domain = to_lower(site.domain);

    if (find_site(config.sites, site.domain) != config.sites.end()) {
        throw std::invalid_argument("a site for domain '" + site.domain + "' already exists");
    }

    config.sites.push_back(std::move(site));
}

void update_site(RuntimeConfig& config, const std::string& domain, const SiteUpdate& update) {
    auto it = find_site(config.sites, domain);
    if (it == config.sites.end()) {
        throw std::invalid_argument("no site configured for domain '" + domain + "'");
    }

    if (update.enabled) {
        it->enabled = *update.enabled;
    }
    if (update.cert_file) {
        it->cert_file = *update.cert_file;
    }
    if (update.key_file) {
        it->key_file = *update.key_file;
    }
    if (update.upstream_host) {
        it->upstream.host = *update.upstream_host;
    }
    if (update.upstream_port) {
        it->upstream.port = *update.upstream_port;
    }
}

void remove_site(RuntimeConfig& config, const std::string& domain) {
    auto it = find_site(config.sites, domain);
    if (it == config.sites.end()) {
        throw std::invalid_argument("no site configured for domain '" + domain + "'");
    }
    config.sites.erase(it);
}

} // namespace atomwall
