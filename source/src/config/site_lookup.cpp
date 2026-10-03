#include "config/site_lookup.hpp"

#include "pipeline/net_utils.hpp"

namespace atomwall {

namespace {

std::string_view strip_port(std::string_view host) {
    const auto colon = host.rfind(':');
    if (colon == std::string_view::npos) {
        return host;
    }
    // IPv6 literals ("[::1]:443") contain colons before the port too; only
    // treat this as a port separator when everything after it is digits.
    const auto port_part = host.substr(colon + 1);
    if (port_part.empty() ||
        port_part.find_first_not_of("0123456789") != std::string_view::npos) {
        return host;
    }
    return host.substr(0, colon);
}

} // namespace

ResolvedSite resolve_site(const RuntimeConfig& config, std::string_view host_or_sni) {
    const auto name = strip_port(host_or_sni);

    for (const auto& site : config.sites) {
        if (iequals(name, site.domain)) {
            ResolvedSite resolved;
            resolved.upstream = &site.upstream;
            resolved.cert_file = site.cert_file.empty() ? nullptr : &site.cert_file;
            resolved.key_file = site.key_file.empty() ? nullptr : &site.key_file;
            resolved.enabled = site.enabled;
            resolved.matched = true;
            return resolved;
        }
    }

    ResolvedSite resolved;
    resolved.upstream = &config.upstream;
    resolved.enabled = true;
    resolved.matched = false;
    return resolved;
}

} // namespace atomwall
