#pragma once

#include <optional>
#include <string>

#include "config/runtime_config.hpp"

namespace atomwall {

// Adds a new site. Throws std::invalid_argument if `site.domain` is empty,
// contains whitespace or a '/' (a bare hostname is expected, not a URL), or
// already matches a configured site (case-insensitive) — domains must be
// unique since they're the sole key used to pick an upstream/cert at request
// time (see config/site_lookup.hpp). `site.domain` is lowercased before
// storing, matching yaml_codec's normalization on load.
void add_site(RuntimeConfig& config, SiteConfig site);

// Optional fields left unset (nullopt) are left unchanged.
struct SiteUpdate {
    std::optional<bool> enabled;
    std::optional<std::string> cert_file;
    std::optional<std::string> key_file;
    std::optional<std::string> upstream_host;
    std::optional<unsigned short> upstream_port;
};

// Applies `update` to the site matching `domain` (case-insensitive). Throws
// std::invalid_argument if no such site is configured.
void update_site(RuntimeConfig& config, const std::string& domain, const SiteUpdate& update);

// Throws std::invalid_argument if no such site is configured.
void remove_site(RuntimeConfig& config, const std::string& domain);

} // namespace atomwall
