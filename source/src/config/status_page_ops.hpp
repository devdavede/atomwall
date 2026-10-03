#pragma once

#include <string>

#include "config/runtime_config.hpp"

namespace atomwall {

// Adds a status-page override for `code`. Throws std::invalid_argument if
// `code` isn't a valid HTTP status code (100-599) or one is already
// configured for it — use update_status_page to change an existing entry.
void add_status_page(RuntimeConfig& config, int code, const std::string& html);

// Replaces the HTML for the existing entry matching `code`. Throws
// std::invalid_argument if no such entry is configured.
void update_status_page(RuntimeConfig& config, int code, const std::string& html);

// Throws std::invalid_argument if no entry is configured for `code`.
void remove_status_page(RuntimeConfig& config, int code);

} // namespace atomwall
