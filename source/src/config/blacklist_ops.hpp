#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include "config/runtime_config.hpp"

namespace atomwall {

enum class BlacklistCategory {
    Ips,
    Routes,
    Countries,
    Isps,
    UserAgents,
    Referrers,
    BodyPatterns,
    FakeRoutes
};

std::optional<BlacklistCategory> parse_blacklist_category(std::string_view name);
std::string_view blacklist_category_name(BlacklistCategory category);

// Throws std::invalid_argument if `value` is invalid for `category` (currently
// only "ips" validates — must be a parseable IP or CIDR). No-op if already present.
// `created_by` is the admin username making the change, empty if unknown (e.g.
// entries added before this field existed, or restored from an old backup).
// `source` is "manual" for a single add or "list" for a bulk .list/URL import
// (see import_blacklist_entries, which always passes "list").
void add_blacklist_entry(RuntimeConfig& config, BlacklistCategory category, const std::string& value,
                          const std::string& created_by = "", const std::string& source = "manual");

// No-op if `value` isn't present.
void remove_blacklist_entry(RuntimeConfig& config, BlacklistCategory category, const std::string& value);

// Empties every entry in `category` (for Ips, both ip_exact and ip_cidrs).
// Only touches the permanent YAML-backed list — temporary/score-triggered IP
// blocks live in IpBlockTracker and are unaffected, see CLAUDE.md.
void clear_blacklist_category(RuntimeConfig& config, BlacklistCategory category);

struct ImportResult {
    std::size_t added = 0;
    std::size_t skipped = 0;
};

// Bulk-add from a `.list`-style upload: one entry per line, blank lines and
// lines starting with '#' ignored, surrounding whitespace and CRLF trimmed.
// Unlike add_blacklist_entry, a line invalid for `category` (e.g. a malformed
// IP) is counted in `skipped` rather than throwing — one bad line shouldn't
// abort an otherwise-good import.
ImportResult import_blacklist_entries(RuntimeConfig& config, BlacklistCategory category,
                                       std::string_view text, const std::string& created_by = "");

// --- whitelist: see WhitelistConfig in runtime_config.hpp. Not a
// BlacklistCategory — semantically the opposite, so it gets its own small
// surface rather than overloading "blacklist category" naming. ---

// Throws std::invalid_argument if `value` isn't a parseable IP or CIDR. No-op
// if already present.
void add_whitelist_entry(RuntimeConfig& config, const std::string& value,
                          const std::string& created_by = "", const std::string& source = "manual");

// No-op if `value` isn't present.
void remove_whitelist_entry(RuntimeConfig& config, const std::string& value);

void clear_whitelist(RuntimeConfig& config);

// Same line-format rules as import_blacklist_entries.
ImportResult import_whitelist_entries(RuntimeConfig& config, std::string_view text,
                                       const std::string& created_by = "");

} // namespace atomwall
