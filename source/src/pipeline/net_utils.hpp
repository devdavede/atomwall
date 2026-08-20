#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "config/runtime_config.hpp"

namespace atomwall {

std::optional<CidrRange> parse_cidr(std::string_view text);

bool address_in_cidr(const boost::asio::ip::address& address, const CidrRange& range);

bool icontains(std::string_view haystack, std::string_view needle);

// Case-insensitive prefix match, same casing rule as icontains — used where
// substring matching would be too loose (e.g. robots.txt Disallow semantics).
bool istarts_with(std::string_view haystack, std::string_view prefix);

// Case-insensitive exact match — used for domain comparison (Host header /
// TLS SNI name against SiteConfig::domain), where even prefix/substring
// matching would let a request spoof a match (e.g. "example.com.evil.com"
// must never match "example.com").
bool iequals(std::string_view a, std::string_view b);

// ASCII-lowercases `text` — used to normalize SiteConfig::domain at every
// entry point (YAML load, admin API) so later exact-string-key lookups (e.g.
// TlsSiteContexts' domain -> ssl::context map) don't need their own
// case-insensitive comparison.
std::string to_lower(std::string_view text);

} // namespace atomwall
