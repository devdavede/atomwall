#pragma once

#include <string>
#include <vector>

#include "config/runtime_config.hpp"

namespace atomwall {

// Builds the /robots.txt body atomwall serves when it needs to say anything
// beyond pure pass-through — either because there are fake_routes to
// advertise as Disallow entries, or because the admin has set custom_content
// (see RobotsTxtConfig). Deliberately *extends* `base` rather than ever
// discarding it: a Disallow line per fake_route is merged into the first
// "User-agent: *" group `base` already has, so a generic-crawler group that
// already exists keeps governing that crawler (most bots use the first
// matching group for a given user-agent and would silently ignore a second,
// later "User-agent: *" block — appending one instead of merging into the
// existing one would have looked fine but not actually worked). Only when
// `base` has no such group at all is a new one appended.
std::string build_robots_txt_body(const std::string& base, const std::vector<BlacklistEntry>& fake_routes);

} // namespace atomwall
