#include "config/blacklist_ops.hpp"

#include <algorithm>
#include <boost/asio/ip/address.hpp>
#include <cctype>
#include <stdexcept>

#include "pipeline/net_utils.hpp"

namespace atomwall {

std::optional<BlacklistCategory> parse_blacklist_category(std::string_view name) {
    if (name == "ips") return BlacklistCategory::Ips;
    if (name == "routes") return BlacklistCategory::Routes;
    if (name == "countries") return BlacklistCategory::Countries;
    if (name == "isps") return BlacklistCategory::Isps;
    if (name == "user_agents") return BlacklistCategory::UserAgents;
    if (name == "referrers") return BlacklistCategory::Referrers;
    if (name == "body_patterns") return BlacklistCategory::BodyPatterns;
    if (name == "fake_routes") return BlacklistCategory::FakeRoutes;
    return std::nullopt;
}

std::string_view blacklist_category_name(BlacklistCategory category) {
    switch (category) {
        case BlacklistCategory::Ips: return "ips";
        case BlacklistCategory::Routes: return "routes";
        case BlacklistCategory::Countries: return "countries";
        case BlacklistCategory::Isps: return "isps";
        case BlacklistCategory::UserAgents: return "user_agents";
        case BlacklistCategory::Referrers: return "referrers";
        case BlacklistCategory::BodyPatterns: return "body_patterns";
        case BlacklistCategory::FakeRoutes: return "fake_routes";
    }
    return "";
}

namespace {

// Shared by the IP blacklist and the whitelist (see whitelist_ops below) —
// both are just "a set of exact IPs + CIDR ranges", differing only in which
// vectors they target and what a match means to the pipeline.
void add_ip_to(std::vector<BlacklistEntry>& exact_list, std::vector<CidrRange>& cidr_list,
               const std::string& value, const std::string& created_by, const std::string& source) {
    if (value.find('/') != std::string::npos) {
        auto range = parse_cidr(value);
        if (!range) {
            throw std::invalid_argument("not a valid CIDR range: " + value);
        }
        range->source = source;
        if (std::none_of(cidr_list.begin(), cidr_list.end(),
                          [&](const auto& r) { return r.text == range->text; })) {
            cidr_list.push_back(*range);
        }
        return;
    }

    boost::system::error_code ec;
    boost::asio::ip::make_address(value, ec);
    if (ec) {
        throw std::invalid_argument("not a valid IP address: " + value);
    }
    if (std::none_of(exact_list.begin(), exact_list.end(),
                      [&](const auto& e) { return e.value == value; })) {
        exact_list.push_back(BlacklistEntry{value, std::chrono::system_clock::now(), created_by, source});
    }
}

void remove_ip_from(std::vector<BlacklistEntry>& exact_list, std::vector<CidrRange>& cidr_list,
                     const std::string& value) {
    exact_list.erase(std::remove_if(exact_list.begin(), exact_list.end(),
                                     [&](const auto& e) { return e.value == value; }),
                      exact_list.end());
    cidr_list.erase(std::remove_if(cidr_list.begin(), cidr_list.end(),
                                    [&](const auto& r) { return r.text == value; }),
                     cidr_list.end());
}

void add_ip(RuntimeConfig& config, const std::string& value, const std::string& created_by,
            const std::string& source) {
    add_ip_to(config.blacklist.ip_exact, config.blacklist.ip_cidrs, value, created_by, source);
}

void remove_ip(RuntimeConfig& config, const std::string& value) {
    remove_ip_from(config.blacklist.ip_exact, config.blacklist.ip_cidrs, value);
}

// Shared by import_blacklist_entries and import_whitelist_entries: splits
// `text` into trimmed, non-empty, non-comment lines and calls `on_line` for
// each. A line invalid for the caller's own add-one-entry function is its
// problem to catch, not this loop's.
template <class OnLine>
void for_each_list_line(std::string_view text, OnLine&& on_line) {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        auto newline = text.find('\n', pos);
        auto line = newline == std::string_view::npos ? text.substr(pos) : text.substr(pos, newline - pos);
        pos = newline == std::string_view::npos ? text.size() + 1 : newline + 1;

        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front()))) {
            line.remove_prefix(1);
        }
        while (!line.empty() && std::isspace(static_cast<unsigned char>(line.back()))) {
            line.remove_suffix(1);
        }
        if (line.empty() || line.front() == '#') {
            continue;
        }
        on_line(line);
    }
}

std::vector<BlacklistEntry>& list_for(RuntimeConfig& config, BlacklistCategory category) {
    switch (category) {
        case BlacklistCategory::Routes: return config.blacklist.routes;
        case BlacklistCategory::Countries: return config.blacklist.countries;
        case BlacklistCategory::Isps: return config.blacklist.isps;
        case BlacklistCategory::UserAgents: return config.blacklist.user_agents;
        case BlacklistCategory::Referrers: return config.blacklist.referrers;
        case BlacklistCategory::BodyPatterns: return config.blacklist.body_patterns;
        case BlacklistCategory::FakeRoutes: return config.blacklist.fake_routes;
        case BlacklistCategory::Ips: break;
    }
    throw std::logic_error("list_for called with Ips category");
}

} // namespace

void add_blacklist_entry(RuntimeConfig& config, BlacklistCategory category, const std::string& value,
                          const std::string& created_by, const std::string& source) {
    if (value.empty()) {
        throw std::invalid_argument("value must not be empty");
    }
    if (category == BlacklistCategory::Ips) {
        add_ip(config, value, created_by, source);
        return;
    }
    // Fake routes are matched by prefix against the request path and get
    // written verbatim into robots.txt's Disallow list (see
    // listener/http_session.hpp) — both only make sense for an actual path.
    if (category == BlacklistCategory::FakeRoutes && value.front() != '/') {
        throw std::invalid_argument("fake route must start with '/'");
    }
    auto& list = list_for(config, category);
    if (std::none_of(list.begin(), list.end(), [&](const auto& e) { return e.value == value; })) {
        list.push_back(BlacklistEntry{value, std::chrono::system_clock::now(), created_by, source});
    }
}

void remove_blacklist_entry(RuntimeConfig& config, BlacklistCategory category, const std::string& value) {
    if (category == BlacklistCategory::Ips) {
        remove_ip(config, value);
        return;
    }
    auto& list = list_for(config, category);
    list.erase(std::remove_if(list.begin(), list.end(),
                               [&](const auto& e) { return e.value == value; }),
               list.end());
}

void clear_blacklist_category(RuntimeConfig& config, BlacklistCategory category) {
    if (category == BlacklistCategory::Ips) {
        config.blacklist.ip_exact.clear();
        config.blacklist.ip_cidrs.clear();
        return;
    }
    list_for(config, category).clear();
}

ImportResult import_blacklist_entries(RuntimeConfig& config, BlacklistCategory category,
                                       std::string_view text, const std::string& created_by) {
    ImportResult result;
    for_each_list_line(text, [&](std::string_view line) {
        try {
            add_blacklist_entry(config, category, std::string(line), created_by, "list");
            ++result.added;
        } catch (const std::invalid_argument&) {
            ++result.skipped;
        }
    });
    return result;
}

// --- whitelist: exact IPs + CIDR ranges that bypass every blocking check,
// see WhitelistConfig's doc comment in runtime_config.hpp. Mirrors the "ips"
// blacklist category's shape (same add_ip_to/remove_ip_from helpers) but
// deliberately isn't wired into BlacklistCategory — it isn't a blacklist,
// and giving it its own small surface keeps that distinction obvious at
// every call site instead of relying on category-name vigilance. ---

void add_whitelist_entry(RuntimeConfig& config, const std::string& value, const std::string& created_by,
                          const std::string& source) {
    if (value.empty()) {
        throw std::invalid_argument("value must not be empty");
    }
    add_ip_to(config.whitelist.ip_exact, config.whitelist.ip_cidrs, value, created_by, source);
}

void remove_whitelist_entry(RuntimeConfig& config, const std::string& value) {
    remove_ip_from(config.whitelist.ip_exact, config.whitelist.ip_cidrs, value);
}

void clear_whitelist(RuntimeConfig& config) {
    config.whitelist.ip_exact.clear();
    config.whitelist.ip_cidrs.clear();
}

ImportResult import_whitelist_entries(RuntimeConfig& config, std::string_view text,
                                       const std::string& created_by) {
    ImportResult result;
    for_each_list_line(text, [&](std::string_view line) {
        try {
            add_whitelist_entry(config, std::string(line), created_by, "list");
            ++result.added;
        } catch (const std::invalid_argument&) {
            ++result.skipped;
        }
    });
    return result;
}

} // namespace atomwall
