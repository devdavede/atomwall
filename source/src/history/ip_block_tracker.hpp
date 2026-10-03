#pragma once

#include <boost/asio/ip/address.hpp>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "config/runtime_config.hpp"

namespace atomwall {

struct TemporaryIpBlock {
    std::string text; // "203.0.113.7" or "198.51.100.0/24"
    bool is_cidr = false;
    boost::asio::ip::address address; // exact IP, or CIDR base address
    unsigned prefix_len = 0;          // valid when is_cidr
    std::string source;               // "manual" or "score"
    int score_at_block = 0;           // meaningful only when source == "score"
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
};

// Temporary IP/CIDR blocks only — permanent blocks live in the persisted YAML
// blacklist (BlacklistConfig::ip_exact/ip_cidrs). In-memory, lost on restart,
// same as RequestLog. Covers two sources: an admin manually blocking with a
// duration, and the score system auto-banning on threshold.
//
// is_blocked() is the very first gate every request passes through, under a
// single mutex, and a wave of auto-bans (an attacker rotating source IPs) is
// exactly when this holds the most entries — so lookups of exact IPs are a
// hash probe, not a scan, and only the (few, admin-issued) CIDR entries are
// walked linearly. Expired entries are dropped on insert (throttled) as well
// as by list_active(); previously only the latter, i.e. only when an admin
// happened to open the block list, so a ban wave would accumulate forever.
class IpBlockTracker {
public:
    explicit IpBlockTracker(std::chrono::milliseconds prune_interval = std::chrono::minutes(1))
        : prune_interval_(prune_interval) {}

    void add(TemporaryIpBlock block);

    bool is_blocked(const boost::asio::ip::address& ip) const;

    // Prunes expired entries, returns what's left (newest first).
    std::vector<TemporaryIpBlock> list_active();

    // Removes an exact IP (matched by address, so any spelling of it works) or
    // a CIDR entry (matched by its text). Returns true if something was removed.
    bool remove(const std::string& text);

    std::size_t size() const;

private:
    struct CidrEntry {
        TemporaryIpBlock block;
        CidrRange range; // built once at add() so is_blocked() doesn't rebuild it per request
    };

    void prune_expired_locked(std::chrono::system_clock::time_point now);

    const std::chrono::milliseconds prune_interval_;
    mutable std::mutex mutex_;
    std::unordered_map<boost::asio::ip::address, TemporaryIpBlock> exact_;
    std::vector<CidrEntry> cidrs_;
    std::chrono::system_clock::time_point last_prune_{};
};

} // namespace atomwall
