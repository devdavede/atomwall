#pragma once

#include <boost/asio/ip/address.hpp>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

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
class IpBlockTracker {
public:
    void add(TemporaryIpBlock block);

    bool is_blocked(const boost::asio::ip::address& ip) const;

    // Prunes expired entries, returns what's left (newest first).
    std::vector<TemporaryIpBlock> list_active();

    // Removes by exact text match. Returns true if something was removed.
    bool remove(const std::string& text);

private:
    mutable std::mutex mutex_;
    std::vector<TemporaryIpBlock> entries_;
};

} // namespace atomwall
