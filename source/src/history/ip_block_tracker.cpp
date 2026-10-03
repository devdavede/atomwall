#include "history/ip_block_tracker.hpp"

#include <algorithm>

#include "pipeline/net_utils.hpp"

namespace atomwall {

void IpBlockTracker::add(TemporaryIpBlock block) {
    const auto now = std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    if (now - last_prune_ >= prune_interval_) {
        prune_expired_locked(now);
        last_prune_ = now;
    }

    if (!block.is_cidr) {
        exact_[block.address] = std::move(block);
        return;
    }
    std::erase_if(cidrs_, [&](const CidrEntry& e) { return e.block.text == block.text; });
    CidrRange range{block.address, block.prefix_len, block.text};
    cidrs_.push_back(CidrEntry{std::move(block), std::move(range)});
}

bool IpBlockTracker::is_blocked(const boost::asio::ip::address& ip) const {
    const auto now = std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    if (auto it = exact_.find(ip); it != exact_.end() && it->second.expires_at > now) {
        return true;
    }
    for (const auto& entry : cidrs_) {
        if (entry.block.expires_at > now && address_in_cidr(ip, entry.range)) {
            return true;
        }
    }
    return false;
}

std::vector<TemporaryIpBlock> IpBlockTracker::list_active() {
    const auto now = std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    prune_expired_locked(now);
    last_prune_ = now;

    std::vector<TemporaryIpBlock> result;
    result.reserve(exact_.size() + cidrs_.size());
    for (const auto& [address, block] : exact_) {
        result.push_back(block);
    }
    for (const auto& entry : cidrs_) {
        result.push_back(entry.block);
    }
    std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
        return a.created_at != b.created_at ? a.created_at > b.created_at : a.text < b.text;
    });
    return result;
}

bool IpBlockTracker::remove(const std::string& text) {
    std::lock_guard lock(mutex_);
    boost::system::error_code ec;
    const auto address = boost::asio::ip::make_address(text, ec);
    if (!ec) {
        return exact_.erase(address) > 0;
    }
    return std::erase_if(cidrs_, [&](const CidrEntry& e) { return e.block.text == text; }) > 0;
}

std::size_t IpBlockTracker::size() const {
    std::lock_guard lock(mutex_);
    return exact_.size() + cidrs_.size();
}

void IpBlockTracker::prune_expired_locked(std::chrono::system_clock::time_point now) {
    std::erase_if(exact_, [&](const auto& entry) { return entry.second.expires_at <= now; });
    std::erase_if(cidrs_, [&](const CidrEntry& e) { return e.block.expires_at <= now; });
}

} // namespace atomwall
