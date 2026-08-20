#include "history/ip_block_tracker.hpp"

#include <algorithm>

#include "pipeline/net_utils.hpp"

namespace atomwall {

void IpBlockTracker::add(TemporaryIpBlock block) {
    std::lock_guard lock(mutex_);
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                   [&](const auto& e) { return e.text == block.text; }),
                    entries_.end());
    entries_.push_back(std::move(block));
}

bool IpBlockTracker::is_blocked(const boost::asio::ip::address& ip) const {
    const auto now = std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.expires_at <= now) {
            continue;
        }
        if (entry.is_cidr) {
            CidrRange range{entry.address, entry.prefix_len, entry.text};
            if (address_in_cidr(ip, range)) {
                return true;
            }
        } else if (entry.address == ip) {
            return true;
        }
    }
    return false;
}

std::vector<TemporaryIpBlock> IpBlockTracker::list_active() {
    const auto now = std::chrono::system_clock::now();
    std::lock_guard lock(mutex_);
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                        [&](const auto& e) { return e.expires_at <= now; }),
        entries_.end());
    std::vector<TemporaryIpBlock> result(entries_.rbegin(), entries_.rend());
    return result;
}

bool IpBlockTracker::remove(const std::string& text) {
    std::lock_guard lock(mutex_);
    const auto before = entries_.size();
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                   [&](const auto& e) { return e.text == text; }),
                    entries_.end());
    return entries_.size() != before;
}

} // namespace atomwall
