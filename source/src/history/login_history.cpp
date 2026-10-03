#include "history/login_history.hpp"

#include <algorithm>

namespace atomwall {

LoginHistory::LoginHistory(std::size_t capacity) : capacity_(capacity) {}

void LoginHistory::record(LoginEvent event) {
    std::lock_guard lock(mutex_);
    event.seq = next_seq_++;
    buffer_.push_back(std::move(event));
    while (buffer_.size() > capacity_) {
        buffer_.pop_front();
    }
}

std::vector<LoginEvent> LoginHistory::recent(std::size_t limit) const {
    std::lock_guard lock(mutex_);
    const std::size_t count = std::min(limit, buffer_.size());
    return std::vector<LoginEvent>(buffer_.end() - static_cast<std::ptrdiff_t>(count), buffer_.end());
}

} // namespace atomwall
