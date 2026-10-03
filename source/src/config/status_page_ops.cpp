#include "config/status_page_ops.hpp"

#include <algorithm>
#include <stdexcept>

namespace atomwall {

namespace {

auto find_status_page(std::vector<StatusPageEntry>& pages, int code) {
    return std::find_if(pages.begin(), pages.end(),
                         [&](const StatusPageEntry& entry) { return entry.code == code; });
}

void validate_code(int code) {
    if (code < 100 || code > 599) {
        throw std::invalid_argument("status code must be between 100 and 599");
    }
}

} // namespace

void add_status_page(RuntimeConfig& config, int code, const std::string& html) {
    validate_code(code);
    if (find_status_page(config.pages.status_pages, code) != config.pages.status_pages.end()) {
        throw std::invalid_argument("a page override for status " + std::to_string(code) +
                                     " already exists");
    }
    config.pages.status_pages.push_back(StatusPageEntry{code, html, std::chrono::system_clock::now()});
}

void update_status_page(RuntimeConfig& config, int code, const std::string& html) {
    auto it = find_status_page(config.pages.status_pages, code);
    if (it == config.pages.status_pages.end()) {
        throw std::invalid_argument("no page override configured for status " + std::to_string(code));
    }
    it->html = html;
}

void remove_status_page(RuntimeConfig& config, int code) {
    auto it = find_status_page(config.pages.status_pages, code);
    if (it == config.pages.status_pages.end()) {
        throw std::invalid_argument("no page override configured for status " + std::to_string(code));
    }
    config.pages.status_pages.erase(it);
}

} // namespace atomwall
