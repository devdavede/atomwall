#include "history/request_log.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>
#include <system_error>

namespace atomwall {

namespace {

// Duplicated from admin/json_view.cpp's to_iso8601 rather than shared: this
// file lives in history/, a layer below admin/, and admin/ already depends
// on history/ (for RequestEvent) — pulling the dependency the other way
// would invert that. Small and stable enough that duplication is cheaper
// than the layering violation.
std::string to_iso8601(std::chrono::system_clock::time_point tp) {
    using namespace std::chrono;
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;
    const std::time_t tt = system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_r(&tt, &tm);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                  static_cast<int>(ms.count()));
    return buf;
}

// Quotes only when needed (delimiter, quote, or newline present), doubling
// any embedded quotes — standard RFC 4180 CSV escaping. Attacker-controlled
// fields (path, user_agent, block_reason) go through this before hitting disk.
std::string csv_escape(const std::string& value) {
    if (value.find_first_of(",\"\n\r") == std::string::npos) {
        return value;
    }
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped += '"';
    for (char c : value) {
        if (c == '"') {
            escaped += '"';
        }
        escaped += c;
    }
    escaped += '"';
    return escaped;
}

constexpr std::string_view kCsvHeader =
    "seq,timestamp,client_ip,country,isp,user_agent,method,path,domain,listener,blocked,"
    "block_reason,bytes_transferred,status_code\n";

std::string to_csv_row(const RequestEvent& event) {
    std::string row;
    row += std::to_string(event.seq);
    row += ',';
    row += to_iso8601(event.timestamp);
    row += ',';
    row += csv_escape(event.client_ip);
    row += ',';
    row += csv_escape(event.country);
    row += ',';
    row += csv_escape(event.isp);
    row += ',';
    row += csv_escape(event.user_agent);
    row += ',';
    row += csv_escape(event.method);
    row += ',';
    row += csv_escape(event.path);
    row += ',';
    row += csv_escape(event.domain);
    row += ',';
    row += csv_escape(event.listener);
    row += ',';
    row += (event.blocked ? "true" : "false");
    row += ',';
    row += csv_escape(event.block_reason);
    row += ',';
    row += std::to_string(event.bytes_transferred);
    row += ',';
    row += std::to_string(event.status_code);
    row += '\n';
    return row;
}

} // namespace

RequestLog::RequestLog(std::size_t capacity, std::string csv_path)
    : capacity_(capacity), csv_path_(std::move(csv_path)) {
    if (!csv_path_.empty()) {
        writer_thread_ = std::thread(&RequestLog::writer_loop, this);
    }
}

RequestLog::~RequestLog() {
    if (!writer_thread_.joinable()) {
        return;
    }
    {
        std::lock_guard lock(mutex_);
        if (!pending_batch_.empty()) {
            write_queue_.push_back(std::move(pending_batch_));
            pending_batch_.clear();
        }
        stop_ = true;
    }
    cv_.notify_one();
    writer_thread_.join();
}

void RequestLog::record(RequestEvent event) {
    std::lock_guard lock(mutex_);
    event.seq = next_seq_++;

    if (!csv_path_.empty()) {
        pending_batch_.push_back(event);
        if (pending_batch_.size() >= kCsvBatchSize) {
            write_queue_.push_back(std::move(pending_batch_));
            pending_batch_.clear();
            cv_.notify_one();
        }
    }

    buffer_.push_back(std::move(event));
    while (buffer_.size() > capacity_) {
        buffer_.pop_front();
    }
}

std::vector<RequestEvent> RequestLog::recent(std::size_t limit) const {
    std::lock_guard lock(mutex_);
    const std::size_t count = std::min(limit, buffer_.size());
    return std::vector<RequestEvent>(buffer_.end() - static_cast<std::ptrdiff_t>(count), buffer_.end());
}

std::vector<RequestEvent> RequestLog::events_since(std::uint64_t since_seq, std::size_t limit) const {
    std::lock_guard lock(mutex_);
    std::vector<RequestEvent> result;
    for (const auto& event : buffer_) {
        if (event.seq > since_seq) {
            result.push_back(event);
            if (result.size() >= limit) {
                break;
            }
        }
    }
    return result;
}

std::uint64_t RequestLog::latest_seq() const {
    std::lock_guard lock(mutex_);
    return next_seq_ - 1;
}

void RequestLog::writer_loop() {
    std::filesystem::path path(csv_path_);
    if (const auto parent = path.parent_path(); !parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            spdlog::error("request_log: failed to create directory {} for CSV persistence: {}",
                          parent.string(), ec.message());
        }
    }

    std::error_code exists_ec;
    const bool write_header = !std::filesystem::exists(path, exists_ec) ||
                               std::filesystem::file_size(path, exists_ec) == 0;

    std::ofstream out(csv_path_, std::ios::app);
    if (!out) {
        spdlog::error("request_log: failed to open {} for writing — CSV persistence disabled for "
                      "this run",
                      csv_path_);
        return;
    }
    if (write_header) {
        out << kCsvHeader;
        out.flush();
    }

    for (;;) {
        std::deque<std::vector<RequestEvent>> batches;
        {
            std::unique_lock lock(mutex_);
            cv_.wait(lock, [this] { return stop_ || !write_queue_.empty(); });
            if (write_queue_.empty() && stop_) {
                break;
            }
            batches.swap(write_queue_);
        }
        for (const auto& batch : batches) {
            for (const auto& event : batch) {
                out << to_csv_row(event);
            }
        }
        out.flush();
    }
}

} // namespace atomwall
