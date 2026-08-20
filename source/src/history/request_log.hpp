#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace atomwall {

struct RequestEvent {
    std::uint64_t seq = 0;
    std::chrono::system_clock::time_point timestamp;
    std::string client_ip;
    std::string country;      // "unknown" until a GeoIP source is wired in
    std::string isp;          // "unknown" until a GeoIP source is wired in
    std::string user_agent;
    std::string method;
    std::string path;
    std::string domain; // Host header (HTTP) / SNI-matched domain (HTTPS), empty if absent
    std::string listener;     // "http" or "https"
    bool blocked = false;
    std::string block_reason; // check name + reason, empty if allowed
    std::uint64_t bytes_transferred = 0; // request + response bytes, for the traffic graph
    int status_code = 0; // HTTP status actually sent to the client
};

// In-memory ring buffer of recent requests, thread-safe for concurrent record()
// calls from any connection-handling thread. The ring buffer itself is not
// persisted (resets on restart, see CLAUDE.md Open decisions) — but when
// `csv_path` is non-empty, every recorded event is also appended to that CSV
// file so history survives a restart. Writes are batched (kCsvBatchSize
// events per flush) and handed off to a dedicated background thread, never
// written on the caller's thread: record() is called on the request hot path
// (see listener/http_session.hpp), and disk I/O there would stall every other
// connection the calling io_context thread is servicing (see CLAUDE.md
// Performance posture).
class RequestLog {
public:
    explicit RequestLog(std::size_t capacity = 5000, std::string csv_path = {});
    ~RequestLog();

    RequestLog(const RequestLog&) = delete;
    RequestLog& operator=(const RequestLog&) = delete;

    void record(RequestEvent event);

    // Most recent `limit` events, oldest first.
    std::vector<RequestEvent> recent(std::size_t limit) const;

    // Events recorded after `since_seq`, oldest first, capped to `limit`.
    // Used by the SSE stream to poll for what's new since its last read.
    std::vector<RequestEvent> events_since(std::uint64_t since_seq, std::size_t limit = 500) const;

    std::uint64_t latest_seq() const;

private:
    void writer_loop();

    mutable std::mutex mutex_;
    std::deque<RequestEvent> buffer_;
    std::size_t capacity_;
    std::uint64_t next_seq_ = 1;

    // Everything below is guarded by mutex_ as well (reused rather than a
    // second mutex, so record()'s single lock/unlock covers both the ring
    // buffer and the CSV batching, and the writer thread's condition_variable
    // has one unambiguous mutex to pair with).
    static constexpr std::size_t kCsvBatchSize = 100;
    const std::string csv_path_; // empty = persistence disabled
    std::vector<RequestEvent> pending_batch_;
    std::deque<std::vector<RequestEvent>> write_queue_;
    bool stop_ = false;
    std::condition_variable cv_;
    std::thread writer_thread_; // joinable only when csv_path_ is non-empty
};

} // namespace atomwall
