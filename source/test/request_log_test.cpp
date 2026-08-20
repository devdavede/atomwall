#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "history/request_log.hpp"

using namespace atomwall;

namespace {

// Unique-per-test-run path under the build directory's temp dir, cleaned up
// at the end of each CSV test — RequestLog's writer thread owns the file
// while the log is alive, so removal must happen after the log is destroyed.
std::filesystem::path temp_csv_path(std::string_view name) {
    static int counter = 0;
    return std::filesystem::temp_directory_path() /
           ("atomwall_request_log_test_" + std::string(name) + "_" + std::to_string(counter++) + ".csv");
}

std::vector<std::string> read_lines(const std::filesystem::path& path) {
    std::ifstream in(path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    return lines;
}

RequestEvent make_event(std::string ip) {
    RequestEvent event;
    event.timestamp = std::chrono::system_clock::now();
    event.client_ip = std::move(ip);
    event.country = "unknown";
    event.isp = "unknown";
    event.user_agent = "test-agent";
    event.method = "GET";
    event.path = "/";
    event.listener = "http";
    return event;
}

} // namespace

TEST_CASE("RequestLog assigns increasing sequence numbers", "[request_log]") {
    RequestLog log(10);
    log.record(make_event("1.1.1.1"));
    log.record(make_event("2.2.2.2"));

    auto events = log.recent(10);
    REQUIRE(events.size() == 2);
    CHECK(events[0].seq == 1);
    CHECK(events[1].seq == 2);
    CHECK(log.latest_seq() == 2);
}

TEST_CASE("RequestLog recent returns the newest N, oldest first", "[request_log]") {
    RequestLog log(10);
    for (int i = 0; i < 5; ++i) {
        log.record(make_event(std::to_string(i)));
    }

    auto events = log.recent(2);
    REQUIRE(events.size() == 2);
    CHECK(events[0].client_ip == "3");
    CHECK(events[1].client_ip == "4");
}

TEST_CASE("RequestLog evicts the oldest entry once over capacity", "[request_log]") {
    RequestLog log(3);
    for (int i = 0; i < 5; ++i) {
        log.record(make_event(std::to_string(i)));
    }

    auto events = log.recent(10);
    REQUIRE(events.size() == 3);
    CHECK(events[0].client_ip == "2");
    CHECK(events[1].client_ip == "3");
    CHECK(events[2].client_ip == "4");
}

TEST_CASE("RequestLog events_since returns only newer entries", "[request_log]") {
    RequestLog log(10);
    log.record(make_event("a"));
    log.record(make_event("b"));
    const auto since = log.latest_seq();
    log.record(make_event("c"));
    log.record(make_event("d"));

    auto events = log.events_since(since);
    REQUIRE(events.size() == 2);
    CHECK(events[0].client_ip == "c");
    CHECK(events[1].client_ip == "d");
}

TEST_CASE("RequestLog events_since with the latest seq returns nothing", "[request_log]") {
    RequestLog log(10);
    log.record(make_event("a"));
    CHECK(log.events_since(log.latest_seq()).empty());
}

TEST_CASE("RequestLog events_since respects the limit", "[request_log]") {
    RequestLog log(10);
    for (int i = 0; i < 5; ++i) {
        log.record(make_event(std::to_string(i)));
    }
    auto events = log.events_since(0, 2);
    REQUIRE(events.size() == 2);
    CHECK(events[0].client_ip == "0");
    CHECK(events[1].client_ip == "1");
}

TEST_CASE("RequestLog flushes a full 100-event batch to its CSV file", "[request_log]") {
    const auto path = temp_csv_path("full_batch");
    std::filesystem::remove(path);
    {
        RequestLog log(5000, path.string());
        for (int i = 0; i < 100; ++i) {
            log.record(make_event(std::to_string(i)));
        }
        // Destructor joins the writer thread, guaranteeing the flush below
        // observes everything written before this scope ends.
    }
    auto lines = read_lines(path);
    REQUIRE(lines.size() == 101); // header + 100 rows
    CHECK(lines[0] == "seq,timestamp,client_ip,country,isp,user_agent,method,path,domain,listener,"
                       "blocked,block_reason,bytes_transferred,status_code");
    CHECK(lines[1].starts_with("1,"));
    CHECK(lines[1].find(",0,") != std::string::npos); // client_ip of the first recorded event
    std::filesystem::remove(path);
}

TEST_CASE("RequestLog flushes a partial (<100) batch to CSV on destruction", "[request_log]") {
    const auto path = temp_csv_path("partial_batch");
    std::filesystem::remove(path);
    {
        RequestLog log(5000, path.string());
        log.record(make_event("a"));
        log.record(make_event("b"));
        log.record(make_event("c"));
    }
    auto lines = read_lines(path);
    REQUIRE(lines.size() == 4); // header + 3 rows
    std::filesystem::remove(path);
}

TEST_CASE("RequestLog CSV persistence appends across instances instead of overwriting", "[request_log]") {
    const auto path = temp_csv_path("append_across_instances");
    std::filesystem::remove(path);
    {
        RequestLog log(5000, path.string());
        log.record(make_event("first-run"));
    }
    {
        RequestLog log(5000, path.string());
        log.record(make_event("second-run"));
    }
    auto lines = read_lines(path);
    REQUIRE(lines.size() == 3); // one header, never rewritten, + one row per run
    CHECK(lines[0].starts_with("seq,timestamp"));
    std::filesystem::remove(path);
}

TEST_CASE("RequestLog does not touch disk when csv_path is empty", "[request_log]") {
    const auto path = temp_csv_path("disabled");
    std::filesystem::remove(path);
    {
        RequestLog log(10); // default csv_path = "" (disabled)
        log.record(make_event("a"));
    }
    CHECK_FALSE(std::filesystem::exists(path));
}
