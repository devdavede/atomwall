#include <catch2/catch_test_macros.hpp>

#include "history/request_rate_tracker.hpp"

using namespace atomwall;
using namespace std::chrono_literals;

TEST_CASE("RequestRateTracker counts requests within the window", "[request_rate_tracker]") {
    RequestRateTracker tracker;
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(tracker.record("203.0.113.7", t0, 10s) == 1);
    CHECK(tracker.record("203.0.113.7", t0 + 1s, 10s) == 2);
    CHECK(tracker.record("203.0.113.7", t0 + 2s, 10s) == 3);
}

TEST_CASE("RequestRateTracker drops timestamps that fall outside the window", "[request_rate_tracker]") {
    RequestRateTracker tracker;
    const auto t0 = std::chrono::steady_clock::now();
    tracker.record("203.0.113.7", t0, 10s);
    tracker.record("203.0.113.7", t0 + 1s, 10s);
    // t0 and t0+1s are now more than 10s in the past relative to t0+12s.
    CHECK(tracker.record("203.0.113.7", t0 + 12s, 10s) == 1);
}

TEST_CASE("RequestRateTracker tracks IPs independently", "[request_rate_tracker]") {
    RequestRateTracker tracker;
    const auto t0 = std::chrono::steady_clock::now();
    tracker.record("203.0.113.7", t0, 10s);
    tracker.record("203.0.113.7", t0, 10s);
    CHECK(tracker.record("203.0.113.8", t0, 10s) == 1);
}
