#include <limits>
#include <catch2/catch_test_macros.hpp>

#include "history/score_tracker.hpp"

using namespace atomwall;

TEST_CASE("ScoreTracker starts at zero for an unseen IP", "[score_tracker]") {
    ScoreTracker tracker;
    CHECK(tracker.current("203.0.113.7") == 0);
}

TEST_CASE("ScoreTracker accumulates points across calls", "[score_tracker]") {
    ScoreTracker tracker;
    CHECK(tracker.add_points("203.0.113.7", 50) == 50);
    CHECK(tracker.add_points("203.0.113.7", 30) == 80);
    CHECK(tracker.current("203.0.113.7") == 80);
}

TEST_CASE("ScoreTracker tracks IPs independently", "[score_tracker]") {
    ScoreTracker tracker;
    tracker.add_points("203.0.113.7", 50);
    tracker.add_points("203.0.113.8", 10);
    CHECK(tracker.current("203.0.113.7") == 50);
    CHECK(tracker.current("203.0.113.8") == 10);
}

TEST_CASE("ScoreTracker::reset zeroes an IP's score", "[score_tracker]") {
    ScoreTracker tracker;
    tracker.add_points("203.0.113.7", 100);
    tracker.reset("203.0.113.7");
    CHECK(tracker.current("203.0.113.7") == 0);
}

TEST_CASE("ScoreTracker saturates at INT_MAX instead of wrapping negative", "[score_tracker]") {
    ScoreTracker tracker;
    constexpr int kMax = std::numeric_limits<int>::max();
    CHECK(tracker.add_points("203.0.113.7", kMax - 1) == kMax - 1);
    CHECK(tracker.add_points("203.0.113.7", 5) == kMax);
    CHECK(tracker.add_points("203.0.113.7", kMax) == kMax);
    CHECK(tracker.current("203.0.113.7") == kMax);
}

TEST_CASE("ScoreTracker saturates at INT_MIN for large negative points", "[score_tracker]") {
    ScoreTracker tracker;
    constexpr int kMin = std::numeric_limits<int>::min();
    CHECK(tracker.add_points("203.0.113.7", kMin + 1) == kMin + 1);
    CHECK(tracker.add_points("203.0.113.7", -5) == kMin);
}

TEST_CASE("ScoreTracker stays bounded, dropping the oldest-tracked IP first", "[score_tracker]") {
    ScoreTracker tracker(3);
    tracker.add_points("198.51.100.1", 10);
    tracker.add_points("198.51.100.2", 20);
    tracker.add_points("198.51.100.3", 30);
    tracker.add_points("198.51.100.4", 40); // evicts .1

    CHECK(tracker.tracked_ips() == 3);
    CHECK(tracker.current("198.51.100.1") == 0);
    CHECK(tracker.current("198.51.100.2") == 20);
    CHECK(tracker.current("198.51.100.4") == 40);
}

TEST_CASE("ScoreTracker keeps accumulating for an IP that's still tracked", "[score_tracker]") {
    ScoreTracker tracker(3);
    tracker.add_points("198.51.100.1", 10);
    tracker.add_points("198.51.100.2", 20);
    tracker.add_points("198.51.100.1", 5); // existing entry: not re-queued, not refreshed
    CHECK(tracker.current("198.51.100.1") == 15);
    CHECK(tracker.tracked_ips() == 2);
}

TEST_CASE("ScoreTracker's eviction doesn't drop an IP that was reset and re-added", "[score_tracker]") {
    ScoreTracker tracker(3);
    tracker.add_points("198.51.100.1", 10);
    tracker.reset("198.51.100.1");                // leaves a stale queue item behind
    tracker.add_points("198.51.100.1", 7);        // fresh entry, newer than the stale item
    tracker.add_points("198.51.100.2", 1);
    tracker.add_points("198.51.100.3", 1);        // queue is now 4 long: pops the stale .1 item

    CHECK(tracker.current("198.51.100.1") == 7);  // must survive its own stale queue item
    CHECK(tracker.tracked_ips() == 3);
}

TEST_CASE("ScoreTracker with a tiny cap still tracks the newest IP", "[score_tracker]") {
    ScoreTracker tracker(0); // clamped to 1
    CHECK(tracker.add_points("198.51.100.1", 10) == 10);
    CHECK(tracker.add_points("198.51.100.2", 20) == 20);
    CHECK(tracker.tracked_ips() == 1);
    CHECK(tracker.current("198.51.100.1") == 0);
}
