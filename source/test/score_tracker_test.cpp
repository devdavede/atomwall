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
