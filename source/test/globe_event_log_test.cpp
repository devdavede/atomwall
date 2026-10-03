#include <catch2/catch_test_macros.hpp>

#include "history/globe_event_log.hpp"

using namespace atomwall;

namespace {

GlobeArcEvent make_event(double lat, bool blocked) {
    GlobeArcEvent event;
    event.timestamp = std::chrono::system_clock::now();
    event.lat = lat;
    event.lon = 0;
    event.blocked = blocked;
    return event;
}

} // namespace

TEST_CASE("GlobeEventLog assigns increasing sequence numbers", "[globe_event_log]") {
    GlobeEventLog log(10);
    log.record(make_event(1.0, false));
    log.record(make_event(2.0, true));

    auto events = log.recent(10);
    REQUIRE(events.size() == 2);
    CHECK(events[0].seq == 1);
    CHECK(events[1].seq == 2);
    CHECK(log.latest_seq() == 2);
}

TEST_CASE("GlobeEventLog recent returns the newest N, oldest first", "[globe_event_log]") {
    GlobeEventLog log(10);
    for (int i = 0; i < 5; ++i) {
        log.record(make_event(i, false));
    }

    auto events = log.recent(2);
    REQUIRE(events.size() == 2);
    CHECK(events[0].lat == 3);
    CHECK(events[1].lat == 4);
}

TEST_CASE("GlobeEventLog evicts the oldest entry once over capacity", "[globe_event_log]") {
    GlobeEventLog log(3);
    for (int i = 0; i < 5; ++i) {
        log.record(make_event(i, false));
    }

    auto events = log.recent(10);
    REQUIRE(events.size() == 3);
    CHECK(events[0].lat == 2);
    CHECK(events[1].lat == 3);
    CHECK(events[2].lat == 4);
}

TEST_CASE("GlobeEventLog events_since returns only newer entries", "[globe_event_log]") {
    GlobeEventLog log(10);
    log.record(make_event(1, false));
    log.record(make_event(2, false));
    const auto since = log.latest_seq();
    log.record(make_event(3, true));
    log.record(make_event(4, true));

    auto events = log.events_since(since);
    REQUIRE(events.size() == 2);
    CHECK(events[0].lat == 3);
    CHECK(events[0].blocked == true);
    CHECK(events[1].lat == 4);
}

TEST_CASE("ServerLocationCache starts empty and reflects the last set() call",
          "[globe_event_log]") {
    ServerLocationCache cache;
    CHECK_FALSE(cache.get().has_value());

    cache.set(GeoLocation{50.1109, 8.6821, "DE"});
    auto location = cache.get();
    REQUIRE(location.has_value());
    CHECK(location->lat == 50.1109);
    CHECK(location->lon == 8.6821);
    CHECK(location->country == "DE");
}
