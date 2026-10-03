#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <thread>

#include "auth/pending_mfa_store.hpp"
#include "auth/session_store.hpp"

using namespace atomwall;

TEST_CASE("SessionStore::create sweeps expired sessions", "[session_store]") {
    SessionStore store;
    for (int i = 0; i < 5; ++i) {
        store.create("alice", false, std::chrono::hours(0));
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    // Each create swept the already-expired one before it, so at most the
    // last (itself now expired) entry remains rather than all five.
    CHECK(store.size() == 1);

    const auto live_token = store.create("bob");
    CHECK(store.size() == 1);
    REQUIRE(store.validate(live_token).has_value());
    CHECK(store.validate(live_token)->username == "bob");
}

TEST_CASE("SessionStore keeps unexpired sessions valid across later creates", "[session_store]") {
    SessionStore store;
    const auto first = store.create("alice");
    store.create("bob");
    CHECK(store.size() == 2);
    CHECK(store.validate(first).has_value());
}

TEST_CASE("PendingMfaStore::create sweeps expired entries", "[pending_mfa_store]") {
    PendingMfaStore store;
    for (int i = 0; i < 5; ++i) {
        store.create("alice", std::chrono::minutes(0));
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    CHECK(store.size() == 1);

    const auto live_token = store.create("bob");
    CHECK(store.size() == 1);
    REQUIRE(store.validate(live_token).has_value());
    CHECK(*store.validate(live_token) == "bob");
}
