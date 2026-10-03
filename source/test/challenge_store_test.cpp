#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "auth/webauthn/challenge_store.hpp"

using namespace atomwall;

namespace {
const std::vector<std::uint8_t> kChallenge = {1, 2, 3};
}

TEST_CASE("ChallengeStore::consume hands a challenge out exactly once", "[challenge_store]") {
    ChallengeStore store;
    store.start("login:a", kChallenge);
    const auto first = store.consume("login:a");
    REQUIRE(first.has_value());
    CHECK(*first == kChallenge);
    CHECK_FALSE(store.consume("login:a").has_value());
    CHECK(store.size() == 0);
}

TEST_CASE("ChallengeStore::consume of an unknown key is empty", "[challenge_store]") {
    ChallengeStore store;
    CHECK_FALSE(store.consume("login:nope").has_value());
}

TEST_CASE("ChallengeStore::consume refuses an expired challenge and still removes it", "[challenge_store]") {
    ChallengeStore store;
    store.start("login:a", kChallenge, std::chrono::minutes(0));
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK_FALSE(store.consume("login:a").has_value());
    CHECK(store.size() == 0);
}

TEST_CASE("concurrent consume of one challenge yields it to exactly one caller", "[challenge_store]") {
    for (int round = 0; round < 20; ++round) {
        ChallengeStore store;
        store.start("login:a", kChallenge);
        std::atomic<int> winners{0};
        std::atomic<bool> go{false};
        std::vector<std::thread> threads;
        for (int i = 0; i < 8; ++i) {
            threads.emplace_back([&] {
                while (!go.load()) {
                }
                if (store.consume("login:a")) {
                    ++winners;
                }
            });
        }
        go = true;
        for (auto& t : threads) {
            t.join();
        }
        CHECK(winners.load() == 1);
    }
}

TEST_CASE("ChallengeStore::start reclaims expired entries", "[challenge_store]") {
    ChallengeStore store;
    for (int i = 0; i < 5; ++i) {
        store.start("login:" + std::to_string(i), kChallenge, std::chrono::minutes(0));
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    store.start("login:live", kChallenge);
    CHECK(store.size() == 1);
    CHECK(store.consume("login:live").has_value());
}

TEST_CASE("ChallengeStore stays bounded under an unauthenticated flood, keeping the newest", "[challenge_store]") {
    ChallengeStore store;
    const std::size_t flood = ChallengeStore::kMaxEntries + 500;
    for (std::size_t i = 0; i < flood; ++i) {
        store.start("login:" + std::to_string(i), kChallenge);
    }
    CHECK(store.size() == ChallengeStore::kMaxEntries);
    CHECK_FALSE(store.consume("login:0").has_value());
    CHECK(store.consume("login:" + std::to_string(flood - 1)).has_value());
}

TEST_CASE("ChallengeStore eviction doesn't drop a key that was re-started", "[challenge_store]") {
    ChallengeStore store;
    store.start("register:alice", kChallenge);
    store.start("register:alice", {9, 9});
    for (std::size_t i = 0; i < ChallengeStore::kMaxEntries - 2; ++i) {
        store.start("login:" + std::to_string(i), kChallenge);
    }
    // Two stamps for alice + kMaxEntries-2 others == kMaxEntries stamps: nothing
    // evicted yet. One more push pops the oldest (alice's stale first stamp),
    // which must not erase her newer entry.
    store.start("login:extra", kChallenge);
    const auto alice = store.consume("register:alice");
    REQUIRE(alice.has_value());
    CHECK(*alice == std::vector<std::uint8_t>{9, 9});
}
