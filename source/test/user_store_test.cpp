#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <filesystem>
#include <random>
#include <thread>
#include <vector>

#include "auth/user_store.hpp"

using namespace atomwall;

namespace {

std::string temp_users_path() {
    auto path = std::filesystem::temp_directory_path() /
                ("atomwall_test_users_" + std::to_string(std::random_device{}()) + ".yaml");
    return path.string();
}

} // namespace

TEST_CASE("consume_totp_step accepts a strictly increasing step and rejects a replay",
          "[user_store]") {
    UserStore store(temp_users_path());
    store.create("alice", "correct horse battery staple");

    CHECK(store.consume_totp_step("alice", 100));
    CHECK_FALSE(store.consume_totp_step("alice", 100)); // exact replay
    CHECK_FALSE(store.consume_totp_step("alice", 99));  // an earlier step, also a replay
    CHECK(store.consume_totp_step("alice", 101));       // genuinely the next step
}

TEST_CASE("consume_totp_step tracks each user independently", "[user_store]") {
    UserStore store(temp_users_path());
    store.create("alice", "correct horse battery staple");
    store.create("bob", "another good password");

    CHECK(store.consume_totp_step("alice", 50));
    CHECK(store.consume_totp_step("bob", 50)); // same step number, different user — not a replay
    CHECK_FALSE(store.consume_totp_step("alice", 50));
    CHECK_FALSE(store.consume_totp_step("bob", 50));
}

TEST_CASE("create_if_empty only creates the first user", "[user_store]") {
    UserStore store(temp_users_path());
    CHECK(store.create_if_empty("alice", "correct horse battery staple"));
    CHECK_FALSE(store.create_if_empty("mallory", "another good password"));
    CHECK(store.find("alice").has_value());
    CHECK_FALSE(store.find("mallory").has_value());
    CHECK(store.list().size() == 1);
}

TEST_CASE("create_if_empty validates credentials like create", "[user_store]") {
    UserStore store(temp_users_path());
    CHECK_THROWS_AS(store.create_if_empty("", "correct horse battery staple"), std::invalid_argument);
    CHECK_THROWS_AS(store.create_if_empty("alice", "short"), std::invalid_argument);
    CHECK(store.empty());
}

TEST_CASE("concurrent create_if_empty calls produce exactly one user", "[user_store]") {
    for (int round = 0; round < 5; ++round) {
        UserStore store(temp_users_path());
        std::atomic<int> winners{0};
        std::atomic<bool> go{false};
        std::vector<std::thread> threads;
        for (int i = 0; i < 8; ++i) {
            threads.emplace_back([&, i] {
                while (!go.load()) {
                }
                if (store.create_if_empty("user" + std::to_string(i), "correct horse battery staple")) {
                    ++winners;
                }
            });
        }
        go = true;
        for (auto& t : threads) {
            t.join();
        }
        CHECK(winners.load() == 1);
        CHECK(store.list().size() == 1);
    }
}
