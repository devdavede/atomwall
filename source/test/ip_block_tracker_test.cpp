#include <boost/asio/ip/address.hpp>
#include <catch2/catch_test_macros.hpp>
#include <thread>

#include "history/ip_block_tracker.hpp"

using namespace atomwall;
namespace net = boost::asio;

namespace {

TemporaryIpBlock make_exact_block(std::string text, std::string source, std::chrono::milliseconds ttl) {
    TemporaryIpBlock block;
    block.text = text;
    block.is_cidr = false;
    block.address = net::ip::make_address(text);
    block.source = std::move(source);
    block.created_at = std::chrono::system_clock::now();
    block.expires_at = block.created_at + ttl;
    return block;
}

} // namespace

TEST_CASE("IpBlockTracker blocks an exact IP that was added", "[ip_block_tracker]") {
    IpBlockTracker tracker;
    tracker.add(make_exact_block("203.0.113.7", "manual", std::chrono::hours(1)));
    CHECK(tracker.is_blocked(net::ip::make_address("203.0.113.7")));
    CHECK_FALSE(tracker.is_blocked(net::ip::make_address("203.0.113.8")));
}

TEST_CASE("IpBlockTracker blocks addresses inside a temporary CIDR entry", "[ip_block_tracker]") {
    IpBlockTracker tracker;
    TemporaryIpBlock block;
    block.text = "198.51.100.0/24";
    block.is_cidr = true;
    block.address = net::ip::make_address("198.51.100.0");
    block.prefix_len = 24;
    block.source = "manual";
    block.created_at = std::chrono::system_clock::now();
    block.expires_at = block.created_at + std::chrono::hours(1);
    tracker.add(block);

    CHECK(tracker.is_blocked(net::ip::make_address("198.51.100.42")));
    CHECK_FALSE(tracker.is_blocked(net::ip::make_address("198.51.101.1")));
}

TEST_CASE("IpBlockTracker treats an expired entry as not blocked", "[ip_block_tracker]") {
    IpBlockTracker tracker;
    tracker.add(make_exact_block("203.0.113.7", "score", std::chrono::milliseconds(10)));
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    CHECK_FALSE(tracker.is_blocked(net::ip::make_address("203.0.113.7")));
}

TEST_CASE("IpBlockTracker::list_active prunes expired entries", "[ip_block_tracker]") {
    IpBlockTracker tracker;
    tracker.add(make_exact_block("203.0.113.7", "manual", std::chrono::milliseconds(10)));
    tracker.add(make_exact_block("203.0.113.8", "manual", std::chrono::hours(1)));
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    auto active = tracker.list_active();
    REQUIRE(active.size() == 1);
    CHECK(active[0].text == "203.0.113.8");
}

TEST_CASE("IpBlockTracker::remove removes by text and reports whether it existed", "[ip_block_tracker]") {
    IpBlockTracker tracker;
    tracker.add(make_exact_block("203.0.113.7", "manual", std::chrono::hours(1)));
    CHECK(tracker.remove("203.0.113.7"));
    CHECK_FALSE(tracker.is_blocked(net::ip::make_address("203.0.113.7")));
    CHECK_FALSE(tracker.remove("203.0.113.7"));
}

TEST_CASE("IpBlockTracker::add replaces an existing entry with the same text", "[ip_block_tracker]") {
    IpBlockTracker tracker;
    tracker.add(make_exact_block("203.0.113.7", "manual", std::chrono::hours(1)));
    tracker.add(make_exact_block("203.0.113.7", "score", std::chrono::hours(2)));

    auto active = tracker.list_active();
    REQUIRE(active.size() == 1);
    CHECK(active[0].source == "score");
}
