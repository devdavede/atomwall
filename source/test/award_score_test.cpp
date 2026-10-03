#include <boost/asio/ip/address.hpp>
#include <catch2/catch_test_macros.hpp>
#include <climits>
#include <vector>

#include "listener/http_session.hpp"

using namespace atomwall;
namespace net = boost::asio;

namespace {

std::vector<TemporaryIpBlock> ban_after_one_offense(int ban_duration_hours) {
    RuntimeConfig config;
    config.ban.enabled = true;
    config.ban.threshold = 10;
    config.ban.ban_duration_hours = ban_duration_hours;
    config.ban.scores["speed_check"] = 10;

    ScoreTracker scores;
    IpBlockTracker blocks;
    const auto ip = net::ip::make_address("203.0.113.7");
    detail::award_score(config, scores, blocks, ip, "203.0.113.7", "speed_check");
    return blocks.list_active();
}

} // namespace

TEST_CASE("award_score bans for the configured duration", "[award_score]") {
    const auto active = ban_after_one_offense(24);
    REQUIRE(active.size() == 1);
    CHECK(active[0].expires_at - active[0].created_at == std::chrono::hours(24));
}

TEST_CASE("award_score clamps an absurd hand-edited duration to the maximum", "[award_score]") {
    // Where system_clock ticks are nanoseconds (Linux/libstdc++) hours(INT_MAX) added to
    // now() overflows int64 and wraps the expiry into the past — a "very long" ban that
    // silently isn't one. Asserting the clamp itself keeps this meaningful on platforms
    // with coarser ticks too.
    for (const int absurd : {INT_MAX, 3'000'000, kMaxBanDurationHours + 1}) {
        const auto active = ban_after_one_offense(absurd);
        REQUIRE(active.size() == 1);
        CHECK(active[0].expires_at - active[0].created_at == std::chrono::hours(kMaxBanDurationHours));
    }
}
