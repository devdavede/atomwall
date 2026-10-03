#include <catch2/catch_test_macros.hpp>
#include <cmath>
#include <limits>

#include "util/numeric.hpp"

using namespace atomwall;

TEST_CASE("saturating_to_int passes ordinary values through, truncating fractions", "[numeric]") {
    CHECK(saturating_to_int(0.0) == 0);
    CHECK(saturating_to_int(42.0) == 42);
    CHECK(saturating_to_int(-42.0) == -42);
    CHECK(saturating_to_int(1.9) == 1);
    CHECK(saturating_to_int(-1.9) == -1);
}

TEST_CASE("saturating_to_int is exact at int's limits", "[numeric]") {
    constexpr int kMax = std::numeric_limits<int>::max();
    constexpr int kMin = std::numeric_limits<int>::min();
    CHECK(saturating_to_int(static_cast<double>(kMax)) == kMax);
    CHECK(saturating_to_int(static_cast<double>(kMax) - 1.0) == kMax - 1);
    CHECK(saturating_to_int(static_cast<double>(kMin)) == kMin);
    CHECK(saturating_to_int(static_cast<double>(kMin) + 1.0) == kMin + 1);
}

TEST_CASE("saturating_to_int saturates out-of-range and non-finite values instead of invoking UB", "[numeric]") {
    constexpr int kMax = std::numeric_limits<int>::max();
    constexpr int kMin = std::numeric_limits<int>::min();
    CHECK(saturating_to_int(2147483648.0) == kMax);
    CHECK(saturating_to_int(1e300) == kMax);
    CHECK(saturating_to_int(std::numeric_limits<double>::infinity()) == kMax);
    CHECK(saturating_to_int(-2147483649.0) == kMin);
    CHECK(saturating_to_int(-1e300) == kMin);
    CHECK(saturating_to_int(-std::numeric_limits<double>::infinity()) == kMin);
    CHECK(saturating_to_int(std::nan("")) == kMin);
}
