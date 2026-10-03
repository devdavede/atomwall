#pragma once

#include <limits>

namespace atomwall {

// static_cast<int>(double) is undefined behavior when the value is outside
// int's range (or NaN), and JSON numbers arrive from the client as doubles
// with no such guarantee: 1e300 is a valid JSON number. Saturating instead
// hands callers' own range checks a value they'll reject as out of range,
// rather than whatever the cast happens to wrap to. Fractions truncate toward
// zero, as the plain cast does.
inline int saturating_to_int(double value) {
    constexpr double kMin = static_cast<double>(std::numeric_limits<int>::min());
    constexpr double kMax = static_cast<double>(std::numeric_limits<int>::max());
    if (!(value > kMin)) { // also true for NaN
        return std::numeric_limits<int>::min();
    }
    if (value >= kMax) {
        return std::numeric_limits<int>::max();
    }
    return static_cast<int>(value);
}

} // namespace atomwall
