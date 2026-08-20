#include "pipeline/net_utils.hpp"

#include <algorithm>
#include <array>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <cctype>
#include <charconv>

namespace atomwall {

namespace net = boost::asio;

std::optional<CidrRange> parse_cidr(std::string_view text) {
    const auto slash = text.find('/');
    if (slash == std::string_view::npos) {
        return std::nullopt;
    }

    const auto address_part = text.substr(0, slash);
    const auto prefix_part = text.substr(slash + 1);

    boost::system::error_code ec;
    auto address = net::ip::make_address(std::string(address_part), ec);
    if (ec) {
        return std::nullopt;
    }

    unsigned prefix_len = 0;
    const auto* begin = prefix_part.data();
    const auto* end = begin + prefix_part.size();
    auto result = std::from_chars(begin, end, prefix_len);
    if (result.ec != std::errc{} || result.ptr != end) {
        return std::nullopt;
    }

    const unsigned max_bits = address.is_v4() ? 32 : 128;
    if (prefix_len > max_bits) {
        return std::nullopt;
    }

    return CidrRange{address, prefix_len, std::string(text)};
}

namespace {

template <std::size_t N>
bool prefix_matches(const std::array<unsigned char, N>& a,
                     const std::array<unsigned char, N>& b,
                     unsigned prefix_len) {
    unsigned full_bytes = prefix_len / 8;
    unsigned remaining_bits = prefix_len % 8;

    for (unsigned i = 0; i < full_bytes; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    if (remaining_bits == 0) {
        return true;
    }
    const unsigned char mask = static_cast<unsigned char>(0xFF00u >> remaining_bits);
    return (a[full_bytes] & mask) == (b[full_bytes] & mask);
}

} // namespace

bool address_in_cidr(const boost::asio::ip::address& address, const CidrRange& range) {
    if (address.is_v4() && range.prefix.is_v4()) {
        return prefix_matches(address.to_v4().to_bytes(), range.prefix.to_v4().to_bytes(),
                               range.prefix_len);
    }
    if (address.is_v6() && range.prefix.is_v6()) {
        return prefix_matches(address.to_v6().to_bytes(), range.prefix.to_v6().to_bytes(),
                               range.prefix_len);
    }
    return false;
}

bool icontains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                           [](unsigned char a, unsigned char b) {
                               return std::tolower(a) == std::tolower(b);
                           });
    return it != haystack.end();
}

bool istarts_with(std::string_view haystack, std::string_view prefix) {
    if (prefix.size() > haystack.size()) {
        return false;
    }
    return std::equal(prefix.begin(), prefix.end(), haystack.begin(),
                       [](unsigned char a, unsigned char b) {
                           return std::tolower(a) == std::tolower(b);
                       });
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    return std::equal(a.begin(), a.end(), b.begin(), [](unsigned char x, unsigned char y) {
        return std::tolower(x) == std::tolower(y);
    });
}

std::string to_lower(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // namespace atomwall
