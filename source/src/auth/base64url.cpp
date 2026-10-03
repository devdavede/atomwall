#include "auth/base64url.hpp"

#include <array>
#include <stdexcept>

namespace atomwall {

namespace {

constexpr std::string_view kAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::array<int, 256> build_decode_table() {
    std::array<int, 256> table{};
    table.fill(-1);
    for (int i = 0; i < static_cast<int>(kAlphabet.size()); ++i) {
        table[static_cast<unsigned char>(kAlphabet[static_cast<std::size_t>(i)])] = i;
    }
    return table;
}

} // namespace

std::string base64url_encode(const std::vector<std::uint8_t>& data) {
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);

    std::size_t i = 0;
    while (i + 3 <= data.size()) {
        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(data[i]) << 16) |
            (static_cast<std::uint32_t>(data[i + 1]) << 8) | static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 6) & 0x3F]);
        out.push_back(kAlphabet[chunk & 0x3F]);
        i += 3;
    }

    const std::size_t remaining = data.size() - i;
    if (remaining == 1) {
        const std::uint32_t chunk = static_cast<std::uint32_t>(data[i]) << 16;
        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
    } else if (remaining == 2) {
        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(data[i]) << 16) | (static_cast<std::uint32_t>(data[i + 1]) << 8);
        out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
        out.push_back(kAlphabet[(chunk >> 6) & 0x3F]);
    }
    return out;
}

std::vector<std::uint8_t> base64url_decode(const std::string& text) {
    static const std::array<int, 256> kDecodeTable = build_decode_table();

    // Unpadded input only — WebAuthn's JSON wire format never sends '='
    // padding; reject it rather than silently stripping it, since a client
    // sending padding is already deviating from spec.
    if (text.find('=') != std::string::npos) {
        throw std::invalid_argument("base64url input must not be padded");
    }
    if (text.size() % 4 == 1) {
        throw std::invalid_argument("invalid base64url length");
    }

    std::vector<std::uint8_t> out;
    out.reserve(text.size() / 4 * 3 + 3);

    std::uint32_t buffer = 0;
    int bits = 0;
    for (char c : text) {
        const int value = kDecodeTable[static_cast<unsigned char>(c)];
        if (value < 0) {
            throw std::invalid_argument("invalid base64url character");
        }
        buffer = (buffer << 6) | static_cast<std::uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

} // namespace atomwall
