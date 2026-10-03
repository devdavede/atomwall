#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace atomwall {

// Owned, libcbor-free representation of a decoded CBOR item. parse_cbor()
// walks the libcbor tree exactly once right after cbor_load() succeeds and
// copies everything into this structure, then releases every libcbor
// reference — the rest of the codebase (cose_key.cpp, webauthn_service.cpp)
// never touches a cbor_item_t* or libcbor's manual refcounting, which
// sidesteps an entire class of use-after-free/leak bugs that come from
// mixing owned (cbor_array_get) and borrowed (cbor_map_handle) references
// from that C API.
struct CborValue {
    enum class Kind { Uint, Negint, Bytes, Text, Array, Map, Bool, Null, Other };

    Kind kind = Kind::Other;
    // For Uint: the value itself. For Negint: the raw encoded magnitude N —
    // the logical value is -1 - N (CBOR's negative-integer encoding), see
    // cbor_to_int64() below.
    std::uint64_t uint_value = 0;
    std::vector<std::uint8_t> bytes;
    std::string text;
    std::vector<CborValue> array;
    std::vector<std::pair<CborValue, CborValue>> map;
    bool bool_value = false;
};

// Decodes `data` (expected to be a handful of KB at most — WebAuthn
// attestation/assertion payloads are always tiny). Throws
// std::invalid_argument on anything malformed, oversized, or too deeply
// nested — see the size/depth caps in cbor_reader.cpp — never on attacker
// input does this leave a partially-referenced libcbor tree behind. Trailing
// bytes after the one top-level item are ignored; use parse_cbor_prefix if
// the exact consumed length matters.
CborValue parse_cbor(const std::vector<std::uint8_t>& data);

// Same decoding as parse_cbor, but also returns how many leading bytes of
// `data` made up that one item — needed to carve the COSE public key's exact
// byte range out of authenticatorData, which isn't itself CBOR-wrapped (it's
// a fixed-layout binary structure with a bare CBOR item embedded partway
// through, see webauthn_service.cpp).
std::pair<CborValue, std::size_t> parse_cbor_prefix(const std::vector<std::uint8_t>& data);

// Converts a Uint/Negint CborValue to a signed 64-bit value. Throws
// std::invalid_argument if `value` isn't an integer or doesn't fit.
std::int64_t cbor_to_int64(const CborValue& value);

// Map lookups — COSE keys use integer keys (e.g. alg, crv, x, y); CBOR
// structures like attestationObject use text-string keys (e.g. "fmt"). Both
// return nullptr (not found / key type mismatch) rather than throwing, since
// "this optional field is absent" is a normal, expected outcome the caller
// decides how to handle.
const CborValue* cbor_map_find_int(const CborValue& map, std::int64_t key);
const CborValue* cbor_map_find_text(const CborValue& map, std::string_view key);

} // namespace atomwall
