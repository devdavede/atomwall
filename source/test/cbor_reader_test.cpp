#include <catch2/catch_test_macros.hpp>

#include <cbor.h>
#include <memory>
#include <sys/resource.h>
#include <vector>

#include "auth/webauthn/cbor_reader.hpp"

using namespace atomwall;

namespace {

// Serializes a libcbor item to bytes and releases it — small helper so each
// test case can build a fixture with libcbor's own API (the ground truth
// we're decoding against) without repeating the encref/serialize/decref
// boilerplate.
std::vector<std::uint8_t> encode_and_free(cbor_item_t* item) {
    unsigned char* buffer = nullptr;
    std::size_t buffer_size = 0;
    std::size_t len = cbor_serialize_alloc(item, &buffer, &buffer_size);
    std::vector<std::uint8_t> out(buffer, buffer + len);
    free(buffer);
    cbor_decref(&item);
    return out;
}

} // namespace

TEST_CASE("parse_cbor decodes a flat map with text keys", "[cbor_reader]") {
    cbor_item_t* map = cbor_new_definite_map(2);
    cbor_map_add(map, {cbor_move(cbor_build_string("fmt")), cbor_move(cbor_build_string("none"))});
    cbor_item_t* bytes = cbor_build_bytestring(reinterpret_cast<const unsigned char*>("hello"), 5);
    cbor_map_add(map, {cbor_move(cbor_build_string("authData")), cbor_move(bytes)});
    auto encoded = encode_and_free(map);

    auto decoded = parse_cbor(encoded);
    REQUIRE(decoded.kind == CborValue::Kind::Map);

    auto* fmt = cbor_map_find_text(decoded, "fmt");
    REQUIRE(fmt != nullptr);
    CHECK(fmt->kind == CborValue::Kind::Text);
    CHECK(fmt->text == "none");

    auto* auth_data = cbor_map_find_text(decoded, "authData");
    REQUIRE(auth_data != nullptr);
    CHECK(auth_data->kind == CborValue::Kind::Bytes);
    CHECK(auth_data->bytes == std::vector<std::uint8_t>({'h', 'e', 'l', 'l', 'o'}));

    CHECK(cbor_map_find_text(decoded, "missing") == nullptr);
}

TEST_CASE("parse_cbor decodes integer map keys, including negative COSE-style labels",
          "[cbor_reader]") {
    cbor_item_t* map = cbor_new_definite_map(2);
    cbor_map_add(map, {cbor_move(cbor_build_uint8(1)), cbor_move(cbor_build_uint8(2))});    // kty: EC2
    cbor_map_add(map, {cbor_move(cbor_build_negint8(6)), cbor_move(cbor_build_uint8(42))}); // -7: 42
    auto encoded = encode_and_free(map);

    auto decoded = parse_cbor(encoded);
    auto* kty = cbor_map_find_int(decoded, 1);
    REQUIRE(kty != nullptr);
    CHECK(cbor_to_int64(*kty) == 2);

    auto* alg = cbor_map_find_int(decoded, -7);
    REQUIRE(alg != nullptr);
    CHECK(cbor_to_int64(*alg) == 42);
}

TEST_CASE("parse_cbor decodes nested arrays", "[cbor_reader]") {
    cbor_item_t* arr = cbor_new_definite_array(3);
    cbor_array_push(arr, cbor_move(cbor_build_uint8(1)));
    cbor_array_push(arr, cbor_move(cbor_build_uint8(2)));
    cbor_array_push(arr, cbor_move(cbor_build_uint8(3)));
    auto encoded = encode_and_free(arr);

    auto decoded = parse_cbor(encoded);
    REQUIRE(decoded.kind == CborValue::Kind::Array);
    REQUIRE(decoded.array.size() == 3);
    CHECK(cbor_to_int64(decoded.array[0]) == 1);
    CHECK(cbor_to_int64(decoded.array[2]) == 3);
}

TEST_CASE("parse_cbor_prefix reports how many bytes the first item consumed", "[cbor_reader]") {
    cbor_item_t* first = cbor_build_uint8(7);
    auto encoded = encode_and_free(first);
    std::vector<std::uint8_t> with_trailer = encoded;
    with_trailer.push_back(0xFF); // garbage trailing byte, should be ignored and reported as unconsumed

    auto [value, consumed] = parse_cbor_prefix(with_trailer);
    CHECK(cbor_to_int64(value) == 7);
    CHECK(consumed == encoded.size());
}

TEST_CASE("parse_cbor rejects empty input", "[cbor_reader]") {
    CHECK_THROWS_AS(parse_cbor({}), std::invalid_argument);
}

TEST_CASE("parse_cbor rejects malformed/truncated CBOR", "[cbor_reader]") {
    // 0xBB = map header declaring 8-byte length follows, but nothing does.
    CHECK_THROWS_AS(parse_cbor({0xBB}), std::invalid_argument);
    // Declares a byte string of length 10 but supplies none of it.
    CHECK_THROWS_AS(parse_cbor({0x4A}), std::invalid_argument);
}

TEST_CASE("parse_cbor rejects input over the size cap", "[cbor_reader]") {
    std::vector<std::uint8_t> huge(5000, 0);
    CHECK_THROWS_AS(parse_cbor(huge), std::invalid_argument);
}

TEST_CASE("parse_cbor rejects excessive nesting depth", "[cbor_reader]") {
    // Build 12 arrays nested inside one another (deeper than the 8-level cap).
    cbor_item_t* innermost = cbor_build_uint8(1);
    cbor_item_t* current = innermost;
    for (int i = 0; i < 12; ++i) {
        cbor_item_t* wrapper = cbor_new_definite_array(1);
        cbor_array_push(wrapper, cbor_move(current));
        current = wrapper;
    }
    auto encoded = encode_and_free(current);
    CHECK_THROWS_AS(parse_cbor(encoded), std::invalid_argument);
}

TEST_CASE("cbor_to_int64 rejects non-integer values", "[cbor_reader]") {
    cbor_item_t* text = cbor_build_string("nope");
    auto encoded = encode_and_free(text);
    auto decoded = parse_cbor(encoded);
    CHECK_THROWS_AS(cbor_to_int64(decoded), std::invalid_argument);
}

namespace {

std::size_t peak_rss_bytes() {
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
#ifdef __APPLE__
    return static_cast<std::size_t>(usage.ru_maxrss);
#else
    return static_cast<std::size_t>(usage.ru_maxrss) * 1024;
#endif
}

} // namespace

TEST_CASE("parse_cbor rejects a tiny input declaring a huge array without allocating for it", "[cbor_reader]") {
    // libcbor allocates and zero-fills a definite array's element storage from
    // the declared count before it checks any of that count against the input.
    // 0x9A + 0x04000000 declares 67M elements (512 MiB of pointers) in 5 bytes,
    // so the input-size cap alone doesn't bound it; a peak-RSS jump is what an
    // unbounded allocation looks like.
    const std::size_t rss_before = peak_rss_bytes();
    CHECK_THROWS_AS(parse_cbor({0x9A, 0x04, 0x00, 0x00, 0x00}), std::invalid_argument);
    CHECK_THROWS_AS(parse_cbor({0xBA, 0x04, 0x00, 0x00, 0x00}), std::invalid_argument);
    CHECK_THROWS_AS(parse_cbor({0x9B, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00}),
                    std::invalid_argument);
    const std::size_t growth = peak_rss_bytes() - rss_before;
    CHECK(growth < 64ull * 1024 * 1024);
}
