#include <catch2/catch_test_macros.hpp>

#include <cbor.h>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <vector>

#include "auth/webauthn/cbor_reader.hpp"
#include "auth/webauthn/cose_key.hpp"

using namespace atomwall;

namespace {

struct EvpPkeyFreeer {
    void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyFreeer>;

std::vector<std::uint8_t> encode_and_free(cbor_item_t* item) {
    unsigned char* buffer = nullptr;
    std::size_t buffer_size = 0;
    std::size_t len = cbor_serialize_alloc(item, &buffer, &buffer_size);
    std::vector<std::uint8_t> out(buffer, buffer + len);
    free(buffer);
    cbor_decref(&item);
    return out;
}

PkeyPtr generate_ec_p256_key() {
    return PkeyPtr(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
}

PkeyPtr generate_rsa_key() {
    return PkeyPtr(EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<std::size_t>(2048)));
}

std::vector<std::uint8_t> ec_point_bytes(EVP_PKEY* key) {
    unsigned char buf[128];
    std::size_t len = 0;
    REQUIRE(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof(buf), &len));
    REQUIRE(len == 65); // 0x04 || x(32) || y(32) for an uncompressed P-256 point
    return std::vector<std::uint8_t>(buf, buf + len);
}

std::vector<std::uint8_t> es256_cose_key_bytes(EVP_PKEY* key) {
    auto point = ec_point_bytes(key);
    std::vector<std::uint8_t> x(point.begin() + 1, point.begin() + 33);
    std::vector<std::uint8_t> y(point.begin() + 33, point.begin() + 65);

    cbor_item_t* map = cbor_new_definite_map(5);
    cbor_map_add(map, {cbor_move(cbor_build_uint8(1)), cbor_move(cbor_build_uint8(2))});    // kty: EC2
    cbor_map_add(map, {cbor_move(cbor_build_uint8(3)), cbor_move(cbor_build_negint8(6))});  // alg: ES256 (-7)
    cbor_map_add(map, {cbor_move(cbor_build_negint8(0)), cbor_move(cbor_build_uint8(1))});  // crv(-1): P-256 (1)
    cbor_map_add(map, {cbor_move(cbor_build_negint8(1)), // x (-2)
                        cbor_move(cbor_build_bytestring(x.data(), x.size()))});
    cbor_map_add(map, {cbor_move(cbor_build_negint8(2)), // y (-3)
                        cbor_move(cbor_build_bytestring(y.data(), y.size()))});
    return encode_and_free(map);
}

std::vector<std::uint8_t> rsa_n_bytes(EVP_PKEY* key) {
    BIGNUM* n = nullptr;
    REQUIRE(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n));
    std::vector<std::uint8_t> out(static_cast<std::size_t>(BN_num_bytes(n)));
    BN_bn2bin(n, out.data());
    BN_free(n);
    return out;
}

std::vector<std::uint8_t> rsa_e_bytes(EVP_PKEY* key) {
    BIGNUM* e = nullptr;
    REQUIRE(EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e));
    std::vector<std::uint8_t> out(static_cast<std::size_t>(BN_num_bytes(e)));
    BN_bn2bin(e, out.data());
    BN_free(e);
    return out;
}

std::vector<std::uint8_t> rs256_cose_key_bytes(EVP_PKEY* key) {
    auto n = rsa_n_bytes(key);
    auto e = rsa_e_bytes(key);
    cbor_item_t* map = cbor_new_definite_map(4);
    cbor_map_add(map, {cbor_move(cbor_build_uint8(1)), cbor_move(cbor_build_uint8(3))}); // kty: RSA
    cbor_item_t* alg = cbor_build_negint16(256);                                        // -257
    cbor_map_add(map, {cbor_move(cbor_build_uint8(3)), cbor_move(alg)});
    cbor_map_add(map, {cbor_move(cbor_build_negint8(0)), // label -1 (n)
                        cbor_move(cbor_build_bytestring(n.data(), n.size()))});
    cbor_map_add(map, {cbor_move(cbor_build_negint8(1)), // label -2 (e)
                        cbor_move(cbor_build_bytestring(e.data(), e.size()))});
    return encode_and_free(map);
}

std::vector<std::uint8_t> sign(EVP_PKEY* key, const std::vector<std::uint8_t>& data) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) == 1);
    std::size_t sig_len = 0;
    REQUIRE(EVP_DigestSign(ctx.get(), nullptr, &sig_len, data.data(), data.size()) == 1);
    std::vector<std::uint8_t> sig(sig_len);
    REQUIRE(EVP_DigestSign(ctx.get(), sig.data(), &sig_len, data.data(), data.size()) == 1);
    sig.resize(sig_len);
    return sig;
}

} // namespace

TEST_CASE("parse_cose_public_key + verify_cose_signature accept a genuine ES256 signature",
          "[cose_key]") {
    auto key = generate_ec_p256_key();
    REQUIRE(key);
    auto cose_bytes = es256_cose_key_bytes(key.get());

    CoseAlgorithm alg{};
    auto parsed = parse_cose_public_key(parse_cbor(cose_bytes), &alg);
    REQUIRE(parsed);
    CHECK(alg == CoseAlgorithm::ES256);

    std::vector<std::uint8_t> message{'h', 'i', ' ', 't', 'h', 'e', 'r', 'e'};
    auto signature = sign(key.get(), message);
    CHECK(verify_cose_signature(parsed.get(), alg, message, signature));
}

TEST_CASE("verify_cose_signature rejects a tampered signature", "[cose_key]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    CoseAlgorithm alg{};
    auto parsed = parse_cose_public_key(parse_cbor(cose_bytes), &alg);

    std::vector<std::uint8_t> message{'d', 'a', 't', 'a'};
    auto signature = sign(key.get(), message);
    signature[signature.size() / 2] ^= 0xFF;
    CHECK_FALSE(verify_cose_signature(parsed.get(), alg, message, signature));
}

TEST_CASE("verify_cose_signature rejects a signature over different data", "[cose_key]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    CoseAlgorithm alg{};
    auto parsed = parse_cose_public_key(parse_cbor(cose_bytes), &alg);

    auto signature = sign(key.get(), {'o', 'n', 'e'});
    CHECK_FALSE(verify_cose_signature(parsed.get(), alg, std::vector<std::uint8_t>{'t', 'w', 'o'},
                                       signature));
}

TEST_CASE("parse_cose_public_key + verify_cose_signature accept a genuine RS256 signature",
          "[cose_key]") {
    auto key = generate_rsa_key();
    REQUIRE(key);
    auto cose_bytes = rs256_cose_key_bytes(key.get());

    CoseAlgorithm alg{};
    auto parsed = parse_cose_public_key(parse_cbor(cose_bytes), &alg);
    REQUIRE(parsed);
    CHECK(alg == CoseAlgorithm::RS256);

    std::vector<std::uint8_t> message{'r', 's', 'a', '!'};
    auto signature = sign(key.get(), message);
    CHECK(verify_cose_signature(parsed.get(), alg, message, signature));
}

TEST_CASE("parse_cose_public_key rejects an unsupported algorithm", "[cose_key]") {
    cbor_item_t* map = cbor_new_definite_map(2);
    cbor_map_add(map, {cbor_move(cbor_build_uint8(1)), cbor_move(cbor_build_uint8(1))}); // kty: OKP
    cbor_item_t* alg = cbor_build_negint8(7);                                            // -8 (EdDSA)
    cbor_map_add(map, {cbor_move(cbor_build_uint8(3)), cbor_move(alg)});
    auto bytes = encode_and_free(map);

    CoseAlgorithm alg_out{};
    CHECK_THROWS_AS(parse_cose_public_key(parse_cbor(bytes), &alg_out), std::invalid_argument);
}

TEST_CASE("parse_cose_public_key rejects a map that isn't a COSE key at all", "[cose_key]") {
    cbor_item_t* map = cbor_new_definite_map(1);
    cbor_map_add(map, {cbor_move(cbor_build_string("not")), cbor_move(cbor_build_string("a cose key"))});
    auto bytes = encode_and_free(map);

    CoseAlgorithm alg_out{};
    CHECK_THROWS_AS(parse_cose_public_key(parse_cbor(bytes), &alg_out), std::invalid_argument);
}

namespace {

std::vector<std::uint8_t> rs256_cose_key_from_raw(const std::vector<std::uint8_t>& n,
                                                   const std::vector<std::uint8_t>& e) {
    cbor_item_t* map = cbor_new_definite_map(4);
    cbor_map_add(map, {cbor_move(cbor_build_uint8(1)), cbor_move(cbor_build_uint8(3))});
    cbor_map_add(map, {cbor_move(cbor_build_uint8(3)), cbor_move(cbor_build_negint16(256))});
    cbor_map_add(map, {cbor_move(cbor_build_negint8(0)), cbor_move(cbor_build_bytestring(n.data(), n.size()))});
    cbor_map_add(map, {cbor_move(cbor_build_negint8(1)), cbor_move(cbor_build_bytestring(e.data(), e.size()))});
    return encode_and_free(map);
}

std::vector<std::uint8_t> odd_modulus(std::size_t bytes) {
    std::vector<std::uint8_t> n(bytes, 0xB7);
    n.back() |= 1;
    return n;
}

} // namespace

TEST_CASE("parse_cose_public_key rejects an RSA key with an oversized modulus or exponent", "[cose_key]") {
    const std::vector<std::uint8_t> e65537{0x01, 0x00, 0x01};
    CoseAlgorithm alg{};

    // ~8000 bits: fits in the CBOR size cap and OpenSSL would accept it, but verifying
    // against it on every login is a cost the server shouldn't let a registrant impose.
    CHECK_THROWS_AS(parse_cose_public_key(parse_cbor(rs256_cose_key_from_raw(odd_modulus(1000), e65537)), &alg),
                    std::invalid_argument);
    CHECK_THROWS_AS(parse_cose_public_key(parse_cbor(rs256_cose_key_from_raw(odd_modulus(513), e65537)), &alg),
                    std::invalid_argument);
    CHECK_THROWS_AS(parse_cose_public_key(
                        parse_cbor(rs256_cose_key_from_raw(odd_modulus(256), {0x01, 0x00, 0x00, 0x00, 0x01})), &alg),
                    std::invalid_argument);
    CHECK_THROWS_AS(parse_cose_public_key(parse_cbor(rs256_cose_key_from_raw({}, e65537)), &alg),
                    std::invalid_argument);
}

TEST_CASE("parse_cose_public_key still accepts RSA moduli up to 4096 bits", "[cose_key]") {
    CoseAlgorithm alg{};
    auto parsed = parse_cose_public_key(
        parse_cbor(rs256_cose_key_from_raw(odd_modulus(512), {0x01, 0x00, 0x01})), &alg);
    CHECK(parsed);
    CHECK(alg == CoseAlgorithm::RS256);
}
