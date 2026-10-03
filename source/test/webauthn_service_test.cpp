#include <catch2/catch_test_macros.hpp>

#include <array>
#include <boost/json.hpp>
#include <cbor.h>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

#include "auth/base64url.hpp"
#include "auth/webauthn/webauthn_service.hpp"

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

PkeyPtr generate_ec_p256_key() { return PkeyPtr(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256")); }

std::vector<std::uint8_t> es256_cose_key_bytes(EVP_PKEY* key) {
    unsigned char buf[128];
    std::size_t len = 0;
    REQUIRE(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, buf, sizeof(buf), &len));
    REQUIRE(len == 65);
    std::vector<std::uint8_t> x(buf + 1, buf + 33);
    std::vector<std::uint8_t> y(buf + 33, buf + 65);

    cbor_item_t* map = cbor_new_definite_map(5);
    cbor_map_add(map, {cbor_move(cbor_build_uint8(1)), cbor_move(cbor_build_uint8(2))});   // kty: EC2
    cbor_map_add(map, {cbor_move(cbor_build_uint8(3)), cbor_move(cbor_build_negint8(6))}); // alg: ES256
    cbor_map_add(map, {cbor_move(cbor_build_negint8(0)), cbor_move(cbor_build_uint8(1))}); // crv: P-256
    cbor_map_add(map, {cbor_move(cbor_build_negint8(1)), cbor_move(cbor_build_bytestring(x.data(), x.size()))});
    cbor_map_add(map, {cbor_move(cbor_build_negint8(2)), cbor_move(cbor_build_bytestring(y.data(), y.size()))});
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

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data) {
    std::array<std::uint8_t, 32> digest{};
    unsigned int len = 0;
    REQUIRE(EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha256(), nullptr) == 1);
    return digest;
}
std::array<std::uint8_t, 32> sha256(const std::string& data) {
    return sha256(std::vector<std::uint8_t>(data.begin(), data.end()));
}

constexpr std::uint8_t kFlagUp = 0x01;
constexpr std::uint8_t kFlagAt = 0x40;

// `credential_id`/`cose_key_bytes` empty => no attested credential data
// (an assertion's authenticatorData never has any).
std::vector<std::uint8_t> build_auth_data(const std::string& rp_id, std::uint8_t flags,
                                           std::uint32_t sign_count,
                                           const std::vector<std::uint8_t>& credential_id,
                                           const std::vector<std::uint8_t>& cose_key_bytes) {
    std::vector<std::uint8_t> out;
    auto rp_hash = sha256(rp_id);
    out.insert(out.end(), rp_hash.begin(), rp_hash.end());
    out.push_back(flags);
    out.push_back(static_cast<std::uint8_t>((sign_count >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((sign_count >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((sign_count >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(sign_count & 0xFF));
    if (flags & kFlagAt) {
        std::vector<std::uint8_t> aaguid(16, 0);
        out.insert(out.end(), aaguid.begin(), aaguid.end());
        const auto len = static_cast<std::uint16_t>(credential_id.size());
        out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(len & 0xFF));
        out.insert(out.end(), credential_id.begin(), credential_id.end());
        out.insert(out.end(), cose_key_bytes.begin(), cose_key_bytes.end());
    }
    return out;
}

std::vector<std::uint8_t> build_attestation_object(const std::vector<std::uint8_t>& auth_data) {
    cbor_item_t* map = cbor_new_definite_map(3);
    cbor_map_add(map, {cbor_move(cbor_build_string("fmt")), cbor_move(cbor_build_string("none"))});
    cbor_map_add(map, {cbor_move(cbor_build_string("attStmt")), cbor_move(cbor_new_definite_map(0))});
    cbor_map_add(map, {cbor_move(cbor_build_string("authData")),
                        cbor_move(cbor_build_bytestring(auth_data.data(), auth_data.size()))});
    return encode_and_free(map);
}

std::string build_client_data_json(const std::string& type, const std::vector<std::uint8_t>& challenge,
                                    const std::string& origin) {
    boost::json::object obj;
    obj["type"] = type;
    obj["challenge"] = base64url_encode(challenge);
    obj["origin"] = origin;
    return boost::json::serialize(obj);
}

const std::string kRpId = "localhost";
const std::string kOrigin = "http://localhost:9000";

} // namespace

TEST_CASE("verify_webauthn_registration accepts a well-formed registration", "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    REQUIRE(key);
    auto cose_bytes = es256_cose_key_bytes(key.get());
    std::vector<std::uint8_t> challenge{1, 2, 3, 4, 5, 6, 7, 8};
    std::vector<std::uint8_t> credential_id{0xAA, 0xBB, 0xCC, 0xDD};

    auto auth_data = build_auth_data(kRpId, kFlagUp | kFlagAt, 0, credential_id, cose_bytes);
    auto attestation_object = build_attestation_object(auth_data);
    auto client_data_json = build_client_data_json("webauthn.create", challenge, kOrigin);

    auto result =
        verify_webauthn_registration(challenge, client_data_json, attestation_object, kRpId, kOrigin);
    CHECK(result.credential_id_b64url == base64url_encode(credential_id));
    CHECK(result.cose_public_key == cose_bytes);
    CHECK(result.sign_count == 0);
}

TEST_CASE("verify_webauthn_registration rejects a wrong origin", "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    std::vector<std::uint8_t> challenge{1, 2, 3};
    auto auth_data = build_auth_data(kRpId, kFlagUp | kFlagAt, 0, {0x01}, cose_bytes);
    auto attestation_object = build_attestation_object(auth_data);
    auto client_data_json = build_client_data_json("webauthn.create", challenge, "https://evil.example");

    CHECK_THROWS_AS(
        verify_webauthn_registration(challenge, client_data_json, attestation_object, kRpId, kOrigin),
        std::invalid_argument);
}

TEST_CASE("verify_webauthn_registration rejects a mismatched challenge", "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    auto auth_data = build_auth_data(kRpId, kFlagUp | kFlagAt, 0, {0x01}, cose_bytes);
    auto attestation_object = build_attestation_object(auth_data);
    auto client_data_json = build_client_data_json("webauthn.create", {9, 9, 9}, kOrigin);

    CHECK_THROWS_AS(verify_webauthn_registration({1, 2, 3}, client_data_json, attestation_object,
                                                  kRpId, kOrigin),
                    std::invalid_argument);
}

TEST_CASE("verify_webauthn_registration rejects a wrong RP ID", "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    std::vector<std::uint8_t> challenge{1, 2, 3};
    auto auth_data = build_auth_data("some-other-rp.example", kFlagUp | kFlagAt, 0, {0x01}, cose_bytes);
    auto attestation_object = build_attestation_object(auth_data);
    auto client_data_json = build_client_data_json("webauthn.create", challenge, kOrigin);

    CHECK_THROWS_AS(
        verify_webauthn_registration(challenge, client_data_json, attestation_object, kRpId, kOrigin),
        std::invalid_argument);
}

TEST_CASE("verify_webauthn_registration rejects a missing user-presence flag", "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    std::vector<std::uint8_t> challenge{1, 2, 3};
    auto auth_data = build_auth_data(kRpId, kFlagAt /* no UP */, 0, {0x01}, cose_bytes);
    auto attestation_object = build_attestation_object(auth_data);
    auto client_data_json = build_client_data_json("webauthn.create", challenge, kOrigin);

    CHECK_THROWS_AS(
        verify_webauthn_registration(challenge, client_data_json, attestation_object, kRpId, kOrigin),
        std::invalid_argument);
}

TEST_CASE("verify_webauthn_authentication accepts a genuine assertion and advances the counter",
          "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    std::vector<std::uint8_t> challenge{9, 9, 9, 9};

    auto auth_data = build_auth_data(kRpId, kFlagUp, 5, {}, {});
    auto client_data_json = build_client_data_json("webauthn.get", challenge, kOrigin);
    auto client_data_hash = sha256(client_data_json);
    std::vector<std::uint8_t> signed_data = auth_data;
    signed_data.insert(signed_data.end(), client_data_hash.begin(), client_data_hash.end());
    auto signature = sign(key.get(), signed_data);

    auto result = verify_webauthn_authentication(challenge, client_data_json, auth_data, signature,
                                                  cose_bytes, /*stored_sign_count=*/3, kRpId, kOrigin);
    CHECK(result.new_sign_count == 5);
}

TEST_CASE("verify_webauthn_authentication rejects a non-increasing sign counter (possible clone)",
          "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    std::vector<std::uint8_t> challenge{1};

    auto auth_data = build_auth_data(kRpId, kFlagUp, 5, {}, {});
    auto client_data_json = build_client_data_json("webauthn.get", challenge, kOrigin);
    auto client_data_hash = sha256(client_data_json);
    std::vector<std::uint8_t> signed_data = auth_data;
    signed_data.insert(signed_data.end(), client_data_hash.begin(), client_data_hash.end());
    auto signature = sign(key.get(), signed_data);

    CHECK_THROWS_AS(verify_webauthn_authentication(challenge, client_data_json, auth_data, signature,
                                                    cose_bytes, /*stored_sign_count=*/5, kRpId, kOrigin),
                    std::invalid_argument);
}

TEST_CASE("verify_webauthn_authentication treats stored+reported sign_count of 0 as unsupported, "
          "not a replay",
          "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    std::vector<std::uint8_t> challenge{2};

    auto auth_data = build_auth_data(kRpId, kFlagUp, 0, {}, {});
    auto client_data_json = build_client_data_json("webauthn.get", challenge, kOrigin);
    auto client_data_hash = sha256(client_data_json);
    std::vector<std::uint8_t> signed_data = auth_data;
    signed_data.insert(signed_data.end(), client_data_hash.begin(), client_data_hash.end());
    auto signature = sign(key.get(), signed_data);

    // Same 0/0 pair used twice in a row must both succeed — this is the norm
    // for synced/platform passkeys that never report a counter.
    CHECK_NOTHROW(verify_webauthn_authentication(challenge, client_data_json, auth_data, signature,
                                                  cose_bytes, 0, kRpId, kOrigin));
    CHECK_NOTHROW(verify_webauthn_authentication(challenge, client_data_json, auth_data, signature,
                                                  cose_bytes, 0, kRpId, kOrigin));
}

TEST_CASE("verify_webauthn_authentication rejects a tampered signature", "[webauthn_service]") {
    auto key = generate_ec_p256_key();
    auto cose_bytes = es256_cose_key_bytes(key.get());
    std::vector<std::uint8_t> challenge{3};

    auto auth_data = build_auth_data(kRpId, kFlagUp, 1, {}, {});
    auto client_data_json = build_client_data_json("webauthn.get", challenge, kOrigin);
    auto client_data_hash = sha256(client_data_json);
    std::vector<std::uint8_t> signed_data = auth_data;
    signed_data.insert(signed_data.end(), client_data_hash.begin(), client_data_hash.end());
    auto signature = sign(key.get(), signed_data);
    signature[0] ^= 0xFF;

    CHECK_THROWS_AS(verify_webauthn_authentication(challenge, client_data_json, auth_data, signature,
                                                    cose_bytes, 0, kRpId, kOrigin),
                    std::invalid_argument);
}
