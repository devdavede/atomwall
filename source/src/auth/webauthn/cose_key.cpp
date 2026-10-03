#include "auth/webauthn/cose_key.hpp"

#include <memory>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <stdexcept>
#include <string>

namespace atomwall {

namespace {

// COSE_Key common parameter labels (RFC 9052/9053).
constexpr std::int64_t kCoseKty = 1;
constexpr std::int64_t kCoseAlg = 3;
constexpr std::int64_t kCoseCrv = -1;
constexpr std::int64_t kCoseX = -2;
constexpr std::int64_t kCoseY = -3;
constexpr std::int64_t kCoseN = -1; // RSA modulus shares label -1 with EC2's crv (different kty)
constexpr std::int64_t kCoseE = -2; // RSA exponent shares label -2 with EC2's x

constexpr std::int64_t kKtyEc2 = 2;
constexpr std::int64_t kKtyRsa = 3;
constexpr std::int64_t kCrvP256 = 1;
constexpr std::int64_t kAlgEs256 = -7;
constexpr std::int64_t kAlgRs256 = -257;

struct ParamBldDeleter {
    void operator()(OSSL_PARAM_BLD* bld) const { OSSL_PARAM_BLD_free(bld); }
};
struct ParamDeleter {
    void operator()(OSSL_PARAM* params) const { OSSL_PARAM_free(params); }
};
struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};
struct BnDeleter {
    void operator()(BIGNUM* bn) const { BN_free(bn); }
};

const std::vector<std::uint8_t>& require_bytes(const CborValue& map, std::int64_t key,
                                                const char* field_name) {
    const auto* value = cbor_map_find_int(map, key);
    if (!value || value->kind != CborValue::Kind::Bytes) {
        throw std::invalid_argument(std::string("COSE key missing/invalid field: ") + field_name);
    }
    return value->bytes;
}

EvpPkeyPtr build_ec_p256_public_key(const std::vector<std::uint8_t>& x,
                                     const std::vector<std::uint8_t>& y) {
    if (x.size() != 32 || y.size() != 32) {
        throw std::invalid_argument("COSE EC2 key: x/y must each be 32 bytes for P-256");
    }
    std::vector<std::uint8_t> point;
    point.reserve(65);
    point.push_back(0x04); // uncompressed SEC1 point indicator
    point.insert(point.end(), x.begin(), x.end());
    point.insert(point.end(), y.begin(), y.end());

    std::unique_ptr<OSSL_PARAM_BLD, ParamBldDeleter> bld(OSSL_PARAM_BLD_new());
    if (!bld || !OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME,
                                                  "prime256v1", 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(),
                                           point.size())) {
        throw std::runtime_error("failed to build EC key parameters");
    }
    std::unique_ptr<OSSL_PARAM, ParamDeleter> params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params) {
        throw std::runtime_error("failed to build EC key parameters");
    }

    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
        throw std::runtime_error("failed to initialize EC key context");
    }
    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw_key, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0 ||
        !raw_key) {
        throw std::invalid_argument("COSE EC2 key: point is not a valid P-256 public key");
    }
    return EvpPkeyPtr(raw_key);
}

// FIDO authenticators use 2048-bit RS256 keys with e = 65537. The 4 KiB CBOR
// cap on its own still admits a ~32,000-bit modulus (and OpenSSL accepts public
// keys up to 16,384 bits), whose signature verification the server would then
// pay for on every login with that credential — unlike the EC path, which
// already insists on exact 32-byte coordinates.
constexpr std::size_t kMaxRsaModulusBytes = 512; // 4096 bits
constexpr std::size_t kMaxRsaExponentBytes = 4;

EvpPkeyPtr build_rsa_public_key(const std::vector<std::uint8_t>& n,
                                 const std::vector<std::uint8_t>& e) {
    if (n.empty() || n.size() > kMaxRsaModulusBytes || e.empty() || e.size() > kMaxRsaExponentBytes) {
        throw std::invalid_argument("COSE RSA key: modulus/exponent size out of range");
    }
    std::unique_ptr<BIGNUM, BnDeleter> bn_n(
        BN_bin2bn(n.data(), static_cast<int>(n.size()), nullptr));
    std::unique_ptr<BIGNUM, BnDeleter> bn_e(
        BN_bin2bn(e.data(), static_cast<int>(e.size()), nullptr));
    if (!bn_n || !bn_e) {
        throw std::invalid_argument("COSE RSA key: invalid modulus/exponent");
    }

    std::unique_ptr<OSSL_PARAM_BLD, ParamBldDeleter> bld(OSSL_PARAM_BLD_new());
    if (!bld || !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, bn_n.get()) ||
        !OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, bn_e.get())) {
        throw std::runtime_error("failed to build RSA key parameters");
    }
    std::unique_ptr<OSSL_PARAM, ParamDeleter> params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params) {
        throw std::runtime_error("failed to build RSA key parameters");
    }

    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr));
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
        throw std::runtime_error("failed to initialize RSA key context");
    }
    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw_key, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0 ||
        !raw_key) {
        throw std::invalid_argument("COSE RSA key: modulus/exponent is not a valid RSA public key");
    }
    return EvpPkeyPtr(raw_key);
}

} // namespace

EvpPkeyPtr parse_cose_public_key(const CborValue& cose_key, CoseAlgorithm* out_algorithm) {
    if (cose_key.kind != CborValue::Kind::Map) {
        throw std::invalid_argument("COSE key is not a CBOR map");
    }
    const auto* kty = cbor_map_find_int(cose_key, kCoseKty);
    const auto* alg = cbor_map_find_int(cose_key, kCoseAlg);
    if (!kty || !alg) {
        throw std::invalid_argument("COSE key missing kty/alg");
    }
    const auto kty_value = cbor_to_int64(*kty);
    const auto alg_value = cbor_to_int64(*alg);

    if (kty_value == kKtyEc2 && alg_value == kAlgEs256) {
        const auto* crv = cbor_map_find_int(cose_key, kCoseCrv);
        if (!crv || cbor_to_int64(*crv) != kCrvP256) {
            throw std::invalid_argument("COSE EC2 key: only the P-256 curve is supported");
        }
        auto key = build_ec_p256_public_key(require_bytes(cose_key, kCoseX, "x"),
                                             require_bytes(cose_key, kCoseY, "y"));
        if (out_algorithm) {
            *out_algorithm = CoseAlgorithm::ES256;
        }
        return key;
    }
    if (kty_value == kKtyRsa && alg_value == kAlgRs256) {
        auto key = build_rsa_public_key(require_bytes(cose_key, kCoseN, "n"),
                                         require_bytes(cose_key, kCoseE, "e"));
        if (out_algorithm) {
            *out_algorithm = CoseAlgorithm::RS256;
        }
        return key;
    }
    throw std::invalid_argument("unsupported COSE key type/algorithm combination (only ES256 "
                                 "P-256 and RS256 are supported)");
}

bool verify_cose_signature(EVP_PKEY* public_key, CoseAlgorithm /*algorithm*/,
                            const std::vector<std::uint8_t>& signed_data,
                            const std::vector<std::uint8_t>& signature) {
    // Both supported algorithms (ES256, RS256) sign over SHA-256; the
    // signature encoding difference (DER ECDSA vs. PKCS#1 v1.5) is handled
    // transparently by EVP_DigestVerify based on the key type.
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) {
        return false;
    }
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, public_key) <= 0) {
        return false;
    }
    return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), signed_data.data(),
                             signed_data.size()) == 1;
}

} // namespace atomwall
