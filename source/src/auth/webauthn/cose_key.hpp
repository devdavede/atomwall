#pragma once

#include <memory>
#include <openssl/evp.h>
#include <vector>

#include "auth/webauthn/cbor_reader.hpp"

namespace atomwall {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

// COSE algorithm identifiers this codebase supports — ES256 (P-256 ECDSA) is
// what every platform authenticator (Touch ID, Windows Hello, Android) and
// modern security key offers; RS256 covers older FIDO U2F-era security keys
// that only speak RSA. Both sign over SHA-256, which is why
// verify_cose_signature() below hard-codes SHA-256 rather than taking it as
// a parameter.
enum class CoseAlgorithm { ES256, RS256 };

// Parses a COSE_Key CBOR map (RFC 9053) into an EVP_PKEY public key. Throws
// std::invalid_argument for anything malformed, unsupported (any algorithm/
// curve other than ES256/RS256+P-256), or structurally inconsistent — this
// runs on attacker-supplied registration data before any trust has been
// established in the credential, so it never guesses or falls back.
EvpPkeyPtr parse_cose_public_key(const CborValue& cose_key, CoseAlgorithm* out_algorithm);

// Verifies `signature` (DER-encoded ECDSA for ES256, PKCS#1 v1.5 for RS256 —
// both exactly what OpenSSL's EVP_DigestVerify produces/expects by default
// for EC/RSA keys, and exactly what the WebAuthn spec requires an
// authenticator to produce) over `signed_data` using SHA-256.
bool verify_cose_signature(EVP_PKEY* public_key, CoseAlgorithm algorithm,
                            const std::vector<std::uint8_t>& signed_data,
                            const std::vector<std::uint8_t>& signature);

} // namespace atomwall
