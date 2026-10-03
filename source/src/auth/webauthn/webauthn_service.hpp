#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace atomwall {

struct WebAuthnRegistrationResult {
    std::string credential_id_b64url;
    std::vector<std::uint8_t> cose_public_key; // raw COSE_Key CBOR bytes, persisted as-is
    std::uint32_t sign_count = 0;
    bool user_verified = false;
};

struct WebAuthnAssertionResult {
    std::uint32_t new_sign_count = 0;
    bool user_verified = false;
};

// Validates a WebAuthn registration ceremony (the response to
// navigator.credentials.create()) and extracts the new credential. Throws
// std::invalid_argument with a human-readable reason on any failure —
// wrong/expired challenge, origin mismatch, bad RP ID hash, malformed CBOR,
// unsupported key algorithm, missing user-presence flag, etc. Never verifies
// the attestation statement's trust chain (registration requests
// `attestation: "none"`): this is a
// deliberate scope cut rather than an oversight.
WebAuthnRegistrationResult verify_webauthn_registration(
    const std::vector<std::uint8_t>& expected_challenge, const std::string& client_data_json,
    const std::vector<std::uint8_t>& attestation_object, const std::string& rp_id,
    const std::string& expected_origin);

// Validates a WebAuthn authentication ceremony (the response to
// navigator.credentials.get()) against a previously-stored credential. Throws
// std::invalid_argument on any failure, including a non-increasing sign
// counter when the stored counter is nonzero (see webauthn_service.cpp for
// the zero/zero exception synced passkeys need).
WebAuthnAssertionResult verify_webauthn_authentication(
    const std::vector<std::uint8_t>& expected_challenge, const std::string& client_data_json,
    const std::vector<std::uint8_t>& authenticator_data, const std::vector<std::uint8_t>& signature,
    const std::vector<std::uint8_t>& stored_cose_public_key, std::uint32_t stored_sign_count,
    const std::string& rp_id, const std::string& expected_origin);

} // namespace atomwall
