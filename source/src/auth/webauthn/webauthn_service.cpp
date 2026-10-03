#include "auth/webauthn/webauthn_service.hpp"

#include <algorithm>
#include <array>
#include <boost/json.hpp>
#include <openssl/evp.h>
#include <stdexcept>
#include <string_view>

#include "auth/base64url.hpp"
#include "auth/webauthn/cbor_reader.hpp"
#include "auth/webauthn/cose_key.hpp"

namespace atomwall {

namespace json = boost::json;

namespace {

constexpr std::uint8_t kFlagUserPresent = 0x01;
constexpr std::uint8_t kFlagUserVerified = 0x04;
constexpr std::uint8_t kFlagAttestedCredentialData = 0x40;

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data) {
    std::array<std::uint8_t, 32> digest{};
    unsigned int len = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &len, EVP_sha256(), nullptr) != 1 ||
        len != digest.size()) {
        throw std::runtime_error("SHA-256 computation failed");
    }
    return digest;
}

std::array<std::uint8_t, 32> sha256(const std::string& data) {
    return sha256(std::vector<std::uint8_t>(data.begin(), data.end()));
}

// Fields common to both ceremonies' clientDataJSON (WebAuthn §5.8.1). Checked
// against the raw JSON text's own bytes for hashing (never a re-serialized
// copy — key order/whitespace must match exactly what the authenticator
// signed over) and parsed separately here only to read out these three
// fields.
void verify_client_data(const std::string& client_data_json,
                         const std::vector<std::uint8_t>& expected_challenge,
                         const std::string& expected_origin, std::string_view expected_type) {
    json::value parsed;
    try {
        parsed = json::parse(client_data_json);
    } catch (const std::exception&) {
        throw std::invalid_argument("clientDataJSON is not valid JSON");
    }
    if (!parsed.is_object()) {
        throw std::invalid_argument("clientDataJSON is not a JSON object");
    }
    const auto& obj = parsed.as_object();

    auto type_it = obj.find("type");
    if (type_it == obj.end() || !type_it->value().is_string() ||
        std::string(type_it->value().as_string()) != expected_type) {
        throw std::invalid_argument("clientDataJSON: unexpected \"type\"");
    }

    auto origin_it = obj.find("origin");
    if (origin_it == obj.end() || !origin_it->value().is_string() ||
        std::string(origin_it->value().as_string()) != expected_origin) {
        throw std::invalid_argument("clientDataJSON: origin does not match this server");
    }

    auto challenge_it = obj.find("challenge");
    if (challenge_it == obj.end() || !challenge_it->value().is_string()) {
        throw std::invalid_argument("clientDataJSON: missing challenge");
    }
    std::vector<std::uint8_t> challenge_bytes;
    try {
        challenge_bytes = base64url_decode(std::string(challenge_it->value().as_string()));
    } catch (const std::invalid_argument&) {
        throw std::invalid_argument("clientDataJSON: malformed challenge encoding");
    }
    if (challenge_bytes != expected_challenge) {
        throw std::invalid_argument("clientDataJSON: challenge does not match — expired or replayed?");
    }
}

struct ParsedAuthenticatorData {
    std::array<std::uint8_t, 32> rp_id_hash{};
    std::uint8_t flags = 0;
    std::uint32_t sign_count = 0;
    std::vector<std::uint8_t> credential_id;
    std::vector<std::uint8_t> cose_public_key; // raw bytes, present only if attested credential data was requested/found
};

// Parses the fixed-layout authenticatorData structure (WebAuthn §6.1) — NOT
// itself CBOR, aside from the credentialPublicKey embedded partway through
// when attested credential data is present. `require_attested_credential`
// is true for registrations (a new credential must be attested) and false
// for assertions (never present there).
ParsedAuthenticatorData parse_authenticator_data(const std::vector<std::uint8_t>& auth_data,
                                                  bool require_attested_credential) {
    constexpr std::size_t kFixedHeaderLen = 32 + 1 + 4; // rpIdHash + flags + signCount
    if (auth_data.size() < kFixedHeaderLen) {
        throw std::invalid_argument("authenticatorData is shorter than the fixed header");
    }

    ParsedAuthenticatorData out;
    std::copy(auth_data.begin(), auth_data.begin() + 32, out.rp_id_hash.begin());
    out.flags = auth_data[32];
    out.sign_count = (static_cast<std::uint32_t>(auth_data[33]) << 24) |
                      (static_cast<std::uint32_t>(auth_data[34]) << 16) |
                      (static_cast<std::uint32_t>(auth_data[35]) << 8) |
                      static_cast<std::uint32_t>(auth_data[36]);

    const bool has_attested = (out.flags & kFlagAttestedCredentialData) != 0;
    if (!require_attested_credential) {
        return out;
    }
    if (!has_attested) {
        throw std::invalid_argument("authenticatorData is missing attested credential data");
    }

    std::size_t offset = kFixedHeaderLen;
    constexpr std::size_t kAaguidLen = 16;
    constexpr std::size_t kCredIdLenFieldLen = 2;
    if (auth_data.size() < offset + kAaguidLen + kCredIdLenFieldLen) {
        throw std::invalid_argument("authenticatorData truncated before credentialId length");
    }
    offset += kAaguidLen; // aaguid itself isn't used for anything here
    const std::uint16_t cred_id_len = (static_cast<std::uint16_t>(auth_data[offset]) << 8) |
                                       static_cast<std::uint16_t>(auth_data[offset + 1]);
    offset += kCredIdLenFieldLen;
    if (auth_data.size() < offset + cred_id_len) {
        throw std::invalid_argument("authenticatorData truncated before end of credentialId");
    }
    out.credential_id.assign(auth_data.begin() + offset, auth_data.begin() + offset + cred_id_len);
    offset += cred_id_len;

    if (offset >= auth_data.size()) {
        throw std::invalid_argument("authenticatorData is missing the credential public key");
    }
    const std::vector<std::uint8_t> remaining(auth_data.begin() + offset, auth_data.end());
    const auto [cose_key_value, consumed] = parse_cbor_prefix(remaining);
    if (cose_key_value.kind != CborValue::Kind::Map) {
        throw std::invalid_argument("credential public key is not a COSE_Key map");
    }
    out.cose_public_key.assign(remaining.begin(), remaining.begin() + consumed);
    return out;
}

} // namespace

WebAuthnRegistrationResult verify_webauthn_registration(
    const std::vector<std::uint8_t>& expected_challenge, const std::string& client_data_json,
    const std::vector<std::uint8_t>& attestation_object, const std::string& rp_id,
    const std::string& expected_origin) {
    verify_client_data(client_data_json, expected_challenge, expected_origin, "webauthn.create");

    const auto attestation = parse_cbor(attestation_object);
    if (attestation.kind != CborValue::Kind::Map) {
        throw std::invalid_argument("attestationObject is not a CBOR map");
    }
    const auto* auth_data_field = cbor_map_find_text(attestation, "authData");
    if (!auth_data_field || auth_data_field->kind != CborValue::Kind::Bytes) {
        throw std::invalid_argument("attestationObject is missing authData");
    }

    const auto parsed = parse_authenticator_data(auth_data_field->bytes, /*require_attested=*/true);

    if (parsed.rp_id_hash != sha256(rp_id)) {
        throw std::invalid_argument("authenticatorData: RP ID hash does not match this server");
    }
    if ((parsed.flags & kFlagUserPresent) == 0) {
        throw std::invalid_argument("authenticatorData: user-presence flag not set");
    }

    // Structural validation only — confirms the stored bytes will parse back
    // into a supported key later, without needing a signature to check yet
    // (registration has no signature over the new key itself to verify).
    const auto cose_key = parse_cbor(parsed.cose_public_key);
    CoseAlgorithm algorithm{};
    parse_cose_public_key(cose_key, &algorithm);

    return WebAuthnRegistrationResult{
        base64url_encode(parsed.credential_id),
        parsed.cose_public_key,
        parsed.sign_count,
        (parsed.flags & kFlagUserVerified) != 0,
    };
}

WebAuthnAssertionResult verify_webauthn_authentication(
    const std::vector<std::uint8_t>& expected_challenge, const std::string& client_data_json,
    const std::vector<std::uint8_t>& authenticator_data, const std::vector<std::uint8_t>& signature,
    const std::vector<std::uint8_t>& stored_cose_public_key, std::uint32_t stored_sign_count,
    const std::string& rp_id, const std::string& expected_origin) {
    verify_client_data(client_data_json, expected_challenge, expected_origin, "webauthn.get");

    const auto parsed = parse_authenticator_data(authenticator_data, /*require_attested=*/false);
    if (parsed.rp_id_hash != sha256(rp_id)) {
        throw std::invalid_argument("authenticatorData: RP ID hash does not match this server");
    }
    if ((parsed.flags & kFlagUserPresent) == 0) {
        throw std::invalid_argument("authenticatorData: user-presence flag not set");
    }

    const auto client_data_hash = sha256(client_data_json);
    std::vector<std::uint8_t> signed_data = authenticator_data;
    signed_data.insert(signed_data.end(), client_data_hash.begin(), client_data_hash.end());

    const auto cose_key = parse_cbor(stored_cose_public_key);
    CoseAlgorithm algorithm{};
    auto public_key = parse_cose_public_key(cose_key, &algorithm);
    if (!verify_cose_signature(public_key.get(), algorithm, signed_data, signature)) {
        throw std::invalid_argument("signature verification failed");
    }

    // Both zero means this authenticator has never reported a counter at all
    // (the norm for synced/platform passkeys, per WebAuthn Level 2 §6.1.1) —
    // treated as "counter not supported," not as a replay. Any other
    // non-increase is a real signal of a possibly-cloned authenticator.
    if (!(stored_sign_count == 0 && parsed.sign_count == 0) &&
        parsed.sign_count <= stored_sign_count) {
        throw std::invalid_argument(
            "sign counter did not increase — possible cloned authenticator");
    }

    return WebAuthnAssertionResult{parsed.sign_count, (parsed.flags & kFlagUserVerified) != 0};
}

} // namespace atomwall
