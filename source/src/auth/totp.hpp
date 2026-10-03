#pragma once

#include <cstdint>
#include <string>

namespace atomwall {

// RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30s step) — the de-facto format every
// authenticator app (Google/Microsoft Authenticator, 1Password, Authy, ...)
// expects; there's no practical reason to support SHA256/SHA512 variants
// here since no mainstream app defaults to them.
std::string generate_totp_secret_base32();

// Builds the otpauth:// URI an authenticator app scans (as a QR code) or
// accepts pasted in directly.
std::string totp_provisioning_uri(const std::string& secret_base32, const std::string& username,
                                   const std::string& issuer = "atomwall");

// Checks `code` against the current 30s step and one step of drift on either
// side (±30s), which absorbs ordinary clock skew between server and phone
// without meaningfully widening the guessing window.
//
// `matched_step`, if non-null, is set to the counter value that matched on
// success (left unchanged on failure). Callers that accept a code as proof
// of login MUST use this to reject replays — this function alone is a pure
// code check and does not track which steps have already been consumed; see
// UserStore::consume_totp_step, which callers pair this with.
bool verify_totp(const std::string& secret_base32, const std::string& code,
                  std::int64_t unix_time_seconds, std::int64_t* matched_step = nullptr);

} // namespace atomwall
