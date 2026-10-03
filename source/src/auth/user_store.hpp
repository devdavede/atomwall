#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "auth/backup_codes.hpp"

namespace atomwall {

// Absence (UserRecord::totp == nullopt) means TOTP is not enrolled. A secret
// only ever lands here once confirmed with a live code — see
// AppState::pending_totp / handle_auth_2fa_totp_confirm in admin_server.cpp
// for the "generated but not yet confirmed" in-memory holding state, which
// deliberately never touches disk.
struct TotpConfig {
    std::string secret_base32;
};

// A registered passkey (WebAuthn credential). `cose_public_key` is the raw
// COSE_Key CBOR bytes exactly as extracted from authenticatorData at
// registration — re-parsed (via cbor_reader/cose_key) each time a signature
// needs verifying, rather than converted to some OpenSSL-specific storage
// format, so the persisted form stays spec-faithful and portable.
struct WebAuthnCredential {
    std::string id_b64url;
    std::string label;
    std::vector<std::uint8_t> cose_public_key;
    std::uint32_t sign_count = 0;
    std::chrono::system_clock::time_point created_at;
};

struct UserRecord {
    std::string username;
    std::string salt_hex;
    std::string hash_hex;
    int iterations = 0;
    std::chrono::system_clock::time_point created_at;
    std::optional<TotpConfig> totp;
    std::vector<BackupCode> backup_codes;
    std::vector<WebAuthnCredential> webauthn_credentials;
    // Stable, non-PII random 32-byte handle (base64url) WebAuthn's spec
    // requires as `user.id` at registration — generated lazily on first
    // passkey registration, never derived from the username itself.
    std::optional<std::string> webauthn_user_handle_b64;
};

// Persisted (YAML, atomic writes) list of admin accounts. Passwords are never
// stored or returned in plaintext — see auth/password_hash.hpp.
class UserStore {
public:
    explicit UserStore(std::string path);

    void load();

    bool empty() const;
    std::vector<UserRecord> list() const;
    std::optional<UserRecord> find(const std::string& username) const;

    // Throws std::invalid_argument on an empty/duplicate username or a
    // too-short password.
    void create(const std::string& username, const std::string& password);

    // Same validation as create(), but only adds the user if the store is
    // still empty, checked and inserted under one lock acquisition. Returns
    // false (adding nothing) if any user already exists. For the first-run
    // setup endpoint: an empty() check followed by a separate create() lets
    // two concurrent requests both see "empty" and both become admins.
    bool create_if_empty(const std::string& username, const std::string& password);

    // Throws std::invalid_argument if this would remove the last remaining
    // user (never allow locking everyone out). Returns false if not found.
    bool remove(const std::string& username);

    // --- second factors ------------------------------------------------

    bool has_second_factor(const std::string& username) const;

    // Activates TOTP + stores the hashed backup codes in one atomic update
    // (never a half-enrolled state: a secret with no backup codes, or vice
    // versa). Throws std::invalid_argument if the user doesn't exist.
    void set_totp(const std::string& username, const std::string& secret_base32,
                  const std::vector<std::string>& backup_code_plaintexts);

    // Removes TOTP and every backup code. Throws if the user doesn't exist.
    void clear_totp(const std::string& username);

    // Replaces the backup code list with a fresh set of 10, returned in
    // plaintext for one-time display. Throws if the user doesn't exist or
    // has no active TOTP enrollment (backup codes only make sense alongside it).
    std::vector<std::string> regenerate_backup_codes(const std::string& username);

    // Marks the first matching unused backup code consumed and persists the
    // change. False if the user doesn't exist or no code matches.
    bool consume_backup_code(const std::string& username, const std::string& candidate);

    // Anti-replay for TOTP: returns true and records `step` as this user's
    // newest accepted step iff `step` is strictly greater than whatever was
    // last recorded for them (or nothing was recorded yet) — false means
    // "already used, reject this login." verify_totp's ±1-step drift window
    // means a single valid code is checkable against up to three step
    // values; without this, any one of those three time-steps' codes could
    // otherwise be replayed by a second party for the ~90s the window is
    // open (see totp.hpp's `matched_step` out-param, which callers pass
    // straight into this). In-memory only, not persisted — same "lost on
    // restart" tradeoff as every other short-lived auth state in this
    // codebase (SessionStore, PendingMfaStore, ...); a restart narrowing the
    // replay window back open for a few seconds is an acceptable cost for
    // not persisting more state than a session token already requires.
    bool consume_totp_step(const std::string& username, std::int64_t step);

    // --- passkeys (WebAuthn) --------------------------------------------

    // Returns the user's stable WebAuthn user handle, generating and
    // persisting a fresh random one on first call. Throws if the user
    // doesn't exist.
    std::string webauthn_user_handle(const std::string& username);

    // Throws if the user doesn't exist.
    void add_webauthn_credential(const std::string& username, WebAuthnCredential credential);

    // Returns false if the user or that credential ID doesn't exist.
    bool remove_webauthn_credential(const std::string& username, const std::string& credential_id_b64url);

    // No-op (not an error) if the user or that credential ID doesn't exist —
    // called after a successful assertion, where failing loudly over a
    // bookkeeping update would be worse than just not updating the counter.
    void update_webauthn_sign_count(const std::string& username, const std::string& credential_id_b64url,
                                     std::uint32_t new_sign_count);

    // Scans every user's credentials (admin-only user counts, not hot path).
    // Used by the passwordless/discoverable-credential login flow, which
    // doesn't know the username until the assertion names a credential ID.
    std::optional<UserRecord> find_by_credential_id(const std::string& credential_id_b64url) const;

private:
    void add_user_locked(const std::string& username, const std::string& password);
    void save_locked() const;

    std::string path_;
    mutable std::mutex mutex_;
    std::vector<UserRecord> users_;
    std::unordered_map<std::string, std::int64_t> last_totp_step_;
};

} // namespace atomwall
