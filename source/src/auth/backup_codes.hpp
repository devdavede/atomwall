#pragma once

#include <string>
#include <vector>

#include "auth/password_hash.hpp"

namespace atomwall {

// A single-use TOTP recovery code, hashed at rest exactly like a password
// (see password_hash.hpp) — a backup code IS a (short-lived-by-design,
// single-use) password, so it reuses the same PBKDF2 machinery rather than
// inventing a second hashing scheme.
struct BackupCode {
    PasswordHash hash;
    bool used = false;
};

// 10 codes of the form "XXXX-XXXX" using an alphabet with ambiguous
// characters (0/O, 1/I/L) removed, since these are meant to be hand-typed
// from a printed/saved copy.
std::vector<std::string> generate_backup_codes(int count = 10);

std::vector<BackupCode> hash_backup_codes(const std::vector<std::string>& plaintext_codes);

// Finds the first unused code matching `candidate` and marks it used in
// `codes` (in place). Returns true on success. Always compares against every
// remaining unused code (no early return on the first hash mismatch) so
// timing doesn't reveal which position, if any, was close to matching.
bool consume_backup_code(std::vector<BackupCode>& codes, const std::string& candidate);

} // namespace atomwall
