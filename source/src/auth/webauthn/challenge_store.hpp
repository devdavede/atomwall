#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace atomwall {

// Holds an in-flight WebAuthn challenge between issuing
// PublicKeyCredentialCreationOptions/RequestOptions and verifying the
// browser's response. `key` is whatever the caller already has on hand to
// scope the ceremony:
//   - a username, for registration (already-authenticated session) and the
//     "passkey as 2nd factor" login path (already has a pending-MFA username)
//   - a random per-attempt token delivered via its own cookie, for the
//     passwordless discoverable-credential login path, where the server
//     doesn't know the username until the assertion comes back
// In-memory, lost on restart — same pattern as every other short-lived auth
// state in this codebase (PendingMfaStore, PendingTotpStore, SessionStore).
//
// Unlike those, the passwordless-login key is handed out to *unauthenticated*
// callers, and an entry is only otherwise removed by a successful verify — so
// abandoned challenges must be reclaimed here or a plain GET flood grows the
// map without bound. start() drops expired entries (oldest first, amortized
// O(1) rather than a full scan per insert) and hard-caps the total, evicting
// the oldest, so memory stays bounded however fast challenges are requested.
class ChallengeStore {
public:
    static constexpr std::size_t kMaxEntries = 10'000;

    void start(const std::string& key, std::vector<std::uint8_t> challenge,
               std::chrono::minutes ttl = std::chrono::minutes(2));

    // Atomically takes the challenge out of the store: it's gone afterwards
    // whether or not it had expired, and whatever happens to the verification
    // it's used for. A WebAuthn challenge must be single-use — leaving it in
    // place until a *successful* verify (as a separate read + clear did) lets
    // it be retried until the TTL runs out, and lets two concurrent submissions
    // both read it before either clears it.
    std::optional<std::vector<std::uint8_t>> consume(const std::string& key);

    std::size_t size() const;

private:
    struct Entry {
        std::vector<std::uint8_t> challenge;
        std::chrono::system_clock::time_point expires_at;
    };

    // Insertion order, for cheap oldest-first expiry/eviction. May hold stale
    // stamps for keys since cleared or re-started; those are skipped when
    // popped (the map entry's expires_at won't match).
    struct Stamp {
        std::string key;
        std::chrono::system_clock::time_point expires_at;
    };

    mutable std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    std::deque<Stamp> order_;
};

} // namespace atomwall
