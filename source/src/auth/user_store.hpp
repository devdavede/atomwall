#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace atomwall {

struct UserRecord {
    std::string username;
    std::string salt_hex;
    std::string hash_hex;
    int iterations = 0;
    std::chrono::system_clock::time_point created_at;
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

    // Throws std::invalid_argument if this would remove the last remaining
    // user (never allow locking everyone out). Returns false if not found.
    bool remove(const std::string& username);

private:
    void save_locked() const;

    std::string path_;
    mutable std::mutex mutex_;
    std::vector<UserRecord> users_;
};

} // namespace atomwall
