#include "auth/user_store.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <yaml-cpp/yaml.h>

#include "auth/backup_codes.hpp"
#include "auth/base64url.hpp"
#include "auth/password_hash.hpp"
#include "util/atomic_file.hpp"

namespace atomwall {

namespace fs = std::filesystem;

UserStore::UserStore(std::string path) : path_(std::move(path)) {}

void UserStore::load() {
    std::lock_guard lock(mutex_);
    users_.clear();

    if (!fs::exists(path_)) {
        return;
    }

    std::ifstream file(path_);
    std::ostringstream buffer;
    buffer << file.rdbuf();

    YAML::Node root = YAML::Load(buffer.str());
    auto list = root["users"];
    if (!list) {
        return;
    }
    for (const auto& node : list) {
        UserRecord user;
        user.username = node["username"].as<std::string>();
        user.salt_hex = node["salt"].as<std::string>();
        user.hash_hex = node["hash"].as<std::string>();
        user.iterations = node["iterations"].as<int>();
        user.created_at = std::chrono::system_clock::time_point(
            std::chrono::seconds(node["created_at_epoch"].as<long long>()));
        if (auto totp_node = node["totp"]) {
            TotpConfig totp;
            totp.secret_base32 = totp_node["secret_base32"].as<std::string>();
            user.totp = std::move(totp);
        }
        if (auto codes_node = node["backup_codes"]) {
            for (const auto& code_node : codes_node) {
                BackupCode code;
                code.hash.salt_hex = code_node["salt"].as<std::string>();
                code.hash.hash_hex = code_node["hash"].as<std::string>();
                code.hash.iterations = code_node["iterations"].as<int>();
                code.used = code_node["used"].as<bool>(false);
                user.backup_codes.push_back(std::move(code));
            }
        }
        if (auto handle_node = node["webauthn_user_handle"]) {
            user.webauthn_user_handle_b64 = handle_node.as<std::string>();
        }
        if (auto creds_node = node["webauthn_credentials"]) {
            for (const auto& cred_node : creds_node) {
                WebAuthnCredential cred;
                cred.id_b64url = cred_node["id"].as<std::string>();
                cred.label = cred_node["label"].as<std::string>("");
                cred.cose_public_key = base64url_decode(cred_node["public_key"].as<std::string>());
                cred.sign_count = cred_node["sign_count"].as<std::uint32_t>(0);
                if (auto ts = cred_node["created_at_epoch"]) {
                    cred.created_at =
                        std::chrono::system_clock::time_point(std::chrono::seconds(ts.as<long long>()));
                }
                user.webauthn_credentials.push_back(std::move(cred));
            }
        }
        users_.push_back(std::move(user));
    }
}

bool UserStore::empty() const {
    std::lock_guard lock(mutex_);
    return users_.empty();
}

std::vector<UserRecord> UserStore::list() const {
    std::lock_guard lock(mutex_);
    return users_;
}

std::optional<UserRecord> UserStore::find(const std::string& username) const {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    return it == users_.end() ? std::nullopt : std::optional<UserRecord>(*it);
}

namespace {

void validate_new_credentials(const std::string& username, const std::string& password) {
    if (username.empty()) {
        throw std::invalid_argument("username must not be empty");
    }
    if (password.size() < 8) {
        throw std::invalid_argument("password must be at least 8 characters");
    }
}

} // namespace

void UserStore::add_user_locked(const std::string& username, const std::string& password) {
    if (std::any_of(users_.begin(), users_.end(),
                     [&](const UserRecord& u) { return u.username == username; })) {
        throw std::invalid_argument("username already exists");
    }

    auto hashed = hash_password(password);
    UserRecord user;
    user.username = username;
    user.salt_hex = hashed.salt_hex;
    user.hash_hex = hashed.hash_hex;
    user.iterations = hashed.iterations;
    user.created_at = std::chrono::system_clock::now();
    users_.push_back(std::move(user));
    save_locked();
}

void UserStore::create(const std::string& username, const std::string& password) {
    validate_new_credentials(username, password);
    std::lock_guard lock(mutex_);
    add_user_locked(username, password);
}

bool UserStore::create_if_empty(const std::string& username, const std::string& password) {
    validate_new_credentials(username, password);
    std::lock_guard lock(mutex_);
    if (!users_.empty()) {
        return false;
    }
    add_user_locked(username, password);
    return true;
}

bool UserStore::remove(const std::string& username) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        return false;
    }
    if (users_.size() == 1) {
        throw std::invalid_argument("cannot remove the last remaining admin user");
    }
    users_.erase(it);
    save_locked();
    return true;
}

bool UserStore::has_second_factor(const std::string& username) const {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    return it != users_.end() && (it->totp.has_value() || !it->webauthn_credentials.empty());
}

void UserStore::set_totp(const std::string& username, const std::string& secret_base32,
                          const std::vector<std::string>& backup_code_plaintexts) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        throw std::invalid_argument("user not found");
    }
    it->totp = TotpConfig{secret_base32};
    it->backup_codes = hash_backup_codes(backup_code_plaintexts);
    save_locked();
}

void UserStore::clear_totp(const std::string& username) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        throw std::invalid_argument("user not found");
    }
    it->totp.reset();
    it->backup_codes.clear();
    save_locked();
}

std::vector<std::string> UserStore::regenerate_backup_codes(const std::string& username) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        throw std::invalid_argument("user not found");
    }
    if (!it->totp) {
        throw std::invalid_argument("TOTP is not enabled for this user");
    }
    auto plaintext = generate_backup_codes();
    it->backup_codes = hash_backup_codes(plaintext);
    save_locked();
    return plaintext;
}

bool UserStore::consume_backup_code(const std::string& username, const std::string& candidate) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        return false;
    }
    if (!atomwall::consume_backup_code(it->backup_codes, candidate)) {
        return false;
    }
    save_locked();
    return true;
}

bool UserStore::consume_totp_step(const std::string& username, std::int64_t step) {
    std::lock_guard lock(mutex_);
    auto it = last_totp_step_.find(username);
    if (it != last_totp_step_.end() && step <= it->second) {
        return false;
    }
    last_totp_step_[username] = step;
    return true;
}

std::string UserStore::webauthn_user_handle(const std::string& username) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        throw std::invalid_argument("user not found");
    }
    if (!it->webauthn_user_handle_b64) {
        std::vector<unsigned char> handle(32);
        if (!RAND_bytes(handle.data(), static_cast<int>(handle.size()))) {
            throw std::runtime_error("RAND_bytes failed");
        }
        it->webauthn_user_handle_b64 =
            base64url_encode(std::vector<std::uint8_t>(handle.begin(), handle.end()));
        save_locked();
    }
    return *it->webauthn_user_handle_b64;
}

void UserStore::add_webauthn_credential(const std::string& username, WebAuthnCredential credential) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        throw std::invalid_argument("user not found");
    }
    it->webauthn_credentials.push_back(std::move(credential));
    save_locked();
}

bool UserStore::remove_webauthn_credential(const std::string& username,
                                            const std::string& credential_id_b64url) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        return false;
    }
    auto cred_it = std::find_if(
        it->webauthn_credentials.begin(), it->webauthn_credentials.end(),
        [&](const WebAuthnCredential& c) { return c.id_b64url == credential_id_b64url; });
    if (cred_it == it->webauthn_credentials.end()) {
        return false;
    }
    it->webauthn_credentials.erase(cred_it);
    save_locked();
    return true;
}

void UserStore::update_webauthn_sign_count(const std::string& username,
                                            const std::string& credential_id_b64url,
                                            std::uint32_t new_sign_count) {
    std::lock_guard lock(mutex_);
    auto it = std::find_if(users_.begin(), users_.end(),
                            [&](const UserRecord& u) { return u.username == username; });
    if (it == users_.end()) {
        return;
    }
    auto cred_it = std::find_if(
        it->webauthn_credentials.begin(), it->webauthn_credentials.end(),
        [&](const WebAuthnCredential& c) { return c.id_b64url == credential_id_b64url; });
    if (cred_it == it->webauthn_credentials.end()) {
        return;
    }
    cred_it->sign_count = new_sign_count;
    save_locked();
}

std::optional<UserRecord> UserStore::find_by_credential_id(const std::string& credential_id_b64url) const {
    std::lock_guard lock(mutex_);
    for (const auto& user : users_) {
        auto cred_it = std::find_if(
            user.webauthn_credentials.begin(), user.webauthn_credentials.end(),
            [&](const WebAuthnCredential& c) { return c.id_b64url == credential_id_b64url; });
        if (cred_it != user.webauthn_credentials.end()) {
            return user;
        }
    }
    return std::nullopt;
}

void UserStore::save_locked() const {
    YAML::Node root;
    YAML::Node list(YAML::NodeType::Sequence);
    for (const auto& user : users_) {
        YAML::Node node;
        node["username"] = user.username;
        node["salt"] = user.salt_hex;
        node["hash"] = user.hash_hex;
        node["iterations"] = user.iterations;
        node["created_at_epoch"] = static_cast<long long>(
            std::chrono::duration_cast<std::chrono::seconds>(user.created_at.time_since_epoch())
                .count());
        if (user.totp) {
            node["totp"]["secret_base32"] = user.totp->secret_base32;
        }
        if (!user.backup_codes.empty()) {
            YAML::Node codes(YAML::NodeType::Sequence);
            for (const auto& code : user.backup_codes) {
                YAML::Node code_node;
                code_node["salt"] = code.hash.salt_hex;
                code_node["hash"] = code.hash.hash_hex;
                code_node["iterations"] = code.hash.iterations;
                code_node["used"] = code.used;
                codes.push_back(code_node);
            }
            node["backup_codes"] = codes;
        }
        if (user.webauthn_user_handle_b64) {
            node["webauthn_user_handle"] = *user.webauthn_user_handle_b64;
        }
        if (!user.webauthn_credentials.empty()) {
            YAML::Node creds(YAML::NodeType::Sequence);
            for (const auto& cred : user.webauthn_credentials) {
                YAML::Node cred_node;
                cred_node["id"] = cred.id_b64url;
                cred_node["label"] = cred.label;
                cred_node["public_key"] = base64url_encode(cred.cose_public_key);
                cred_node["sign_count"] = cred.sign_count;
                cred_node["created_at_epoch"] = static_cast<long long>(
                    std::chrono::duration_cast<std::chrono::seconds>(cred.created_at.time_since_epoch())
                        .count());
                creds.push_back(cred_node);
            }
            node["webauthn_credentials"] = creds;
        }
        list.push_back(node);
    }
    root["users"] = list;

    if (auto parent = fs::path(path_).parent_path(); !parent.empty()) {
        fs::create_directories(parent);
    }
    YAML::Emitter emitter;
    emitter << root;
    write_file_atomically(path_, emitter.c_str(), 0600, ExistingFileMode::Reset);
}

} // namespace atomwall
