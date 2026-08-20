#include "auth/user_store.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <yaml-cpp/yaml.h>

#include "auth/password_hash.hpp"

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

void UserStore::create(const std::string& username, const std::string& password) {
    if (username.empty()) {
        throw std::invalid_argument("username must not be empty");
    }
    if (password.size() < 8) {
        throw std::invalid_argument("password must be at least 8 characters");
    }

    std::lock_guard lock(mutex_);
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
        list.push_back(node);
    }
    root["users"] = list;

    if (auto parent = fs::path(path_).parent_path(); !parent.empty()) {
        fs::create_directories(parent);
    }
    const auto tmp_path = path_ + ".tmp";
    {
        std::ofstream file(tmp_path, std::ios::trunc);
        if (!file) {
            throw std::runtime_error("cannot write " + tmp_path);
        }
        YAML::Emitter emitter;
        emitter << root;
        file << emitter.c_str();
    }
    fs::rename(tmp_path, path_);
}

} // namespace atomwall
