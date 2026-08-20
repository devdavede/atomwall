#include "config/config_store.hpp"

#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>
#include <stdexcept>

#include "config/yaml_codec.hpp"

namespace atomwall {

namespace fs = std::filesystem;

ConfigStore::ConfigStore(std::string path) : path_(std::move(path)) {
    writer_thread_ = std::thread(&ConfigStore::writer_loop, this);
}

ConfigStore::~ConfigStore() {
    {
        std::lock_guard lock(writer_mutex_);
        stop_ = true;
    }
    writer_cv_.notify_one();
    writer_thread_.join();
}

void ConfigStore::load_or_create() {
    if (!fs::exists(path_)) {
        spdlog::info("config: no file at {}, writing defaults", path_);
        if (auto parent = fs::path(path_).parent_path(); !parent.empty()) {
            fs::create_directories(parent);
        }
        write_to_disk(RuntimeConfig{});
    }

    std::ifstream file(path_);
    if (!file) {
        throw std::runtime_error("config: cannot open " + path_);
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();

    auto config = std::make_shared<RuntimeConfig>(parse_yaml_config(buffer.str()));

    std::unique_lock lock(mutex_);
    current_ = std::move(config);
    last_mtime_ = fs::last_write_time(path_);
}

std::shared_ptr<const RuntimeConfig> ConfigStore::get() const {
    std::shared_lock lock(mutex_);
    return current_;
}

void ConfigStore::update(const std::function<void(RuntimeConfig&)>& mutator) {
    // Holds for the whole read-mutate-swap sequence — see write_mutex_'s doc
    // comment for why concurrent update() calls need this even though it no
    // longer wraps the (now-async) disk write.
    std::lock_guard write_lock(write_mutex_);

    RuntimeConfig updated;
    {
        std::shared_lock lock(mutex_);
        updated = *current_;
    }
    mutator(updated);

    auto snapshot = std::make_shared<const RuntimeConfig>(std::move(updated));
    {
        std::unique_lock lock(mutex_);
        current_ = snapshot;
        // last_mtime_ is deliberately left alone here — it's only meaningful
        // once this snapshot actually lands on disk (writer_loop updates it
        // after a successful write), otherwise poll_for_external_changes
        // would see path_'s on-disk mtime lagging behind and mistake our own
        // not-yet-persisted change for an external edit to reload.
    }

    {
        std::lock_guard wlock(writer_mutex_);
        pending_write_ = snapshot;
    }
    writer_cv_.notify_one();
}

void ConfigStore::poll_for_external_changes() {
    std::error_code ec;
    auto mtime = fs::last_write_time(path_, ec);
    if (ec) {
        return;
    }

    {
        std::shared_lock lock(mutex_);
        if (mtime == last_mtime_) {
            return;
        }
    }

    try {
        std::ifstream file(path_);
        std::ostringstream buffer;
        buffer << file.rdbuf();
        auto config = std::make_shared<const RuntimeConfig>(parse_yaml_config(buffer.str()));

        std::unique_lock lock(mutex_);
        current_ = std::move(config);
        last_mtime_ = mtime;
        spdlog::info("config: reloaded {} after external change", path_);
    } catch (const std::exception& e) {
        spdlog::warn("config: ignoring unparsable external edit to {}: {}", path_, e.what());
    }
}

void ConfigStore::write_to_disk(const RuntimeConfig& config) {
    const auto tmp_path = path_ + ".tmp";
    {
        std::ofstream file(tmp_path, std::ios::trunc);
        if (!file) {
            throw std::runtime_error("config: cannot write " + tmp_path);
        }
        file << to_yaml_config(config);
    }
    fs::rename(tmp_path, path_);
}

void ConfigStore::writer_loop() {
    for (;;) {
        std::shared_ptr<const RuntimeConfig> to_write;
        {
            std::unique_lock lock(writer_mutex_);
            writer_cv_.wait(lock, [this] { return stop_ || pending_write_ != nullptr; });
            if (!pending_write_ && stop_) {
                break;
            }
            to_write = std::move(pending_write_);
            pending_write_.reset();
        }

        try {
            write_to_disk(*to_write);
            std::unique_lock lock(mutex_);
            last_mtime_ = fs::last_write_time(path_);
        } catch (const std::exception& e) {
            spdlog::error("config: background persist to {} failed: {}", path_, e.what());
        }
    }
}

} // namespace atomwall
