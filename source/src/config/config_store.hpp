#pragma once

#include <condition_variable>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>

#include "config/runtime_config.hpp"

namespace atomwall {

// Thread-safe holder for the single YAML-backed RuntimeConfig. Readers get a
// shared_ptr<const RuntimeConfig> snapshot that never changes underneath them;
// writers (admin API mutations, or external file edits picked up by polling)
// publish a whole new snapshot atomically.
class ConfigStore {
public:
    explicit ConfigStore(std::string path);
    ~ConfigStore();

    // Loads from disk, writing out a default config file first if none exists.
    // Throws on unrecoverable errors (bad YAML, unwritable path).
    void load_or_create();

    std::shared_ptr<const RuntimeConfig> get() const;

    // The config file path this store was constructed with — used to derive
    // sibling paths (users.yaml, uploaded geoip .mmdb) relative to it.
    const std::string& path() const { return path_; }

    // Applies `mutator` to a copy of the current config and publishes it as
    // the new current snapshot — get() sees it immediately after this
    // returns. Throws if the mutator throws (e.g. validation failure); the
    // published config is left unchanged in that case.
    //
    // Persisting to disk does NOT happen inline here — see writer_loop().
    // With a large blacklist that write can take seconds (rewriting the
    // whole YAML file), and blocking the admin API's response on it turned
    // a single mutation into a multi-minute hang under real load (this is
    // not hypothetical — it happened). The in-memory snapshot is always
    // authoritative for readers; disk just catches up shortly after.
    void update(const std::function<void(RuntimeConfig&)>& mutator);

    // Call periodically; reloads from disk if the file's mtime changed since
    // the last load/update, so hand-edits to the YAML file take effect without
    // a restart.
    void poll_for_external_changes();

private:
    void write_to_disk(const RuntimeConfig& config);
    // Runs on writer_thread_: blocks on writer_cv_ for a new snapshot to
    // persist, writes it, and loops. Multiple update() calls in quick
    // succession collapse onto whatever is the newest snapshot when this
    // thread next picks up work — every intermediate state in between is
    // legitimately fine to skip, since only the final one needs to reach
    // disk. Drains any last pending snapshot before exiting on shutdown.
    void writer_loop();

    std::string path_;
    mutable std::shared_mutex mutex_;
    std::shared_ptr<const RuntimeConfig> current_;
    std::filesystem::file_time_type last_mtime_{};
    // Serializes the read-mutate-swap sequence in update() across concurrent
    // admin API requests, so two mutations landing at once can't both read
    // the same stale `current_` and silently clobber each other's change.
    // Cheap to hold now that it no longer wraps the disk write.
    std::mutex write_mutex_;

    // Background disk persistence — see writer_loop().
    std::mutex writer_mutex_;
    std::condition_variable writer_cv_;
    std::shared_ptr<const RuntimeConfig> pending_write_; // null = nothing to do
    bool stop_ = false;
    std::thread writer_thread_;
};

} // namespace atomwall
