#include <catch2/catch_test_macros.hpp>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util/atomic_file.hpp"

using namespace atomwall;
namespace fs = std::filesystem;

namespace {

fs::path fresh_dir() {
    auto dir = fs::temp_directory_path() / ("atomwall_atomic_" + std::to_string(std::random_device{}()));
    fs::create_directories(dir);
    return dir;
}

std::string slurp(const fs::path& path) {
    std::ifstream in(path);
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

mode_t mode_of(const fs::path& path) {
    struct stat st {};
    REQUIRE(::stat(path.c_str(), &st) == 0);
    return st.st_mode & 07777;
}

} // namespace

TEST_CASE("write_file_atomically creates the file with the requested restrictive mode", "[atomic_file]") {
    const auto path = fresh_dir() / "out.yaml";
    write_file_atomically(path.string(), "hello: world\n", 0600);
    CHECK(slurp(path) == "hello: world\n");
    CHECK(mode_of(path) == 0600);
    CHECK_FALSE(fs::exists(path.string() + ".tmp"));
}

TEST_CASE("write_file_atomically ignores a permissive umask", "[atomic_file]") {
    const auto previous = ::umask(0);
    const auto path = fresh_dir() / "out.yaml";
    write_file_atomically(path.string(), "x", 0600);
    ::umask(previous);
    CHECK(mode_of(path) == 0600);
}

TEST_CASE("Reset tightens an existing file's permissions; Preserve keeps them", "[atomic_file]") {
    const auto dir = fresh_dir();
    const auto secret = dir / "users.yaml";
    { std::ofstream(secret) << "old"; }
    ::chmod(secret.c_str(), 0644);
    write_file_atomically(secret.string(), "new", 0600, ExistingFileMode::Reset);
    CHECK(slurp(secret) == "new");
    CHECK(mode_of(secret) == 0600);

    const auto config = dir / "atomwall.yaml";
    { std::ofstream(config) << "old"; }
    ::chmod(config.c_str(), 0640);
    write_file_atomically(config.string(), "new", 0600, ExistingFileMode::Preserve);
    CHECK(slurp(config) == "new");
    CHECK(mode_of(config) == 0640);

    const auto created = dir / "fresh.yaml";
    write_file_atomically(created.string(), "new", 0600, ExistingFileMode::Preserve);
    CHECK(mode_of(created) == 0600);
}

TEST_CASE("write_file_atomically leaves the existing file untouched when the write fails", "[atomic_file]") {
    const auto path = fresh_dir() / "atomwall.yaml";
    write_file_atomically(path.string(), "good config\n", 0600);

    // A file-size limit makes write() fail partway through, the same shape as a
    // full disk: the old code renamed the truncated temp file over the good one.
    auto* previous_handler = std::signal(SIGXFSZ, SIG_IGN);
    rlimit original{};
    REQUIRE(getrlimit(RLIMIT_FSIZE, &original) == 0);
    rlimit tiny = original;
    tiny.rlim_cur = 8;
    REQUIRE(setrlimit(RLIMIT_FSIZE, &tiny) == 0);

    CHECK_THROWS_AS(write_file_atomically(path.string(), std::string(4096, 'x'), 0600), std::runtime_error);

    setrlimit(RLIMIT_FSIZE, &original);
    std::signal(SIGXFSZ, previous_handler);

    CHECK(slurp(path) == "good config\n");
    CHECK_FALSE(fs::exists(path.string() + ".tmp"));
}

TEST_CASE("write_file_atomically throws and leaves nothing behind when the directory is missing", "[atomic_file]") {
    const auto path = fresh_dir() / "missing" / "out.yaml";
    CHECK_THROWS_AS(write_file_atomically(path.string(), "x", 0600), std::runtime_error);
}
