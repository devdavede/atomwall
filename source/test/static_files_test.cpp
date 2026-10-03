#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <fstream>
#include <random>

#include "admin/static_files.hpp"

using namespace atomwall;
namespace fs = std::filesystem;

namespace {

struct Site {
    fs::path base = fs::temp_directory_path() / ("atomwall_static_" + std::to_string(std::random_device{}()));
    fs::path root = base / "site";
    fs::path sibling = base / "site_evil"; // shares "site" as a string prefix

    Site() {
        fs::create_directories(root / "vendor");
        fs::create_directories(sibling);
        write(root / "index.html", "home");
        write(root / "app.js", "js");
        write(root / "vendor" / "lib.js", "lib");
        write(sibling / "secret.txt", "secret");
        write(base / "outside.txt", "outside");
    }
    static void write(const fs::path& path, const char* text) { std::ofstream(path) << text; }
    std::optional<fs::path> resolve(std::string_view target) const { return resolve_static_path(root, target); }
};

} // namespace

TEST_CASE("resolve_static_path serves files inside the root", "[static_files]") {
    Site site;
    CHECK(site.resolve("/app.js") == fs::weakly_canonical(site.root / "app.js"));
    CHECK(site.resolve("/vendor/lib.js") == fs::weakly_canonical(site.root / "vendor" / "lib.js"));
    CHECK(site.resolve("/app.js?v=3") == fs::weakly_canonical(site.root / "app.js"));
    CHECK(site.resolve("/") == fs::weakly_canonical(site.root / "index.html"));
    CHECK(site.resolve("//vendor//lib.js") == fs::weakly_canonical(site.root / "vendor" / "lib.js"));
}

TEST_CASE("resolve_static_path rejects missing files and directories", "[static_files]") {
    Site site;
    CHECK_FALSE(site.resolve("/nope.js").has_value());
    CHECK_FALSE(site.resolve("/vendor").has_value());
}

TEST_CASE("resolve_static_path rejects traversal, however it's spelled", "[static_files]") {
    Site site;
    for (const char* target : {"/../outside.txt", "/vendor/../../outside.txt", "/%2e%2e/outside.txt",
                                "/%2E%2E/outside.txt", "/vendor/%2e%2e/%2e%2e/outside.txt",
                                "/..%2foutside.txt", "/%2e%2e%2foutside.txt", "/../site_evil/secret.txt"}) {
        INFO(target);
        CHECK_FALSE(site.resolve(target).has_value());
    }
}

TEST_CASE("resolve_static_path rejects an embedded NUL rather than letting the OS truncate at it",
          "[static_files]") {
    Site site;
    // POSIX calls stop at the NUL, so "app.js%00.png" would name app.js while
    // looking like a .png (or any extension) to everything that inspects the string.
    CHECK_FALSE(site.resolve("/app.js%00.png").has_value());
    CHECK_FALSE(site.resolve("/vendor/%00").has_value());
    CHECK_FALSE(site.resolve("/%00").has_value());
}

TEST_CASE("resolve_static_path refuses a symlink that escapes the root", "[static_files]") {
    Site site;
    fs::create_symlink(site.base / "outside.txt", site.root / "link.txt");
    CHECK_FALSE(site.resolve("/link.txt").has_value());
}

TEST_CASE("resolve_static_path refuses a symlink into a sibling directory sharing the root's name prefix",
          "[static_files]") {
    Site site;
    // The root is ".../site"; this resolves to ".../site_evil/secret.txt", which
    // starts with the root's *string* but isn't inside it.
    fs::create_directory_symlink(site.sibling, site.root / "linked");
    CHECK_FALSE(site.resolve("/linked/secret.txt").has_value());
}

TEST_CASE("resolve_static_path allows a symlink that stays inside the root", "[static_files]") {
    Site site;
    fs::create_symlink(site.root / "app.js", site.root / "alias.js");
    CHECK(site.resolve("/alias.js") == fs::weakly_canonical(site.root / "app.js"));
}
