#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <filesystem>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <random>
#include <thread>
#include <vector>

#include "listener/tls_site_contexts.hpp"

using namespace atomwall;
namespace fs = std::filesystem;

namespace {

struct FileCloser {
    void operator()(FILE* f) const { if (f) std::fclose(f); }
};
using FilePtr = std::unique_ptr<FILE, FileCloser>;

void write_self_signed(const fs::path& cert_path, const fs::path& key_path, const char* common_name) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_EC_gen("P-256"), EVP_PKEY_free);
    REQUIRE(pkey);
    std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
    REQUIRE(cert);
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    X509_set_pubkey(cert.get(), pkey.get());
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    REQUIRE(X509_sign(cert.get(), pkey.get(), EVP_sha256()) > 0);

    FilePtr cert_file(std::fopen(cert_path.c_str(), "w"));
    FilePtr key_file(std::fopen(key_path.c_str(), "w"));
    REQUIRE(cert_file);
    REQUIRE(key_file);
    REQUIRE(PEM_write_X509(cert_file.get(), cert.get()) == 1);
    REQUIRE(PEM_write_PrivateKey(key_file.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);
}

struct Env {
    fs::path dir = fs::temp_directory_path() / ("atomwall_tls_" + std::to_string(std::random_device{}()));
    Env() { fs::create_directories(dir); }

    SiteConfig site(const std::string& domain) {
        SiteConfig s;
        s.domain = domain;
        s.cert_file = (dir / (domain + ".crt")).string();
        s.key_file = (dir / (domain + ".key")).string();
        return s;
    }
    SiteConfig site_with_cert(const std::string& domain) {
        auto s = site(domain);
        write_self_signed(s.cert_file, s.key_file, domain.c_str());
        return s;
    }
};

std::shared_ptr<const RuntimeConfig> snapshot(std::vector<SiteConfig> sites) {
    RuntimeConfig config;
    config.sites = std::move(sites);
    return std::make_shared<const RuntimeConfig>(std::move(config));
}

} // namespace

TEST_CASE("TlsSiteContexts loads a context per site that has a usable cert", "[tls_site_contexts]") {
    Env env;
    SiteConfig no_cert;
    no_cert.domain = "plain.example";
    SiteConfig broken = env.site("broken.example"); // files don't exist
    TlsSiteContexts contexts;

    auto map = contexts.current(snapshot({env.site_with_cert("a.example"), no_cert, broken}));
    CHECK(map->size() == 1);
    CHECK(map->count("a.example") == 1);
}

TEST_CASE("TlsSiteContexts returns the same map for the same snapshot", "[tls_site_contexts]") {
    Env env;
    TlsSiteContexts contexts;
    auto config = snapshot({env.site_with_cert("a.example")});
    auto first = contexts.current(config);
    CHECK(contexts.current(config) == first);
}

TEST_CASE("TlsSiteContexts doesn't reload certs for an unrelated config change", "[tls_site_contexts]") {
    Env env;
    const auto site = env.site_with_cert("a.example");
    TlsSiteContexts contexts;
    auto first = contexts.current(snapshot({site}));

    RuntimeConfig changed;
    changed.sites = {site};
    changed.blacklist.user_agents = {BlacklistEntry{"sqlmap"}}; // e.g. an admin blocking a UA
    auto second = contexts.current(std::make_shared<const RuntimeConfig>(std::move(changed)));

    CHECK(second == first);
}

TEST_CASE("TlsSiteContexts picks up a cert renewed in place", "[tls_site_contexts]") {
    Env env;
    const auto site = env.site_with_cert("a.example");
    TlsSiteContexts contexts;
    auto first = contexts.current(snapshot({site}));
    const auto old_context = first->at("a.example");

    write_self_signed(site.cert_file, site.key_file, "a.example");
    fs::last_write_time(site.cert_file, fs::file_time_type::clock::now() + std::chrono::hours(1));
    fs::last_write_time(site.key_file, fs::file_time_type::clock::now() + std::chrono::hours(1));

    auto second = contexts.current(snapshot({site}));
    CHECK(second != first);
    REQUIRE(second->count("a.example") == 1);
    CHECK(second->at("a.example") != old_context);
}

TEST_CASE("TlsSiteContexts reloads when a site is added or its cert path changes", "[tls_site_contexts]") {
    Env env;
    auto a = env.site_with_cert("a.example");
    TlsSiteContexts contexts;
    auto first = contexts.current(snapshot({a}));
    REQUIRE(first->size() == 1);

    auto with_b = contexts.current(snapshot({a, env.site_with_cert("b.example")}));
    CHECK(with_b->size() == 2);

    auto moved = a;
    moved.cert_file = (env.dir / "a2.crt").string();
    moved.key_file = (env.dir / "a2.key").string();
    write_self_signed(moved.cert_file, moved.key_file, "a.example");
    auto after_move = contexts.current(snapshot({moved}));
    CHECK(after_move->size() == 1);
    CHECK(after_move->at("a.example") != with_b->at("a.example"));
}

TEST_CASE("TlsSiteContexts picks up a cert that appears after the site was configured", "[tls_site_contexts]") {
    Env env;
    auto site = env.site("late.example");
    TlsSiteContexts contexts;
    CHECK(contexts.current(snapshot({site}))->empty());

    write_self_signed(site.cert_file, site.key_file, "late.example");
    CHECK(contexts.current(snapshot({site}))->count("late.example") == 1);
}

TEST_CASE("TlsSiteContexts is safe under concurrent lookups while snapshots change", "[tls_site_contexts]") {
    Env env;
    const auto a = env.site_with_cert("a.example");
    const auto b = env.site_with_cert("b.example");
    TlsSiteContexts contexts;
    contexts.current(snapshot({a}));

    std::atomic<bool> stop{false};
    std::atomic<int> null_maps{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 6; ++i) {
        threads.emplace_back([&, i] {
            while (!stop.load()) {
                auto map = contexts.current(snapshot(i % 2 ? std::vector<SiteConfig>{a}
                                                            : std::vector<SiteConfig>{a, b}));
                if (!map) {
                    ++null_maps;
                }
            }
        });
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    stop = true;
    for (auto& t : threads) {
        t.join();
    }
    CHECK(null_maps.load() == 0);
    CHECK(contexts.current(snapshot({a, b}))->size() == 2);
}
