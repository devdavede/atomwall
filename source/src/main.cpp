#include <algorithm>
#include <boost/asio.hpp>
#include <cctype>
#include <filesystem>
#include <memory>
#include <openssl/opensslv.h>
#include <spdlog/spdlog.h>
#include <thread>
#include <vector>

#include "admin/admin_server.hpp"
#include "admin/url_fetch.hpp"
#include "app_state.hpp"
#include "globe/globe_server.hpp"
#include "listener/listener.hpp"
#include "listener/tls_listener.hpp"

namespace {

boost::asio::awaitable<void> run_config_poll_loop(std::shared_ptr<atomwall::ConfigStore> config_store) {
    auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::steady_timer timer(executor);
    for (;;) {
        timer.expires_after(std::chrono::seconds(2));
        co_await timer.async_wait(boost::asio::use_awaitable);
        config_store->poll_for_external_changes();
    }
}

// Fills in state->server_location once at startup — either from the manual
// globe.server_lat/lon config, or (if unset and auto-detect is on) a
// one-time public-IP lookup + GeoIP resolution. Not on the hot path, so a
// blocking-feeling network round trip here is fine (see CLAUDE.md
// Performance posture's carve-out for startup-only work). Until this
// resolves, globe endpoints simply report server_location: null.
boost::asio::awaitable<void> resolve_server_location(std::shared_ptr<atomwall::AppState> state) {
    auto config = state->config_store->get();
    if (config->globe.server_lat && config->globe.server_lon) {
        state->server_location->set(
            atomwall::GeoLocation{*config->globe.server_lat, *config->globe.server_lon, ""});
        co_return;
    }
    if (!config->globe.auto_detect_server_location || !state->geoip || !state->geoip->loaded()) {
        co_return;
    }

    // Best-effort: this is a nicety (fills in the globe's server point), not
    // critical proxy function, so any failure here — network, parse, no
    // GeoIP match — just leaves server_location unset rather than taking the
    // whole process down via fatal_on_error.
    try {
        auto fetched =
            co_await atomwall::fetch_url("https://api.ipify.org", 64, std::chrono::seconds(5));
        if (!fetched.ok) {
            spdlog::warn("globe: failed to auto-detect server public IP: {}", fetched.error);
            co_return;
        }
        while (!fetched.body.empty() && std::isspace(static_cast<unsigned char>(fetched.body.back()))) {
            fetched.body.pop_back();
        }

        boost::system::error_code ec;
        auto address = boost::asio::ip::make_address(fetched.body, ec);
        if (ec) {
            spdlog::warn("globe: auto-detected public IP '{}' did not parse as an address",
                         fetched.body);
            co_return;
        }

        auto location = state->geoip->lookup(address);
        if (!location) {
            spdlog::warn("globe: GeoIP lookup for auto-detected server IP {} found nothing",
                         fetched.body);
            co_return;
        }

        spdlog::info("globe: auto-detected server location ({}, {}) from public IP {}", location->lat,
                     location->lon, fetched.body);
        state->server_location->set(*location);
    } catch (const std::exception& e) {
        spdlog::warn("globe: server location auto-detect failed: {}", e.what());
    }
}

void fatal_on_error(std::exception_ptr e) {
    if (!e) {
        return;
    }
    try {
        std::rethrow_exception(e);
    } catch (const std::exception& ex) {
        spdlog::critical("fatal: {}", ex.what());
    }
    std::exit(1);
}

} // namespace

int main(int argc, char** argv) {
    spdlog::info("atomwall starting (Boost {}.{}.{}, {})",
                 BOOST_VERSION / 100000,
                 BOOST_VERSION / 100 % 1000,
                 BOOST_VERSION % 100,
                 OPENSSL_VERSION_TEXT);

    const std::string config_path = argc > 1 ? argv[1] : "config/atomwall.yaml";
    auto state = std::make_shared<atomwall::AppState>();
    state->config_store = std::make_shared<atomwall::ConfigStore>(config_path);
    try {
        state->config_store->load_or_create();
    } catch (const std::exception& e) {
        spdlog::critical("failed to load config from {}: {}", config_path, e.what());
        return 1;
    }

    auto config = state->config_store->get();
    if (!config->blacklist.countries.empty()) {
        spdlog::warn(
            "country blacklist entries are configured but have no effect yet — GeoIP is wired "
            "in for display (request log, live globe) but not yet into blacklist enforcement "
            "(see CLAUDE.md Open decisions); ISP blacklist enforcement, unlike country, is wired "
            "in (see pipeline/checks.cpp check_isp_blacklist)");
    }
    if (config->geoip.mmdb_path.empty()) {
        spdlog::info(
            "geoip.mmdb_path is not set — Country column and the live visitor globe will have "
            "no data until a MaxMind GeoLite2-City .mmdb file is configured");
    }
    if (config->geoip.asn_mmdb_path.empty()) {
        spdlog::info(
            "geoip.asn_mmdb_path is not set — ISP column will stay \"unknown\" until a "
            "GeoLite2-ASN or DB-IP ASN .mmdb file is configured");
    }

    state->geoip = std::make_shared<atomwall::GeoIpService>(config->geoip.mmdb_path);
    state->asn = std::make_shared<atomwall::AsnService>(config->geoip.asn_mmdb_path);
    state->request_log = std::make_shared<atomwall::RequestLog>(
        5000, config->request_log.enabled ? config->request_log.csv_path : std::string{});
    if (config->request_log.enabled) {
        spdlog::info("persisting request history to {} (batched every 100 events)",
                     config->request_log.csv_path);
    }
    state->globe_events = std::make_shared<atomwall::GlobeEventLog>(config->globe.history_size);
    state->server_location = std::make_shared<atomwall::ServerLocationCache>();
    state->ip_blocks = std::make_shared<atomwall::IpBlockTracker>();
    state->scores = std::make_shared<atomwall::ScoreTracker>();
    state->rate_tracker = std::make_shared<atomwall::RequestRateTracker>();
    state->tls_sites = std::make_shared<atomwall::TlsSiteContexts>();

    const auto users_path = (std::filesystem::path(config_path).parent_path() / "users.yaml").string();
    state->users = std::make_shared<atomwall::UserStore>(users_path);
    state->users->load();
    if (state->users->empty()) {
        spdlog::warn("no admin users yet — open the admin UI to create the first account");
    }
    state->sessions = std::make_shared<atomwall::SessionStore>();
    state->login_history = std::make_shared<atomwall::LoginHistory>();

    boost::asio::io_context io_context;
    boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait([&](const boost::system::error_code&, int signal) {
        spdlog::info("received signal {}, shutting down", signal);
        io_context.stop();
    });

    if (config->http.enabled) {
        boost::asio::co_spawn(io_context, atomwall::run_http_listener(state), fatal_on_error);
    }
    if (config->https.enabled) {
        boost::asio::co_spawn(io_context, atomwall::run_tls_listener(state), fatal_on_error);
    }
    if (config->admin.enabled) {
        boost::asio::co_spawn(io_context, atomwall::run_admin_server(state), fatal_on_error);
    }
    if (config->globe.public_enabled) {
        boost::asio::co_spawn(io_context, atomwall::run_globe_server(state), fatal_on_error);
    }
    boost::asio::co_spawn(io_context, run_config_poll_loop(state->config_store), fatal_on_error);
    boost::asio::co_spawn(io_context, resolve_server_location(state), fatal_on_error);

    const unsigned worker_count = std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> workers;
    workers.reserve(worker_count - 1);
    for (unsigned i = 1; i < worker_count; ++i) {
        workers.emplace_back([&io_context] { io_context.run(); });
    }

    io_context.run();
    for (auto& worker : workers) {
        worker.join();
    }

    return 0;
}
