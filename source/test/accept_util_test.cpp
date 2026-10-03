#include <boost/asio.hpp>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <vector>

#include "listener/accept_util.hpp"

using namespace atomwall;
namespace net = boost::asio;
using net::ip::tcp;

namespace {

struct Loopback {
    net::io_context io;
    tcp::acceptor acceptor{io, {net::ip::make_address("127.0.0.1"), 0}};
    tcp::socket client{io};
    tcp::socket late_client{io};

    void connect_client() { client.connect(acceptor.local_endpoint()); }
    void connect_late_client() { late_client.connect(acceptor.local_endpoint()); }
};

} // namespace

TEST_CASE("accept_next returns the accepted connection", "[accept_util]") {
    Loopback env;
    env.connect_client();

    bool accepted = false;
    net::co_spawn(
        env.io,
        [&]() -> net::awaitable<void> {
            auto socket = co_await accept_next(env.acceptor);
            accepted = socket.is_open();
        },
        net::detached);
    env.io.run();
    CHECK(accepted);
}

TEST_CASE("accept_next treats a closed acceptor as terminal, not retryable", "[accept_util]") {
    Loopback env;

    bool threw_aborted = false;
    net::co_spawn(
        env.io,
        [&]() -> net::awaitable<void> {
            try {
                co_await accept_next(env.acceptor);
            } catch (const boost::system::system_error& e) {
                threw_aborted = e.code() == net::error::operation_aborted;
            }
        },
        net::detached);
    env.io.poll();
    env.acceptor.close();
    env.io.run();
    CHECK(threw_aborted);
}

TEST_CASE("accept_next survives fd exhaustion and accepts once fds free up", "[accept_util]") {
    Loopback env;
    env.connect_client();

    rlimit original{};
    REQUIRE(getrlimit(RLIMIT_NOFILE, &original) == 0);
    int highest_open_fd = -1;
    const int scan_limit = static_cast<int>(std::min<rlim_t>(original.rlim_cur, 4096));
    for (int fd = 0; fd < scan_limit; ++fd) {
        if (fcntl(fd, F_GETFD) != -1) {
            highest_open_fd = fd;
        }
    }
    rlimit lowered = original;
    lowered.rlim_cur = static_cast<rlim_t>(highest_open_fd + 1);
    REQUIRE(setrlimit(RLIMIT_NOFILE, &lowered) == 0);

    // Exiting this loop means open() just failed with EMFILE, i.e. the table
    // is exhausted (it may already have been, if there were no free holes).
    std::vector<int> fillers;
    for (;;) {
        const int fd = ::open("/dev/null", O_RDONLY);
        if (fd < 0) {
            break;
        }
        fillers.push_back(fd);
    }

    net::steady_timer release_timer(env.io);
    release_timer.expires_after(std::chrono::milliseconds(150));
    release_timer.async_wait([&](const boost::system::error_code&) {
        for (const int fd : fillers) {
            ::close(fd);
        }
        fillers.clear();
        // With no free fd holes the lowered limit itself is what's exhausting
        // the table, so lifting it is the "fds free up" event.
        setrlimit(RLIMIT_NOFILE, &original);
        // BSD-derived kernels (macOS) drop the queued connection when accept()
        // fails with EMFILE, where Linux leaves it queued — so don't depend on
        // the early connection surviving; offer a fresh one now that there's
        // room to accept it.
        env.connect_late_client();
    });

    bool accepted = false;
    bool threw = false;
    net::co_spawn(
        env.io,
        [&]() -> net::awaitable<void> {
            try {
                auto socket = co_await accept_next(env.acceptor, std::chrono::milliseconds(20));
                accepted = socket.is_open();
            } catch (...) {
                threw = true;
            }
        },
        net::detached);
    env.io.run();

    for (const int fd : fillers) {
        ::close(fd);
    }
    setrlimit(RLIMIT_NOFILE, &original);

    CHECK_FALSE(threw);
    CHECK(accepted);
}
