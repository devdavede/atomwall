#include "util/atomic_file.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace atomwall {

namespace {

[[noreturn]] void throw_errno(const std::string& what, const std::string& path, int error) {
    throw std::runtime_error(what + " " + path + ": " + std::strerror(error));
}

struct TempFile {
    std::string path;
    int fd = -1;
    bool committed = false;

    ~TempFile() {
        if (fd >= 0) {
            ::close(fd);
        }
        if (!committed) {
            ::unlink(path.c_str());
        }
    }
};

} // namespace

void write_file_atomically(const std::string& path, std::string_view contents, mode_t mode,
                            ExistingFileMode existing) {
    if (existing == ExistingFileMode::Preserve) {
        struct stat current {};
        if (::stat(path.c_str(), &current) == 0) {
            mode = current.st_mode & 07777;
        }
    }

    TempFile tmp;
    tmp.path = path + ".tmp";
    tmp.fd = ::open(tmp.path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (tmp.fd < 0) {
        throw_errno("cannot write", tmp.path, errno);
    }
    // open()'s mode is masked by the umask and ignored entirely if a stale
    // temp file was already there.
    if (::fchmod(tmp.fd, mode) != 0) {
        throw_errno("cannot set permissions on", tmp.path, errno);
    }

    const char* cursor = contents.data();
    std::size_t remaining = contents.size();
    while (remaining > 0) {
        const ssize_t written = ::write(tmp.fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw_errno("cannot write", tmp.path, errno);
        }
        cursor += written;
        remaining -= static_cast<std::size_t>(written);
    }

    if (::fsync(tmp.fd) != 0) {
        throw_errno("cannot sync", tmp.path, errno);
    }
    const int fd = tmp.fd;
    tmp.fd = -1;
    if (::close(fd) != 0) {
        throw_errno("cannot close", tmp.path, errno);
    }

    if (::rename(tmp.path.c_str(), path.c_str()) != 0) {
        throw_errno("cannot replace", path, errno);
    }
    tmp.committed = true;

    // Makes the rename itself durable. Best effort: the data is already
    // safely in place, this only narrows the crash window.
    auto parent = std::filesystem::path(path).parent_path();
    if (parent.empty()) {
        parent = ".";
    }
    const int dir_fd = ::open(parent.c_str(), O_RDONLY | O_CLOEXEC);
    if (dir_fd >= 0) {
        ::fsync(dir_fd);
        ::close(dir_fd);
    }
}

} // namespace atomwall
