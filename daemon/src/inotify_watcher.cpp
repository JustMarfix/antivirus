#include "inotify_watcher.hpp"

#include "avcore/error.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sys/inotify.h>
#include <unistd.h>

namespace av::daemon {

namespace {

constexpr std::uint32_t kWatchMask =
    IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF | IN_ONLYDIR;

std::string join_path(const std::string& dir, const char* name) {
    if (dir.empty() || dir.back() == '/') {
        return dir + name;
    }
    return dir + "/" + name;
}

}

InotifyWatcher::InotifyWatcher() {
    int fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) {
        throw IoError(std::string("inotify_init1 failed: ") + std::strerror(errno));
    }
    inotify_fd_ = util::UniqueFd(fd);
}

bool InotifyWatcher::add_watch(const std::string& path) {
    int wd = ::inotify_add_watch(inotify_fd_.get(), path.c_str(), kWatchMask);
    if (wd < 0) {
        if (errno == ENOENT || errno == ENOTDIR || errno == EACCES || errno == ENOSPC) {
            return false;
        }
        throw IoError(std::string("inotify_add_watch failed for '") + path +
                      "': " + std::strerror(errno));
    }
    wd_to_path_[wd] = path;
    return true;
}

void InotifyWatcher::process_available(const DirChangeHandler& handler) {
    alignas(inotify_event) std::array<char, 16 * 1024> buffer{};
    for (;;) {
        ssize_t len = ::read(inotify_fd_.get(), buffer.data(), buffer.size());
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            throw IoError(std::string("inotify read failed: ") + std::strerror(errno));
        }
        if (len == 0) {
            return;
        }

        std::size_t offset = 0;
        while (offset + sizeof(inotify_event) <= static_cast<std::size_t>(len)) {
            const auto* event = reinterpret_cast<const inotify_event*>(buffer.data() + offset);

            if (event->mask & IN_IGNORED) {
                // The watch was auto-removed (its directory disappeared).
                wd_to_path_.erase(event->wd);
            } else if ((event->mask & IN_ISDIR) && event->len > 0) {
                auto it = wd_to_path_.find(event->wd);
                if (it != wd_to_path_.end()) {
                    std::string child = join_path(it->second, event->name);
                    if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
                        handler(DirChange{DirChange::Kind::Created, child});
                    } else if (event->mask & (IN_DELETE | IN_MOVED_FROM)) {
                        handler(DirChange{DirChange::Kind::Removed, child});
                    }
                }
            }

            offset += sizeof(inotify_event) + event->len;
        }
    }
}

}
