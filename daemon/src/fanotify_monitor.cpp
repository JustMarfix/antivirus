#include "fanotify_monitor.hpp"

#include "avcore/error.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/fanotify.h>
#include <unistd.h>

namespace av::daemon {

namespace {

std::string resolve_fd_path(int fd) {
    std::string link = "/proc/self/fd/" + std::to_string(fd);
    std::array<char, 4096> buffer{};
    ssize_t len = ::readlink(link.c_str(), buffer.data(), buffer.size() - 1);
    if (len < 0) {
        return {};
    }
    return std::string(buffer.data(), static_cast<std::size_t>(len));
}

}

namespace {

unsigned long long event_mask(bool enforce) {
    unsigned long long mask = enforce ? (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM)
                                      : (FAN_OPEN | FAN_OPEN_EXEC | FAN_CLOSE_WRITE);
    return mask | FAN_EVENT_ON_CHILD;
}

}

FanotifyMonitor::FanotifyMonitor(bool enforce) : enforce_(enforce) {
    unsigned int init_flags =
        (enforce_ ? FAN_CLASS_CONTENT : FAN_CLASS_NOTIF) | FAN_NONBLOCK | FAN_CLOEXEC;
    int fd = ::fanotify_init(init_flags, O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fd < 0) {
        throw IoError(std::string("fanotify_init failed: ") + std::strerror(errno));
    }
    fan_fd_ = util::UniqueFd(fd);
}

bool FanotifyMonitor::add_mark(const std::string& dir) {
    if (::fanotify_mark(fan_fd_.get(), FAN_MARK_ADD, event_mask(enforce_), AT_FDCWD, dir.c_str()) <
        0) {
        if (errno == ENOENT || errno == ENOTDIR || errno == EACCES || errno == ENOSPC) {
            return false;
        }
        throw IoError(std::string("fanotify_mark(add) failed for '") + dir +
                      "': " + std::strerror(errno));
    }
    return true;
}

void FanotifyMonitor::remove_mark(const std::string& dir) {
    if (::fanotify_mark(fan_fd_.get(), FAN_MARK_REMOVE, event_mask(enforce_), AT_FDCWD,
                        dir.c_str()) < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return;
        }
        throw IoError(std::string("fanotify_mark(remove) failed for '") + dir +
                      "': " + std::strerror(errno));
    }
}

void FanotifyMonitor::respond(int event_fd, AccessDecision decision) {
    struct fanotify_response response{};
    response.fd = event_fd;
    response.response = (decision == AccessDecision::Allow) ? FAN_ALLOW : FAN_DENY;
    if (::write(fan_fd_.get(), &response, sizeof(response)) !=
        static_cast<ssize_t>(sizeof(response))) {
        throw IoError(std::string("fanotify response write failed: ") + std::strerror(errno));
    }
}

void FanotifyMonitor::process_available(const AccessHandler& handler) {
    std::array<char, 8192> buffer{};
    for (;;) {
        ssize_t len = ::read(fan_fd_.get(), buffer.data(), buffer.size());
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            throw IoError(std::string("fanotify read failed: ") + std::strerror(errno));
        }
        if (len == 0) {
            return;
        }

        const auto* metadata = reinterpret_cast<const fanotify_event_metadata*>(buffer.data());
        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                throw IoError("fanotify metadata version mismatch");
            }
            if (metadata->fd >= 0) {
                FileAccessEvent event;
                event.fd = metadata->fd;
                event.path = resolve_fd_path(metadata->fd);
                event.pid = metadata->pid;
                event.is_exec = (metadata->mask & (FAN_OPEN_EXEC_PERM | FAN_OPEN_EXEC)) != 0;
                event.needs_response = (metadata->mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM)) != 0;

                AccessDecision decision = AccessDecision::Allow;
                try {
                    decision = handler(event);
                } catch (const AvException&) {
                    // On any handler failure, fail open so we never leave a
                    // process blocked waiting for a permission decision.
                    decision = AccessDecision::Allow;
                }
                if (event.needs_response) {
                    respond(metadata->fd, decision);
                }
                ::close(metadata->fd);
            }
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

}
