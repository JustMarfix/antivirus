#pragma once

#include "avcore/util/unique_fd.hpp"

#include <cstdint>
#include <functional>
#include <string>

/// @file fanotify_monitor.hpp
/// @brief Real-time file-access monitor built on the Linux fanotify API.

namespace av::daemon {

/// @brief Access decision returned by the scan callback for a permission event.
enum class AccessDecision {
    Allow, ///< Permit the operation.
    Deny   ///< Block the operation (reported to the requesting process as EACCES).
};

/// @brief A single file-access event surfaced by fanotify.
struct FileAccessEvent {
    std::string path;            ///< Resolved path of the accessed file (may be empty).
    int fd = -1;                 ///< Kernel-supplied descriptor, valid only during the callback.
    std::int64_t pid = 0;        ///< PID of the process performing the access.
    bool is_exec = false;        ///< True for execute events.
    bool needs_response = false; ///< True only in enforcing mode (a decision is awaited).
};

/// @brief Callback deciding whether an access should be allowed.
using AccessHandler = std::function<AccessDecision(const FileAccessEvent&)>;

/// @brief Wraps an fanotify instance and a set of per-directory marks.
///
/// Each mark is placed on an individual directory with @c FAN_EVENT_ON_CHILD and
/// **without** @c FAN_MARK_MOUNT, so a mark covers only that directory and its
/// direct entries - never the whole filesystem. Recursive coverage is achieved
/// by adding one mark per directory in a subtree (see @ref RecursiveWatcher);
/// marks can be added and removed at runtime as the tree changes.
///
/// Two modes are supported:
/// - **notify** (default, safe): the kernel only *reports* opens/execs; the
///   accessing process is never blocked, so the monitor can never stall the
///   system even if scanning is slow or the daemon crashes;
/// - **enforce**: the kernel sends blocking *permission* events and waits for an
///   allow/deny decision, which lets malicious files be blocked. Because marks
///   are directory-scoped, only opens within watched directories can be delayed.
///   Must be requested explicitly.
///
/// In both modes scanning must read the file through the descriptor supplied in
/// each event (@ref FileAccessEvent::fd); the monitor never re-opens files
/// itself, which is what prevents the self-deadlock where the responder blocks
/// on its own open while the kernel waits for that same open to be approved.
class FanotifyMonitor {
  public:
    /// @brief Initialise fanotify without marking anything yet.
    /// @param enforce If true, use blocking permission events; otherwise notify only.
    /// @throws av::IoError if fanotify cannot be initialised (typically due to
    ///         missing privileges).
    explicit FanotifyMonitor(bool enforce = false);

    /// @brief Add a mark on a single directory.
    /// @param dir Directory to mark.
    /// @return True if marked; false if @p dir no longer exists or is not an
    ///         accessible directory (expected during a tree walk).
    /// @throws av::IoError on an unexpected failure.
    bool add_mark(const std::string& dir);

    /// @brief Remove a previously added mark.
    /// @param dir Directory whose mark should be removed.
    ///
    /// Marks on deleted directories are dropped by the kernel automatically;
    /// this call additionally tolerates an already-absent mark.
    void remove_mark(const std::string& dir);

    /// @brief Underlying fanotify descriptor, for integration with an event loop.
    /// @return The raw, non-owning descriptor.
    int fd() const noexcept { return fan_fd_.get(); }

    /// @brief Whether the monitor is in enforcing (blocking) mode.
    /// @return True if permission events are in use.
    bool enforcing() const noexcept { return enforce_; }

    /// @brief Read and dispatch all currently pending events.
    /// @param handler Decision callback invoked for each event.
    /// @throws av::IoError on a fatal read error.
    void process_available(const AccessHandler& handler);

  private:
    void respond(int event_fd, AccessDecision decision);

    util::UniqueFd fan_fd_;
    bool enforce_ = false;
};

}
