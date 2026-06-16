#pragma once

#include "avcore/util/unique_fd.hpp"

#include <functional>
#include <string>
#include <unordered_map>

/// @file inotify_watcher.hpp
/// @brief inotify-based tracker of directory-tree structure changes.

namespace av::daemon {

/// @brief A change to the watched directory structure.
struct DirChange {
    /// @brief Kind of structural change.
    enum class Kind {
        Created, ///< A subdirectory was created or moved into a watched directory.
        Removed  ///< A subdirectory was deleted from or moved out of a watched directory.
    };

    Kind kind;        ///< What happened.
    std::string path; ///< Absolute path of the affected subdirectory.
};

/// @brief Callback invoked for each structural change.
using DirChangeHandler = std::function<void(const DirChange&)>;

/// @brief Watches directories for child-directory creation and removal.
///
/// Unlike fanotify directory marks, inotify reliably reports when subdirectories
/// appear or disappear, which is what lets the antivirus keep a recursive
/// fanotify mark set in sync as the tree changes at runtime. inotify requires no
/// special privileges, so this component is unit-testable on its own.
///
/// Only directory events are surfaced; file-level events are ignored here (file
/// access is handled by fanotify).
class InotifyWatcher {
  public:
    /// @brief Create an inotify instance.
    /// @throws av::IoError if inotify cannot be initialised.
    InotifyWatcher();

    /// @brief Underlying inotify descriptor, for integration with an event loop.
    /// @return The raw, non-owning descriptor.
    int fd() const noexcept { return inotify_fd_.get(); }

    /// @brief Start watching a single directory for child create/remove events.
    /// @param path Directory to watch.
    /// @return True if the watch was added; false if @p path could not be
    ///         watched because it no longer exists or is not an accessible
    ///         directory (a benign, expected outcome during a tree walk).
    /// @throws av::IoError on an unexpected failure.
    bool add_watch(const std::string& path);

    /// @brief Number of directories currently watched.
    std::size_t watch_count() const noexcept { return wd_to_path_.size(); }

    /// @brief Read and dispatch all currently pending structural changes.
    /// @param handler Callback invoked for each change.
    /// @throws av::IoError on a fatal read error.
    void process_available(const DirChangeHandler& handler);

  private:
    util::UniqueFd inotify_fd_;
    std::unordered_map<int, std::string> wd_to_path_;
};

}
