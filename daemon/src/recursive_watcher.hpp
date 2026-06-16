#pragma once

#include "fanotify_monitor.hpp"
#include "inotify_watcher.hpp"

#include <string>

/// @file recursive_watcher.hpp
/// @brief Recursive directory monitoring combining fanotify and inotify.

namespace av::daemon {

/// @brief Watches a directory subtree for file access, recursively and
///        dynamically.
///
/// fanotify directory marks are not recursive, so this watcher places one mark
/// per directory in the subtree. inotify is used in parallel to detect
/// subdirectories that appear or disappear after startup, keeping the fanotify
/// mark set in sync: a newly created (or moved-in) directory is marked and
/// watched on the fly, and a removed one is dropped.
class RecursiveWatcher {
  public:
    /// @brief Create the watcher.
    /// @param enforce If true, fanotify runs in blocking/enforcing mode.
    /// @throws av::IoError if fanotify or inotify cannot be initialised.
    explicit RecursiveWatcher(bool enforce = false);

    /// @brief Exclude a directory subtree from watching.
    ///
    /// Typically set to the quarantine store so the watcher never marks it: this
    /// prevents access to stored files from being re-scanned and re-quarantined.
    /// @param prefix Absolute path of the subtree to skip.
    void set_excluded(std::string prefix) { excluded_ = std::move(prefix); }

    /// @brief Recursively mark and watch a directory and all its current
    ///        subdirectories.
    /// @param root Root directory of the subtree to watch.
    void watch_tree(const std::string& root);

    /// @brief fanotify descriptor (file-access events).
    int fanotify_fd() const noexcept { return fanotify_.fd(); }

    /// @brief inotify descriptor (directory-structure changes).
    int inotify_fd() const noexcept { return inotify_.fd(); }

    /// @brief Whether fanotify is in enforcing (blocking) mode.
    bool enforcing() const noexcept { return fanotify_.enforcing(); }

    /// @brief Number of directories currently watched.
    std::size_t watched_count() const noexcept { return inotify_.watch_count(); }

    /// @brief Process pending file-access events.
    /// @param handler Decision callback for each access.
    void process_access(const AccessHandler& handler) { fanotify_.process_available(handler); }

    /// @brief Process pending directory-structure changes, updating the mark set.
    void process_structure();

  private:
    void add_subtree(const std::string& root);

    FanotifyMonitor fanotify_;
    InotifyWatcher inotify_;
    std::string excluded_;
};

}
