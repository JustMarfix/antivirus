#include "recursive_watcher.hpp"

#include "avcore/util/path.hpp"

#include <filesystem>
#include <system_error>

namespace av::daemon {

namespace fs = std::filesystem;

RecursiveWatcher::RecursiveWatcher(bool enforce) : fanotify_(enforce), inotify_() {}

void RecursiveWatcher::add_subtree(const std::string& root) {
    std::error_code ec;
    if (!fs::is_directory(root, ec) || ec) {
        return;
    }
    if (!excluded_.empty() && util::is_subpath(root, excluded_)) {
        return;
    }

    // Mark the root before descending so files created during the walk are still
    // covered by the parent's watch.
    fanotify_.add_mark(root);
    inotify_.add_watch(root);

    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
    fs::recursive_directory_iterator end;
    for (; !ec && it != end; it.increment(ec)) {
        std::error_code dir_ec;
        if (it->is_directory(dir_ec) && !dir_ec) {
            const std::string path = it->path().string();
            if (!excluded_.empty() && util::is_subpath(path, excluded_)) {
                it.disable_recursion_pending();
                continue;
            }
            fanotify_.add_mark(path);
            inotify_.add_watch(path);
        }
    }
}

void RecursiveWatcher::watch_tree(const std::string& root) {
    add_subtree(root);
}

void RecursiveWatcher::process_structure() {
    inotify_.process_available([this](const DirChange& change) {
        if (change.kind == DirChange::Kind::Created) {
            add_subtree(change.path);
        } else {
            fanotify_.remove_mark(change.path);
        }
    });
}

}
