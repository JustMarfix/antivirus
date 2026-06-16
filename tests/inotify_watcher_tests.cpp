#include "avcore/error.hpp"
#include "inotify_watcher.hpp"

#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

using namespace av;
using av::daemon::DirChange;
using av::daemon::InotifyWatcher;

namespace {

namespace fs = std::filesystem;

fs::path make_temp_dir() {
    static int counter = 0;
    fs::path dir = fs::temp_directory_path() /
                   ("avino_" + std::to_string(::getpid()) + "_" + std::to_string(counter++));
    fs::create_directories(dir);
    return dir;
}

std::vector<DirChange> drain(InotifyWatcher& watcher) {
    std::vector<DirChange> changes;
    watcher.process_available([&changes](const DirChange& c) { changes.push_back(c); });
    return changes;
}

}

TEST_CASE("InotifyWatcher reports subdirectory creation and removal") {
    fs::path root = make_temp_dir();
    InotifyWatcher watcher;
    REQUIRE(watcher.add_watch(root.string()));
    CHECK(watcher.watch_count() == 1);

    SUBCASE("creating a subdirectory yields a Created change") {
        fs::create_directory(root / "sub");
        std::vector<DirChange> changes = drain(watcher);
        REQUIRE(changes.size() == 1);
        CHECK(changes[0].kind == DirChange::Kind::Created);
        CHECK(changes[0].path == (root / "sub").string());
    }

    SUBCASE("removing a subdirectory yields a Removed change") {
        fs::create_directory(root / "gone");
        (void) drain(watcher);
        fs::remove(root / "gone");
        std::vector<DirChange> changes = drain(watcher);
        REQUIRE(changes.size() == 1);
        CHECK(changes[0].kind == DirChange::Kind::Removed);
        CHECK(changes[0].path == (root / "gone").string());
    }

    SUBCASE("creating a regular file produces no directory change") {
        std::ofstream(root / "file.txt") << "data";
        std::vector<DirChange> changes = drain(watcher);
        CHECK(changes.empty());
    }

    fs::remove_all(root);
}

TEST_CASE("InotifyWatcher add_watch rejects invalid targets gracefully") {
    InotifyWatcher watcher;
    SUBCASE("a non-existent path is not watched") {
        CHECK_FALSE(watcher.add_watch("/no/such/avino/path"));
        CHECK(watcher.watch_count() == 0);
    }
    SUBCASE("a regular file is not watched (directories only)") {
        fs::path root = make_temp_dir();
        fs::path file = root / "f.bin";
        std::ofstream(file) << "x";
        CHECK_FALSE(watcher.add_watch(file.string()));
        fs::remove_all(root);
    }
}
