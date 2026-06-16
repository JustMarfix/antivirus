#include "avcore/error.hpp"
#include "avcore/exclusions/exclusion_store.hpp"

#include <algorithm>
#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

using av::exclusions::ExclusionStore;

namespace {

namespace fs = std::filesystem;

fs::path unique_dir(const std::string& tag) {
    static int counter = 0;
    fs::path dir = fs::temp_directory_path() / ("avx_" + tag + "_" + std::to_string(::getpid()) +
                                                "_" + std::to_string(counter++));
    fs::create_directories(dir);
    return dir;
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

}

TEST_CASE("ExclusionStore excludes a single file") {
    fs::path work = unique_dir("file");
    fs::path victim = work / "keepme.bin";
    std::ofstream(victim) << "data";

    ExclusionStore store;
    CHECK(store.add(victim.string()));
    CHECK(store.is_excluded(fs::weakly_canonical(victim).string()));
    CHECK_FALSE(store.is_excluded((work / "other.bin").string()));
}

TEST_CASE("ExclusionStore excludes a directory subtree") {
    fs::path dir = unique_dir("dir");
    ExclusionStore store;
    store.add(dir.string());

    CHECK(store.is_excluded(dir.string()));
    CHECK(store.is_excluded((dir / "nested" / "deep.txt").string()));
    CHECK_FALSE(store.is_excluded((dir.string() + "_sibling/file")));
}

TEST_CASE("ExclusionStore add is idempotent and remove works") {
    fs::path dir = unique_dir("dup");
    ExclusionStore store;

    CHECK(store.add(dir.string()));
    CHECK_FALSE(store.add(dir.string()));
    CHECK(store.list().size() == 1);

    CHECK(store.remove(dir.string()));
    CHECK(store.list().empty());
    CHECK_FALSE(store.remove(dir.string()));
    CHECK_FALSE(store.is_excluded(dir.string()));
}

TEST_CASE("ExclusionStore rejects an empty path") {
    ExclusionStore store;
    CHECK_THROWS_AS(store.add(""), av::InvalidArgument);
}

TEST_CASE("ExclusionStore persists across reopen") {
    fs::path home = unique_dir("persist");
    fs::path list_file = home / "exclusions.list";
    fs::path a = home / "a";
    fs::path b = home / "b";

    {
        ExclusionStore store(list_file);
        store.add(a.string());
        store.add(b.string());
    }
    CHECK(fs::exists(list_file));

    ExclusionStore reopened(list_file);
    std::vector<std::string> entries = reopened.list();
    CHECK(entries.size() == 2);
    CHECK(contains(entries, fs::weakly_canonical(a).string()));
    CHECK(contains(entries, fs::weakly_canonical(b).string()));
    CHECK(reopened.is_excluded(fs::weakly_canonical(a).string()));
}
