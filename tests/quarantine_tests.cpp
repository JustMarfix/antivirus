#include "avcore/error.hpp"
#include "avcore/quarantine/quarantine.hpp"

#include <doctest/doctest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace av;
using av::quarantine::Quarantine;
using av::quarantine::QuarantineEntry;

namespace {

namespace fs = std::filesystem;

fs::path unique_dir(const std::string& tag) {
    static int counter = 0;
    fs::path dir = fs::temp_directory_path() / ("avq_" + tag + "_" + std::to_string(::getpid()) +
                                                "_" + std::to_string(counter++));
    fs::create_directories(dir);
    return dir;
}

std::string read_all(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}

TEST_CASE("Quarantine isolates, lists and restores a file") {
    fs::path work = unique_dir("work");
    fs::path store = unique_dir("store");
    fs::path victim = work / "evil.bin";
    std::ofstream(victim) << "malicious-content";

    Quarantine q(store);

    SUBCASE("quarantining moves the file and records metadata") {
        QuarantineEntry entry = q.quarantine_file(victim, "Eicar-Test-File");
        CHECK_FALSE(fs::exists(victim));
        CHECK(entry.threat_name == "Eicar-Test-File");
        CHECK(entry.original_path == fs::absolute(victim).string());

        auto entries = q.list();
        REQUIRE(entries.size() == 1);
        CHECK(entries[0].id == entry.id);

        QuarantineEntry fetched = q.get(entry.id);
        CHECK(fetched.threat_name == "Eicar-Test-File");
    }

    SUBCASE("restoring brings the file back with its content") {
        QuarantineEntry entry = q.quarantine_file(victim, "Threat");
        q.restore(entry.id);
        CHECK(fs::exists(victim));
        CHECK(read_all(victim) == "malicious-content");
        CHECK(q.list().empty());
    }

    SUBCASE("removing deletes permanently without restoring") {
        QuarantineEntry entry = q.quarantine_file(victim, "Threat");
        q.remove(entry.id);
        CHECK(q.list().empty());
        CHECK_FALSE(fs::exists(victim));
    }

    fs::remove_all(work);
    fs::remove_all(store);
}

TEST_CASE("Quarantine reports errors via exceptions") {
    fs::path store = unique_dir("store2");
    Quarantine q(store);

    SUBCASE("quarantining a missing file throws") {
        CHECK_THROWS_AS(q.quarantine_file("/no/such/avq/file", "X"), IoError);
    }
    SUBCASE("unknown id is rejected") {
        CHECK_THROWS_AS(q.get("deadbeef"), InvalidArgument);
        CHECK_THROWS_AS(q.restore("deadbeef"), InvalidArgument);
        CHECK_THROWS_AS(q.remove("deadbeef"), InvalidArgument);
    }
    SUBCASE("restore refuses to overwrite an existing file") {
        fs::path work = unique_dir("work2");
        fs::path victim = work / "f.bin";
        std::ofstream(victim) << "data";
        QuarantineEntry entry = q.quarantine_file(victim, "T");
        std::ofstream(victim) << "something-new";
        CHECK_THROWS_AS(q.restore(entry.id), IoError);
        fs::remove_all(work);
    }

    fs::remove_all(store);
}
