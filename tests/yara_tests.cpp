#include <doctest/doctest.h>

#ifdef AV_HAVE_YARA

#include "avcore/error.hpp"
#include "avcore/scan/file_scanner.hpp"
#include "avcore/scan/signature_database.hpp"
#include "avcore/scan/yara_scanner.hpp"
#include "test_support.hpp"

#include <filesystem>
#include <fstream>
#include <unistd.h>

using namespace av;
using av::test::bytes;

namespace {
constexpr const char* kRule =
    "rule Demo_Marker { strings: $a = \"AV_YARA_DEMO_MARKER\" condition: $a }";
}

TEST_CASE("YaraScanner compiles a rule and matches it") {
    scan::YaraScanner yara;
    yara.add_rules_string(kRule);
    yara.compile();
    REQUIRE(yara.ready());

    SUBCASE("matching buffer returns the rule name") {
        auto hit = yara.scan_buffer(bytes("...AV_YARA_DEMO_MARKER..."));
        REQUIRE(hit.has_value());
        CHECK(*hit == "Demo_Marker");
    }
    SUBCASE("clean buffer does not match") {
        CHECK_FALSE(yara.scan_buffer(bytes("nothing to see here")).has_value());
    }
}

TEST_CASE("YaraScanner loads a whole directory of rule files") {
    namespace fs = std::filesystem;
    fs::path dir = fs::temp_directory_path() /
                   ("avyara_" + std::to_string(::getpid()) + "_" + std::to_string(::getpid() % 7));
    fs::create_directories(dir / "nested");
    std::ofstream(dir / "a.yar") << "rule Rule_A { strings: $a = \"MARKER_AAA\" condition: $a }\n";
    std::ofstream(dir / "nested" / "b.yara")
        << "rule Rule_B { strings: $b = \"MARKER_BBB\" condition: $b }\n";
    std::ofstream(dir / "notes.txt") << "this is not a yara rule\n";

    scan::YaraScanner yara;
    std::size_t loaded = yara.add_rules_path(dir);
    CHECK(loaded == 2);
    yara.compile();

    CHECK(*yara.scan_buffer(bytes("xx MARKER_AAA xx")) == "Rule_A");
    CHECK(*yara.scan_buffer(bytes("yy MARKER_BBB yy")) == "Rule_B");
    CHECK_FALSE(yara.scan_buffer(bytes("nothing")).has_value());

    fs::remove_all(dir);
}

TEST_CASE("YaraScanner reports a missing rules path") {
    scan::YaraScanner yara;
    CHECK_THROWS_AS(yara.add_rules_path("/no/such/rules/path"), IoError);
}

TEST_CASE("YaraScanner enforces its usage contract") {
    SUBCASE("invalid rule source fails to compile") {
        scan::YaraScanner yara;
        CHECK_THROWS_AS(yara.add_rules_string("rule broken { this is not yara }"), ScanError);
    }
    SUBCASE("scanning before compile is rejected") {
        scan::YaraScanner yara;
        yara.add_rules_string(kRule);
        CHECK_THROWS_AS(yara.scan_buffer(bytes("x")), InvalidArgument);
    }
}

TEST_CASE("FileScanner consults YARA rules after signatures") {
    scan::SignatureDatabase db;
    db.build();
    scan::YaraScanner yara;
    yara.add_rules_string(kRule);
    yara.compile();

    scan::FileScanner scanner(db, 64 * 1024 * 1024, &yara);
    scan::ScanResult result = scanner.scan_buffer(bytes("payload AV_YARA_DEMO_MARKER payload"));
    CHECK(result.infected());
    CHECK(result.threat_name == "Demo_Marker");
    CHECK(result.detail == "yara-rule");

    CHECK(scanner.scan_buffer(bytes("clean")).verdict == scan::Verdict::Clean);
}

#endif
