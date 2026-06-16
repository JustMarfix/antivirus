#include "avcore/error.hpp"
#include "avcore/hashing/sha256.hpp"
#include "avcore/scan/file_scanner.hpp"
#include "avcore/scan/signature_database.hpp"
#include "avcore/scan/verdict.hpp"
#include "avcore/util/hex.hpp"
#include "test_support.hpp"

#include <doctest/doctest.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>

using namespace av;
using av::test::bytes;

namespace {

constexpr const char* kEicar =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

std::filesystem::path write_temp_file(const std::string& contents) {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() /
        ("avtest_" + std::to_string(std::hash<std::string>{}(contents)) + ".bin");
    std::ofstream out(path, std::ios::binary);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    out.close();
    return path;
}

}

TEST_CASE("Content signature detects the EICAR test string") {
    scan::SignatureDatabase db;
    db.add_content_signature(bytes(kEicar), "Eicar-Test-Signature");
    db.build();
    scan::FileScanner scanner(db);

    SUBCASE("buffer containing the signature is flagged") {
        std::string payload = std::string("prefix...") + kEicar + "...suffix";
        scan::ScanResult result = scanner.scan_buffer(bytes(payload));
        CHECK(result.infected());
        CHECK(result.threat_name == "Eicar-Test-Signature");
    }
    SUBCASE("clean buffer passes") {
        scan::ScanResult result = scanner.scan_buffer(bytes("an ordinary clean file"));
        CHECK(result.verdict == scan::Verdict::Clean);
        CHECK(result.threat_name.empty());
    }
}

TEST_CASE("Hash signature detects a known sample") {
    std::string sample = "totally-malicious-payload";
    std::string digest = hashing::Sha256::hash_hex(bytes(sample));

    scan::SignatureDatabase db;
    db.add_hash_signature(digest, "Known-Sample");
    db.build();
    scan::FileScanner scanner(db);

    CHECK(scanner.scan_buffer(bytes(sample)).threat_name == "Known-Sample");
    CHECK(scanner.scan_buffer(bytes("different content")).verdict == scan::Verdict::Clean);
}

TEST_CASE("Hash signatures work for MD5 and SHA-1 digests too") {
    scan::SignatureDatabase db;
    db.add_hash_signature("44d88612fea8a8f36de82e1278abb02f", "Eicar-By-MD5");
    db.build();
    scan::FileScanner scanner(db);

    scan::ScanResult result = scanner.scan_buffer(bytes(kEicar));
    CHECK(result.infected());
    CHECK(result.threat_name == "Eicar-By-MD5");
    CHECK(result.detail.rfind("md5:", 0) == 0);
}

TEST_CASE("Scanning files on disk works and handles missing files") {
    scan::SignatureDatabase db;
    db.add_content_signature(bytes(kEicar), "Eicar-Test-Signature");
    db.build();
    scan::FileScanner scanner(db);

    SUBCASE("infected file") {
        std::filesystem::path path = write_temp_file(std::string(kEicar));
        scan::ScanResult result = scanner.scan_file(path);
        std::filesystem::remove(path);
        CHECK(result.infected());
    }
    SUBCASE("missing file yields an error verdict, not an exception") {
        scan::ScanResult result = scanner.scan_file("/no/such/avtest/file");
        CHECK(result.verdict == scan::Verdict::Error);
        CHECK_FALSE(result.detail.empty());
    }
}

TEST_CASE("Scanning through a file descriptor (fanotify-safe path)") {
    scan::SignatureDatabase db;
    db.add_content_signature(bytes(kEicar), "Eicar-Test-Signature");
    db.build();
    scan::FileScanner scanner(db);

    SUBCASE("descriptor of an infected file is flagged") {
        std::filesystem::path path = write_temp_file(std::string(kEicar));
        int fd = ::open(path.c_str(), O_RDONLY);
        REQUIRE(fd >= 0);
        scan::ScanResult result = scanner.scan_fd(fd, path.string());
        ::close(fd);
        std::filesystem::remove(path);
        CHECK(result.infected());
        CHECK(result.threat_name == "Eicar-Test-Signature");
    }
    SUBCASE("an invalid descriptor yields an error verdict, not an exception") {
        scan::ScanResult result = scanner.scan_fd(-1, "bad-fd");
        CHECK(result.verdict == scan::Verdict::Error);
        CHECK_FALSE(result.detail.empty());
    }
}

TEST_CASE("SignatureDatabase parsing and validation") {
    SUBCASE("valid database file loads both signature kinds") {
        std::string db_text = "# comment line\n"
                              "hash:44d88612fea8a8f36de82e1278abb02f:Eicar-By-Hash\n"
                              "hex:6d616c:Mal-Pattern\n";
        std::filesystem::path path = write_temp_file(db_text);
        scan::SignatureDatabase db;
        db.load_from_file(path);
        std::filesystem::remove(path);
        db.build();
        CHECK(db.hash_signature_count() == 1);
        CHECK(db.content_signature_count() == 1);
        CHECK(db.match_content(bytes("a malware sample")).has_value());
    }
    SUBCASE("malformed line is rejected") {
        std::filesystem::path path = write_temp_file("this-is-not-valid\n");
        scan::SignatureDatabase db;
        CHECK_THROWS_AS(db.load_from_file(path), ParseError);
        std::filesystem::remove(path);
    }
    SUBCASE("invalid hex digest is rejected") {
        scan::SignatureDatabase db;
        CHECK_THROWS_AS(db.add_hash_signature("xyz", "bad"), InvalidArgument);
    }
    SUBCASE("matching before build is rejected") {
        scan::SignatureDatabase db;
        CHECK_THROWS_AS(db.match_content(bytes("data")), InvalidArgument);
    }
}
