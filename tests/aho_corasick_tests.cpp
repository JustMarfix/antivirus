#include "avcore/error.hpp"
#include "avcore/matching/aho_corasick.hpp"
#include "test_support.hpp"

#include <doctest/doctest.h>

using namespace av;
using av::matching::AhoCorasick;
using av::test::bytes;

TEST_CASE("AhoCorasick finds overlapping patterns") {
    AhoCorasick ac;
    ac.add_pattern("he", 1);
    ac.add_pattern("she", 2);
    ac.add_pattern("his", 3);
    ac.add_pattern("hers", 4);
    ac.build();

    auto matches = ac.find_all(bytes("ushers"));
    // "she" at [1,4), "he" at [2,4), "hers" at [2,6).
    REQUIRE(matches.size() == 3);
    CHECK(matches[0].id == 2);
    CHECK(matches[0].begin == 1);
    CHECK(matches[0].end == 4);
    CHECK(matches[1].id == 1);
    CHECK(matches[1].begin == 2);
    CHECK(matches[2].id == 4);
    CHECK(matches[2].end == 6);
}

TEST_CASE("AhoCorasick reports absence and presence") {
    AhoCorasick ac;
    ac.add_pattern("malware", 1);
    ac.build();

    CHECK(ac.contains_any(bytes("this binary contains malware signature")));
    CHECK_FALSE(ac.contains_any(bytes("a perfectly clean file")));
    CHECK(ac.find_all(bytes("nothing here")).empty());
}

TEST_CASE("AhoCorasick matches arbitrary binary bytes") {
    AhoCorasick ac;
    std::array<std::uint8_t, 3> needle = {0x00, 0xff, 0x90};
    ac.add_pattern(needle, 7);
    ac.build();

    std::array<std::uint8_t, 5> haystack = {0x01, 0x00, 0xff, 0x90, 0x02};
    auto matches = ac.find_all(haystack);
    REQUIRE(matches.size() == 1);
    CHECK(matches[0].id == 7);
    CHECK(matches[0].begin == 1);
    CHECK(matches[0].end == 4);
}

TEST_CASE("AhoCorasick enforces its usage contract") {
    AhoCorasick ac;
    SUBCASE("empty pattern is rejected") {
        std::array<std::uint8_t, 0> empty{};
        CHECK_THROWS_AS(ac.add_pattern(empty, 1), InvalidArgument);
    }
    SUBCASE("scanning before build is rejected") {
        ac.add_pattern("x", 1);
        CHECK_THROWS_AS(ac.find_all(bytes("x")), InvalidArgument);
        CHECK_THROWS_AS(ac.contains_any(bytes("x")), InvalidArgument);
    }
    SUBCASE("adding after build is rejected") {
        ac.add_pattern("x", 1);
        ac.build();
        CHECK_THROWS_AS(ac.add_pattern("y", 2), InvalidArgument);
    }
}
