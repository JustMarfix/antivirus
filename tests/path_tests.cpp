#include "avcore/util/path.hpp"

#include <doctest/doctest.h>

using av::util::is_subpath;

TEST_CASE("is_subpath recognises nested and equal paths") {
    CHECK(is_subpath("/var/lib/quarantine/abc.quar", "/var/lib/quarantine"));
    CHECK(is_subpath("/var/lib/quarantine", "/var/lib/quarantine"));
    CHECK(is_subpath("/var/lib/quarantine/sub/x", "/var/lib/quarantine"));
    CHECK(is_subpath("/a/b", "/a/b/"));
}

TEST_CASE("is_subpath rejects non-nested paths") {
    SUBCASE("sibling sharing a prefix string is not nested") {
        CHECK_FALSE(is_subpath("/var/lib/quarantine-other/x", "/var/lib/quarantine"));
    }
    SUBCASE("parent is not under child") {
        CHECK_FALSE(is_subpath("/var/lib", "/var/lib/quarantine"));
    }
    SUBCASE("unrelated path") {
        CHECK_FALSE(is_subpath("/home/user/file", "/var/lib/quarantine"));
    }
    SUBCASE("empty prefix matches nothing") {
        CHECK_FALSE(is_subpath("/anything", ""));
    }
}
