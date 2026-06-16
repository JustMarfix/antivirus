#include "avcore/error.hpp"
#include "avcore/util/hex.hpp"
#include "test_support.hpp"

#include <array>
#include <doctest/doctest.h>

using namespace av;

TEST_CASE("to_hex encodes bytes as lowercase hex") {
    std::array<std::uint8_t, 4> data = {0x00, 0x0f, 0xa5, 0xff};
    CHECK(util::to_hex(data) == "000fa5ff");

    std::array<std::uint8_t, 0> empty{};
    CHECK(util::to_hex(empty).empty());
}

TEST_CASE("from_hex round-trips and rejects malformed input") {
    SUBCASE("valid input decodes") {
        std::string decoded = util::from_hex("000fa5ff");
        std::array<std::uint8_t, 4> expected = {0x00, 0x0f, 0xa5, 0xff};
        CHECK(util::to_hex(test::bytes(decoded)) == util::to_hex(expected));
    }
    SUBCASE("odd length is rejected") {
        CHECK_THROWS_AS(util::from_hex("abc"), InvalidArgument);
    }
    SUBCASE("non-hex digit is rejected") {
        CHECK_THROWS_AS(util::from_hex("zz"), InvalidArgument);
    }
}
