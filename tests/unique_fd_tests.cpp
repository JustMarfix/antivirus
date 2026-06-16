#include "avcore/util/unique_fd.hpp"

#include <doctest/doctest.h>
#include <fcntl.h>
#include <unistd.h>

using av::util::UniqueFd;

TEST_CASE("UniqueFd owns and releases descriptors") {
    SUBCASE("default-constructed owner is empty") {
        UniqueFd fd;
        CHECK_FALSE(fd.valid());
        CHECK(fd.get() < 0);
    }

    SUBCASE("owning a real descriptor") {
        int raw = ::open("/dev/null", O_RDONLY);
        REQUIRE(raw >= 0);
        UniqueFd fd(raw);
        CHECK(fd.valid());
        CHECK(fd.get() == raw);
    }

    SUBCASE("move transfers ownership") {
        UniqueFd a(::open("/dev/null", O_RDONLY));
        int raw = a.get();
        UniqueFd b(std::move(a));
        CHECK_FALSE(a.valid());
        CHECK(b.get() == raw);
    }

    SUBCASE("release hands back the descriptor") {
        UniqueFd fd(::open("/dev/null", O_RDONLY));
        int raw = fd.release();
        CHECK_FALSE(fd.valid());
        CHECK(raw >= 0);
        CHECK(::close(raw) == 0);
    }

    SUBCASE("reset closes and empties") {
        UniqueFd fd(::open("/dev/null", O_RDONLY));
        fd.reset();
        CHECK_FALSE(fd.valid());
    }
}
