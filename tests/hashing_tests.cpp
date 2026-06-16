#include "avcore/error.hpp"
#include "avcore/hashing/md5.hpp"
#include "avcore/hashing/sha1.hpp"
#include "avcore/hashing/sha256.hpp"
#include "avcore/util/hex.hpp"
#include "test_support.hpp"

#include <doctest/doctest.h>
#include <string>

using namespace av;
using av::test::bytes;

TEST_CASE("MD5 matches RFC 1321 test vectors") {
    CHECK(hashing::Md5::hash_hex(bytes("")) == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(hashing::Md5::hash_hex(bytes("abc")) == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(hashing::Md5::hash_hex(bytes("The quick brown fox jumps over the lazy dog")) ==
          "9e107d9d372bb6826bd81d3542a419d6");
    // dot at the end
    CHECK(hashing::Md5::hash_hex(bytes("The quick brown fox jumps over the lazy dog.")) ==
          "e4d909c290d0fb1ca068ffaddf22cbd0");
}

TEST_CASE("SHA-1 matches FIPS 180-4 test vectors") {
    CHECK(hashing::Sha1::hash_hex(bytes("")) == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    CHECK(hashing::Sha1::hash_hex(bytes("abc")) == "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(hashing::Sha1::hash_hex(
              bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
          "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

TEST_CASE("SHA-256 matches FIPS 180-4 test vectors") {
    CHECK(hashing::Sha256::hash_hex(bytes("")) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hashing::Sha256::hash_hex(bytes("abc")) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(hashing::Sha256::hash_hex(
              bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("Streaming updates equal one-shot hashing") {
    std::string message(1000, 'a');

    hashing::Sha256 streamed;
    for (char c : message) {
        std::uint8_t byte = static_cast<std::uint8_t>(c);
        streamed.update(std::span<const std::uint8_t>(&byte, 1));
    }
    auto streamed_digest = streamed.finalize();

    auto oneshot_digest = hashing::Sha256::hash(bytes(message));
    CHECK(util::to_hex(streamed_digest) == util::to_hex(oneshot_digest));
}

TEST_CASE("Hashers reject reuse after finalize") {
    hashing::Md5 md5;
    md5.update(bytes("abc"));
    (void) md5.finalize();
    CHECK_THROWS_AS(md5.update(bytes("more")), InvalidArgument);
    CHECK_THROWS_AS((void) md5.finalize(), InvalidArgument);
}
