#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

/// @file sha1.hpp
/// @brief Self-contained streaming implementation of the SHA-1 digest
///        (FIPS 180-4).

namespace av::hashing {

/// @brief Incremental SHA-1 hasher.
///
/// Feed data with @ref update and obtain the digest with @ref finalize. The
/// object must not be reused after @ref finalize is called.
class Sha1 {
  public:
    /// @brief Length of a SHA-1 digest in bytes.
    static constexpr std::size_t digest_size = 20;

    /// @brief Fixed-size SHA-1 digest.
    using Digest = std::array<std::uint8_t, digest_size>;

    /// @brief Construct a hasher initialised to the SHA-1 starting state.
    Sha1();

    /// @brief Absorb a chunk of input into the running digest.
    /// @param data Bytes to hash.
    void update(std::span<const std::uint8_t> data);

    /// @brief Finish hashing and produce the digest.
    /// @return The 20-byte SHA-1 digest of all absorbed data.
    Digest finalize();

    /// @brief One-shot helper hashing a whole buffer.
    /// @param data Bytes to hash.
    /// @return The SHA-1 digest of @p data.
    static Digest hash(std::span<const std::uint8_t> data);

    /// @brief One-shot helper returning the digest as a lowercase hex string.
    /// @param data Bytes to hash.
    /// @return 40-character hexadecimal digest.
    static std::string hash_hex(std::span<const std::uint8_t> data);

  private:
    void process_block(const std::uint8_t* block);

    std::array<std::uint32_t, 5> state_;
    std::array<std::uint8_t, 64> buffer_;
    std::uint64_t bit_count_;
    std::size_t buffer_len_;
    bool finalized_;
};

}
