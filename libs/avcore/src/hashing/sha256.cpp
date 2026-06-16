#include "avcore/hashing/sha256.hpp"

#include "avcore/error.hpp"
#include "avcore/util/hex.hpp"

#include <array>
#include <bit>
#include <cstring>

// SHA-256 follows FIPS 180-4. The round constants below are the first 32 bits
// of the fractional parts of the cube roots of the first 64 primes.

namespace av::hashing {

namespace {

constexpr std::array<std::uint32_t, 64> kK = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

std::uint32_t load_be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

std::uint32_t big_sigma0(std::uint32_t x) {
    return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22);
}
std::uint32_t big_sigma1(std::uint32_t x) {
    return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25);
}
std::uint32_t small_sigma0(std::uint32_t x) {
    return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3);
}
std::uint32_t small_sigma1(std::uint32_t x) {
    return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10);
}

}

Sha256::Sha256()
    : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
      buffer_{}, bit_count_(0), buffer_len_(0), finalized_(false) {}

void Sha256::process_block(const std::uint8_t* block) {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = load_be32(block + i * 4);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
        std::uint32_t ch = (e & f) ^ (~e & g);
        std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        std::uint32_t t1 = h + big_sigma1(e) + ch + kK[i] + w[i];
        std::uint32_t t2 = big_sigma0(a) + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> data) {
    if (finalized_) {
        throw InvalidArgument("Sha256::update called after finalize");
    }
    bit_count_ += static_cast<std::uint64_t>(data.size()) * 8;
    std::size_t offset = 0;

    if (buffer_len_ > 0) {
        std::size_t need = 64 - buffer_len_;
        std::size_t take = data.size() < need ? data.size() : need;
        std::memcpy(buffer_.data() + buffer_len_, data.data(), take);
        buffer_len_ += take;
        offset += take;
        if (buffer_len_ == 64) {
            process_block(buffer_.data());
            buffer_len_ = 0;
        }
    }

    while (offset + 64 <= data.size()) {
        process_block(data.data() + offset);
        offset += 64;
    }

    std::size_t remaining = data.size() - offset;
    if (remaining > 0) {
        std::memcpy(buffer_.data(), data.data() + offset, remaining);
        buffer_len_ = remaining;
    }
}

Sha256::Digest Sha256::finalize() {
    if (finalized_) {
        throw InvalidArgument("Sha256::finalize called twice");
    }
    std::uint64_t total_bits = bit_count_;

    std::array<std::uint8_t, 1> pad_byte = {0x80};
    update(pad_byte);
    std::array<std::uint8_t, 1> zero = {0x00};
    while (buffer_len_ != 56) {
        update(zero);
    }

    std::array<std::uint8_t, 8> length_be{};
    for (std::size_t i = 0; i < 8; ++i) {
        length_be[i] = static_cast<std::uint8_t>((total_bits >> (56 - 8 * i)) & 0xFF);
    }
    std::memcpy(buffer_.data() + buffer_len_, length_be.data(), 8);
    process_block(buffer_.data());
    buffer_len_ = 0;

    Digest out{};
    for (std::size_t i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFF);
    }
    finalized_ = true;
    return out;
}

Sha256::Digest Sha256::hash(std::span<const std::uint8_t> data) {
    Sha256 h;
    h.update(data);
    return h.finalize();
}

std::string Sha256::hash_hex(std::span<const std::uint8_t> data) {
    Digest d = hash(data);
    return util::to_hex(d);
}

}
