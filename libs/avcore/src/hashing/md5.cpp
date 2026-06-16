#include "avcore/hashing/md5.hpp"

#include "avcore/error.hpp"
#include "avcore/util/hex.hpp"

#include <array>
#include <bit>
#include <cstring>

// MD5 follows RFC 1321. The per-round constants and shift amounts below are the
// values mandated by that specification.

namespace av::hashing {

namespace {

constexpr std::array<std::uint32_t, 64> kT = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

constexpr std::array<std::uint32_t, 16> kShift = {7, 12, 17, 22, 5, 9,  14, 20,
                                                  4, 11, 16, 23, 6, 10, 15, 21};

std::uint32_t load_le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

}

Md5::Md5()
    : state_{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}, buffer_{}, bit_count_(0),
      buffer_len_(0), finalized_(false) {}

void Md5::process_block(const std::uint8_t* block) {
    std::array<std::uint32_t, 16> m{};
    for (std::size_t i = 0; i < 16; ++i) {
        m[i] = load_le32(block + i * 4);
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];

    for (std::uint32_t i = 0; i < 64; ++i) {
        std::uint32_t f = 0;
        std::uint32_t g = 0;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        std::uint32_t rotate = kShift[(i / 16) * 4 + (i % 4)];
        std::uint32_t tmp = d;
        d = c;
        c = b;
        std::uint32_t sum = a + f + kT[i] + m[g];
        b = b + std::rotl(sum, static_cast<int>(rotate));
        a = tmp;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
}

void Md5::update(std::span<const std::uint8_t> data) {
    if (finalized_) {
        throw InvalidArgument("Md5::update called after finalize");
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

Md5::Digest Md5::finalize() {
    if (finalized_) {
        throw InvalidArgument("Md5::finalize called twice");
    }
    std::uint64_t total_bits = bit_count_;

    std::array<std::uint8_t, 1> pad_byte = {0x80};
    update(pad_byte);
    std::array<std::uint8_t, 1> zero = {0x00};
    while (buffer_len_ != 56) {
        update(zero);
    }

    std::array<std::uint8_t, 8> length_le{};
    for (std::size_t i = 0; i < 8; ++i) {
        length_le[i] = static_cast<std::uint8_t>((total_bits >> (8 * i)) & 0xFF);
    }
    std::memcpy(buffer_.data() + buffer_len_, length_le.data(), 8);
    process_block(buffer_.data());
    buffer_len_ = 0;

    Digest out{};
    for (std::size_t i = 0; i < 4; ++i) {
        out[i * 4 + 0] = static_cast<std::uint8_t>(state_[i] & 0xFF);
        out[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFF);
        out[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFF);
        out[i * 4 + 3] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFF);
    }
    finalized_ = true;
    return out;
}

Md5::Digest Md5::hash(std::span<const std::uint8_t> data) {
    Md5 h;
    h.update(data);
    return h.finalize();
}

std::string Md5::hash_hex(std::span<const std::uint8_t> data) {
    Digest d = hash(data);
    return util::to_hex(d);
}

}
