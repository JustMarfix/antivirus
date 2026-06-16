#include "avcore/hashing/sha1.hpp"

#include "avcore/error.hpp"
#include "avcore/util/hex.hpp"

#include <array>
#include <bit>
#include <cstring>

// SHA-1 follows FIPS 180-4. Input is processed in 512-bit blocks using
// big-endian word order.

namespace av::hashing {

namespace {

std::uint32_t load_be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

}

Sha1::Sha1()
    : state_{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}, buffer_{}, bit_count_(0),
      buffer_len_(0), finalized_(false) {}

void Sha1::process_block(const std::uint8_t* block) {
    std::array<std::uint32_t, 80> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = load_be32(block + i * 4);
    }
    for (std::size_t i = 16; i < 80; ++i) {
        w[i] = std::rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];

    for (std::size_t i = 0; i < 80; ++i) {
        std::uint32_t f = 0;
        std::uint32_t k = 0;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        std::uint32_t tmp = std::rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = std::rotl(b, 30);
        b = a;
        a = tmp;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
}

void Sha1::update(std::span<const std::uint8_t> data) {
    if (finalized_) {
        throw InvalidArgument("Sha1::update called after finalize");
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

Sha1::Digest Sha1::finalize() {
    if (finalized_) {
        throw InvalidArgument("Sha1::finalize called twice");
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
    for (std::size_t i = 0; i < 5; ++i) {
        out[i * 4 + 0] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFF);
    }
    finalized_ = true;
    return out;
}

Sha1::Digest Sha1::hash(std::span<const std::uint8_t> data) {
    Sha1 h;
    h.update(data);
    return h.finalize();
}

std::string Sha1::hash_hex(std::span<const std::uint8_t> data) {
    Digest d = hash(data);
    return util::to_hex(d);
}

}
