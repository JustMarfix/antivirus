#pragma once

#include <cstdint>
#include <span>
#include <string_view>

/// @file test_support.hpp
/// @brief Small helpers shared by the test translation units.

namespace av::test {

/// @brief View a string literal as a span of bytes for hashing/matching APIs.
/// @param text Text to reinterpret.
/// @return Byte span aliasing @p text (valid for the lifetime of @p text).
inline std::span<const std::uint8_t> bytes(std::string_view text) {
    return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),
                                         text.size());
}

}
