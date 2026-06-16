#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

/// @file hex.hpp
/// @brief Helpers for converting between raw bytes and hexadecimal strings.

namespace av::util {

/// @brief Encode a byte range as a lowercase hexadecimal string.
/// @param bytes Range of bytes to encode.
/// @return Hexadecimal representation, two characters per input byte.
std::string to_hex(std::span<const std::uint8_t> bytes);

/// @brief Decode a hexadecimal string into raw bytes.
/// @param hex Hexadecimal string with an even number of [0-9a-fA-F] characters.
/// @return Decoded bytes.
/// @throws av::InvalidArgument if the string has odd length or invalid digits.
std::string from_hex(std::string_view hex);

}
