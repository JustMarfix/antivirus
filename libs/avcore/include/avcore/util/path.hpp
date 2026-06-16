#pragma once

#include <string_view>

/// @file path.hpp
/// @brief Lexical path helpers.

namespace av::util {

/// @brief Test whether one path lies within a directory, lexically.
///
/// The comparison is purely textual: both arguments are expected to be absolute
/// and canonical (e.g. as produced by reading @c /proc/self/fd or
/// @c std::filesystem::weakly_canonical). Trailing slashes on @p prefix are
/// ignored. A path equal to @p prefix counts as inside it.
/// @param path Candidate path.
/// @param prefix Directory that may contain @p path.
/// @return True if @p path is @p prefix or nested under it.
bool is_subpath(std::string_view path, std::string_view prefix);

}
