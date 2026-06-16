#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

/// @file file.hpp
/// @brief Filesystem helpers built on RAII streams (no manual memory).

namespace av::util {

/// @brief Read a whole file into memory.
/// @param path Path to the file to read.
/// @param max_bytes Optional upper bound; reading stops once it is reached.
/// @return The file contents as raw bytes.
/// @throws av::IoError if the file cannot be opened or read.
std::vector<std::uint8_t> read_file(const std::filesystem::path& path,
                                    std::size_t max_bytes = SIZE_MAX);

/// @brief Read the contents of an already-open file descriptor into memory.
///
/// Reading is performed with @c pread starting at offset zero, so the
/// descriptor's own file offset is left untouched and no @c open is issued by
/// the caller. This is the safe way to inspect a file handed to us by the
/// kernel (e.g. an fanotify event fd), avoiding a fresh open that could
/// re-trigger the very event being handled.
/// @param fd Open, readable file descriptor (not closed by this function).
/// @param max_bytes Optional upper bound; reading stops once it is reached.
/// @return The bytes read from @p fd.
/// @throws av::IoError on a read error.
std::vector<std::uint8_t> read_fd(int fd, std::size_t max_bytes = SIZE_MAX);

}
