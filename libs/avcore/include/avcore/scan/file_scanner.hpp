#pragma once

#include "avcore/scan/signature_database.hpp"
#include "avcore/scan/verdict.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>

/// @file file_scanner.hpp
/// @brief Static, signature-based scanning of files and buffers.

namespace av::scan {

class YaraScanner;

/// @brief Scans buffers and files against a @ref SignatureDatabase.
///
/// The scanner checks the full-file MD5/SHA-1/SHA-256 digests against the hash
/// signatures, searches the content for byte-pattern signatures, and (when a
/// @ref YaraScanner is supplied) matches YARA rules. The database must be built
/// before scanning. The scanner keeps references to the database and optional
/// YARA scanner and does not own them.
class FileScanner {
  public:
    /// @brief Construct a scanner bound to a signature database.
    /// @param database Built signature database (must outlive the scanner).
    /// @param max_scan_bytes Largest amount of a file that is read and scanned.
    /// @param yara Optional compiled YARA scanner (must outlive the scanner).
    explicit FileScanner(const SignatureDatabase& database,
                         std::size_t max_scan_bytes = 64 * 1024 * 1024,
                         const YaraScanner* yara = nullptr);

    /// @brief Scan an in-memory buffer.
    /// @param data Bytes to scan.
    /// @param object_name Label echoed back in the result detail.
    /// @return The scan result.
    ScanResult scan_buffer(std::span<const std::uint8_t> data,
                           const std::string& object_name = {}) const;

    /// @brief Scan a file on disk.
    /// @param path Path to the file to scan.
    /// @return The scan result; Verdict::Error if the file cannot be read.
    ScanResult scan_file(const std::filesystem::path& path) const;

    /// @brief Scan the contents of an already-open file descriptor.
    ///
    /// The descriptor is read with @c pread and is never re-opened, which is the
    /// only safe way to scan a handle supplied by an fanotify event without
    /// triggering a new access event on the same file.
    /// @param fd Open, readable descriptor (not closed by this function).
    /// @param object_name Label echoed back in the result detail.
    /// @return The scan result; Verdict::Error if the descriptor cannot be read.
    ScanResult scan_fd(int fd, const std::string& object_name = {}) const;

  private:
    const SignatureDatabase& database_;
    std::size_t max_scan_bytes_;
    const YaraScanner* yara_;
};

}
