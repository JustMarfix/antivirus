#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>

/// @file yara_scanner.hpp
/// @brief Wrapper around the YARA engine for rule-based scanning.
///
/// The handles are kept as opaque pointers so this header does not depend on
/// @c yara.h; only the implementation does. Available when the project is built
/// with YARA support.

namespace av::scan {

/// @brief Compiles YARA rules and scans buffers/files against them.
///
/// Add rules with @ref add_rules_file and/or @ref add_rules_string, finalise
/// them with @ref compile, then scan. Failures are reported via @ref av::ScanError
/// (compilation/scan) and @ref av::IoError (file access).
class YaraScanner {
  public:
    /// @brief Initialise the YARA engine and a fresh rule compiler.
    /// @throws av::ScanError if YARA cannot be initialised.
    YaraScanner();

    /// @brief Finalise and release all YARA resources.
    ~YaraScanner();

    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;

    /// @brief Add rules from a @c .yar source file.
    /// @param path Path to the rules file.
    /// @throws av::IoError if the file cannot be opened.
    /// @throws av::ScanError if the rules fail to compile.
    /// @throws av::InvalidArgument if called after @ref compile.
    void add_rules_file(const std::filesystem::path& path);

    /// @brief Add rules from a file, or from every rules file in a directory.
    ///
    /// When @p path is a directory it is searched recursively for files with a
    /// @c .yar or @c .yara extension; they are loaded in lexicographically sorted
    /// order so compilation is deterministic. A plain file is loaded as-is.
    /// @param path Rules file or a directory of rules files.
    /// @return The number of rule files loaded (1 for a single file).
    /// @throws av::IoError if @p path does not exist or a file cannot be opened.
    /// @throws av::ScanError if any rules fail to compile.
    /// @throws av::InvalidArgument if called after @ref compile.
    std::size_t add_rules_path(const std::filesystem::path& path);

    /// @brief Add rules from an in-memory string.
    /// @param rules YARA rule source text.
    /// @throws av::ScanError if the rules fail to compile.
    /// @throws av::InvalidArgument if called after @ref compile.
    void add_rules_string(const std::string& rules);

    /// @brief Finalise compilation; required before scanning.
    /// @throws av::ScanError if rule generation fails.
    void compile();

    /// @brief Scan a buffer.
    /// @param data Bytes to scan.
    /// @return The first matching rule name, or std::nullopt.
    /// @throws av::InvalidArgument if @ref compile has not been called.
    /// @throws av::ScanError on a scanning failure.
    std::optional<std::string> scan_buffer(std::span<const std::uint8_t> data) const;

    /// @brief Scan a file (read into memory and matched).
    /// @param path Path to the file.
    /// @return The first matching rule name, or std::nullopt.
    /// @throws av::IoError if the file cannot be read.
    std::optional<std::string> scan_file(const std::filesystem::path& path) const;

    /// @brief Whether @ref compile has produced a usable rule set.
    bool ready() const noexcept { return rules_ != nullptr; }

  private:
    void* compiler_ = nullptr; // YR_COMPILER*
    void* rules_ = nullptr;    // YR_RULES*
};

}
