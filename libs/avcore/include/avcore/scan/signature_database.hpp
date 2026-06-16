#pragma once

#include "avcore/matching/aho_corasick.hpp"
#include "avcore/scan/verdict.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

/// @file signature_database.hpp
/// @brief Storage and lookup for malware signatures.

namespace av::scan {

/// @brief A collection of malware signatures usable by the scanner.
///
/// Two signature kinds are supported:
/// - hash signatures: a full-file MD5/SHA-1/SHA-256 digest identifying a known
///   sample;
/// - content signatures: a byte pattern that, if present anywhere in a file,
///   indicates a threat. Content signatures are matched in a single pass with
///   the Aho-Corasick.
///
/// Call @ref build once after loading all signatures and before scanning.
class SignatureDatabase {
  public:
    /// @brief Construct an empty database.
    SignatureDatabase();

    /// @brief Register a hash signature.
    /// @param hex_digest Lowercase or uppercase hexadecimal digest (any length).
    /// @param threat_name Name reported when a file's digest matches.
    /// @throws av::InvalidArgument if @p hex_digest is not valid hexadecimal.
    void add_hash_signature(const std::string& hex_digest, const std::string& threat_name);

    /// @brief Register a content (byte-pattern) signature.
    /// @param pattern Non-empty byte pattern to search for.
    /// @param threat_name Name reported when the pattern is found.
    /// @throws av::InvalidArgument if @p pattern is empty or after @ref build.
    void add_content_signature(std::span<const std::uint8_t> pattern,
                               const std::string& threat_name);

    /// @brief Load signatures from a text database file.
    ///
    /// Each non-empty, non-comment line has the form `type:value:name` where
    /// @c type is `hash` (value is a hex digest) or `hex` (value is a
    /// hex-encoded byte pattern). Lines starting with `#` are comments.
    /// @param path Path to the database file.
    /// @throws av::IoError if the file cannot be read.
    /// @throws av::ParseError on a malformed line.
    void load_from_file(const std::filesystem::path& path);

    /// @brief Finalise the content-signature automaton.
    void build();

    /// @brief Look up a full-file digest among the hash signatures.
    /// @param hex_digest Hexadecimal digest to query.
    /// @return The threat name if known, std::nullopt otherwise.
    std::optional<std::string> match_hash(const std::string& hex_digest) const;

    /// @brief Search a buffer for content signatures.
    /// @param data Bytes to scan.
    /// @return The first matching threat name, std::nullopt if none match.
    /// @throws av::InvalidArgument if @ref build has not been called.
    std::optional<std::string> match_content(std::span<const std::uint8_t> data) const;

    /// @brief Number of registered hash signatures.
    std::size_t hash_signature_count() const noexcept { return hashes_.size(); }

    /// @brief Number of registered content signatures.
    std::size_t content_signature_count() const noexcept { return pattern_names_.size(); }

  private:
    std::unordered_map<std::string, std::string> hashes_;
    matching::AhoCorasick automaton_;
    std::vector<std::string> pattern_names_;
    bool built_;
};

}
