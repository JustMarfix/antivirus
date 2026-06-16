#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

/// @file quarantine.hpp
/// @brief Isolation store for files identified as malicious.

namespace av::quarantine {

/// @brief A record describing one quarantined file.
struct QuarantineEntry {
    std::string id;                  ///< Opaque identifier of the entry.
    std::string original_path;       ///< Absolute path the file was moved from.
    std::string threat_name;         ///< Threat that triggered quarantining.
    std::int64_t quarantined_at = 0; ///< Quarantine time (Unix seconds).
};

/// @brief Moves suspicious files into a protected store and back.
///
/// Quarantining relocates a file into an owner-only store directory, strips its
/// execute/permission bits, and records the metadata needed to restore it later.
/// All filesystem failures are reported through @ref av::IoError; references to
/// unknown entries through @ref av::InvalidArgument.
class Quarantine {
  public:
    /// @brief Open (creating if needed) a quarantine store.
    /// @param store_dir Directory holding quarantined files and metadata.
    /// @throws av::IoError if the directory cannot be created or accessed.
    explicit Quarantine(std::filesystem::path store_dir);

    /// @brief Move a file into quarantine.
    /// @param path File to isolate.
    /// @param threat_name Threat name to record with the entry.
    /// @return The created entry.
    /// @throws av::IoError if @p path cannot be read or moved.
    QuarantineEntry quarantine_file(const std::filesystem::path& path,
                                    const std::string& threat_name);

    /// @brief List all quarantined entries.
    /// @return Entries currently held in the store (unspecified order).
    /// @throws av::IoError if the store cannot be read.
    std::vector<QuarantineEntry> list() const;

    /// @brief Look up a single entry.
    /// @param id Identifier of the entry.
    /// @return The entry.
    /// @throws av::InvalidArgument if no such entry exists.
    QuarantineEntry get(const std::string& id) const;

    /// @brief Restore a quarantined file to its original location.
    /// @param id Identifier of the entry.
    /// @throws av::InvalidArgument if no such entry exists.
    /// @throws av::IoError if the original location is occupied or unwritable.
    void restore(const std::string& id);

    /// @brief Permanently delete a quarantined file and its metadata.
    /// @param id Identifier of the entry.
    /// @throws av::InvalidArgument if no such entry exists.
    void remove(const std::string& id);

    /// @brief Path of the store directory.
    const std::filesystem::path& store_dir() const noexcept { return store_dir_; }

  private:
    std::filesystem::path data_path(const std::string& id) const;
    std::filesystem::path meta_path(const std::string& id) const;
    QuarantineEntry read_meta(const std::filesystem::path& meta) const;

    std::filesystem::path store_dir_;
};

}
