#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

/// @file exclusion_store.hpp
/// @brief User-managed list of paths excluded from scanning and quarantine.

namespace av::exclusions {

/// @brief A persisted set of files and directories that the scanner ignores.
///
/// An exclusion entry is an absolute path. A candidate path is considered
/// excluded when it equals an entry (a single excluded file) or lies beneath one
/// (an excluded directory) - both cases handled lexically by
/// @ref av::util::is_subpath. Entries are stored canonically so the textual
/// comparison is reliable.
///
/// The store optionally persists to a plain-text file (one path per line). When
/// constructed with an empty path it operates purely in memory. All filesystem
/// failures are reported through @ref av::IoError.
class ExclusionStore {
  public:
    /// @brief Open (and load) an exclusion store.
    /// @param persist_path File backing the list, or empty for in-memory only.
    /// @throws av::IoError if an existing backing file cannot be read.
    explicit ExclusionStore(std::filesystem::path persist_path = {});

    /// @brief Add a path to the exclusion list.
    /// @param path File or directory to exclude (canonicalised before storing).
    /// @return True if the entry was newly added, false if already present.
    /// @throws av::IoError if the list cannot be persisted.
    bool add(const std::string& path);

    /// @brief Remove a path from the exclusion list.
    /// @param path Entry to remove (matched after canonicalisation).
    /// @return True if an entry was removed, false if it was not present.
    /// @throws av::IoError if the list cannot be persisted.
    bool remove(const std::string& path);

    /// @brief List all excluded paths.
    /// @return The canonical entries currently held (sorted).
    std::vector<std::string> list() const;

    /// @brief Test whether a path is covered by an exclusion.
    /// @param path Candidate path; expected absolute and canonical.
    /// @return True if @p path equals or lies beneath any excluded entry.
    bool is_excluded(std::string_view path) const;

  private:
    void load();
    void save() const;
    static std::string canonical(const std::string& path);

    std::filesystem::path persist_path_;
    std::vector<std::string> entries_;
};

}
