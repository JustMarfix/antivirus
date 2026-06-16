#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

/// @file elf_analyzer.hpp
/// @brief Static analysis of ELF binaries for security-relevant traits.

namespace av::analysis {

/// @brief High-level kind of an ELF object.
enum class ElfType {
    None,         ///< The input is not an ELF object.
    Relocatable,  ///< ET_REL (object file).
    Executable,   ///< ET_EXEC (fixed-address executable).
    SharedObject, ///< ET_DYN (shared library or PIE executable).
    Core,         ///< ET_CORE (core dump).
    Other         ///< A valid ELF of an unrecognised type.
};

/// @brief Facts extracted from an ELF binary.
struct ElfInfo {
    bool is_elf = false;                 ///< True if the input parsed as ELF.
    ElfType type = ElfType::None;        ///< Object kind.
    bool is_64bit = false;               ///< True for ELFCLASS64.
    std::string machine;                 ///< Human-readable architecture name.
    std::uint64_t entry = 0;             ///< Entry-point virtual address.
    bool has_interpreter = false;        ///< True if a PT_INTERP segment is present.
    bool has_write_exec_segment = false; ///< True if any segment is both writable and executable.
    std::size_t segment_count = 0;       ///< Number of program headers.
    std::size_t section_count = 0;       ///< Number of section headers.
    std::vector<std::string> section_names; ///< Names of all sections.
};

/// @brief Parse and analyse an ELF binary held in memory.
/// @param data Raw bytes of a candidate ELF object.
/// @return Extracted facts; @c is_elf is false if @p data is not ELF.
/// @throws av::ParseError if a valid ELF header is followed by corrupt tables.
ElfInfo analyze_elf(std::span<const std::uint8_t> data);

/// @brief Parse and analyse an ELF binary on disk.
/// @param path Path to the candidate ELF file.
/// @return Extracted facts; @c is_elf is false if the file is not ELF.
/// @throws av::IoError if the file cannot be read.
ElfInfo analyze_elf_file(const std::filesystem::path& path);

}
