#include "avcore/analysis/elf_analyzer.hpp"

#include "avcore/error.hpp"
#include "avcore/util/file.hpp"

#include <elfio/elfio.hpp>
#include <sstream>

namespace av::analysis {

namespace {

ElfType map_type(ELFIO::Elf_Half type) {
    switch (type) {
    case ELFIO::ET_REL:
        return ElfType::Relocatable;
    case ELFIO::ET_EXEC:
        return ElfType::Executable;
    case ELFIO::ET_DYN:
        return ElfType::SharedObject;
    case ELFIO::ET_CORE:
        return ElfType::Core;
    default:
        return ElfType::Other;
    }
}

std::string map_machine(ELFIO::Elf_Half machine) {
    switch (machine) {
    case ELFIO::EM_386:
        return "x86";
    case ELFIO::EM_X86_64:
        return "x86-64";
    case ELFIO::EM_ARM:
        return "arm";
    case ELFIO::EM_AARCH64:
        return "aarch64";
    case ELFIO::EM_RISCV:
        return "riscv";
    default:
        return "unknown(" + std::to_string(machine) + ")";
    }
}

ElfInfo analyze_reader(ELFIO::elfio& reader) {
    ElfInfo info;
    info.is_elf = true;
    info.type = map_type(reader.get_type());
    info.is_64bit = reader.get_class() == ELFIO::ELFCLASS64;
    info.machine = map_machine(reader.get_machine());
    info.entry = reader.get_entry();
    info.segment_count = reader.segments.size();
    info.section_count = reader.sections.size();

    for (const auto& segment : reader.segments) {
        ELFIO::Elf_Word flags = segment->get_flags();
        bool writable = (flags & ELFIO::PF_W) != 0;
        bool executable = (flags & ELFIO::PF_X) != 0;
        if (writable && executable) {
            info.has_write_exec_segment = true;
        }
        if (segment->get_type() == ELFIO::PT_INTERP) {
            info.has_interpreter = true;
        }
    }

    for (const auto& section : reader.sections) {
        info.section_names.push_back(section->get_name());
    }
    return info;
}

}

ElfInfo analyze_elf(std::span<const std::uint8_t> data) {
    std::string buffer(reinterpret_cast<const char*>(data.data()), data.size());
    std::istringstream stream(buffer, std::ios::binary);

    ELFIO::elfio reader;
    if (!reader.load(stream)) {
        return ElfInfo{};
    }
    try {
        return analyze_reader(reader);
    } catch (const std::exception& e) {
        throw ParseError(std::string("analyze_elf: ") + e.what());
    }
}

ElfInfo analyze_elf_file(const std::filesystem::path& path) {
    std::vector<std::uint8_t> data = util::read_file(path);
    return analyze_elf(data);
}

}
