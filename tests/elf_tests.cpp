#include "avcore/analysis/elf_analyzer.hpp"
#include "test_support.hpp"

#include <algorithm>
#include <doctest/doctest.h>

using namespace av;
using av::test::bytes;

TEST_CASE("analyze_elf_file recognises a real ELF binary") {
    analysis::ElfInfo info = analysis::analyze_elf_file("/proc/self/exe");

    CHECK(info.is_elf);
    CHECK(info.is_64bit);
    CHECK(info.machine == "x86-64");
    CHECK(info.section_count > 0);
    CHECK(info.segment_count > 0);
    CHECK_FALSE(info.section_names.empty());
    bool has_text = std::find(info.section_names.begin(), info.section_names.end(), ".text") !=
                    info.section_names.end();
    CHECK(has_text);
}

TEST_CASE("analyze_elf rejects non-ELF input gracefully") {
    SUBCASE("plain text is not ELF") {
        analysis::ElfInfo info = analysis::analyze_elf(bytes("#!/bin/sh\necho hi\n"));
        CHECK_FALSE(info.is_elf);
        CHECK(info.type == analysis::ElfType::None);
    }
    SUBCASE("a bare magic without a valid header is not ELF") {
        std::array<std::uint8_t, 4> fake_magic = {0x7f, 'E', 'L', 'F'};
        analysis::ElfInfo info = analysis::analyze_elf(fake_magic);
        CHECK_FALSE(info.is_elf);
    }
}
