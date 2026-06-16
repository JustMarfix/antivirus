# avcore: the privilege-free scanning and protocol library shared by the daemon
# and the GUI client.

add_library(
    avcore STATIC
    src/util/hex.cpp
    src/util/file.cpp
    src/util/path.cpp
    src/util/unique_fd.cpp
    src/hashing/md5.cpp
    src/hashing/sha1.cpp
    src/hashing/sha256.cpp
    src/matching/aho_corasick.cpp
    src/scan/verdict.cpp
    src/scan/signature_database.cpp
    src/scan/file_scanner.cpp
    src/analysis/elf_analyzer.cpp
    src/quarantine/quarantine.cpp
    src/exclusions/exclusion_store.cpp)

add_library(av::core ALIAS avcore)

target_include_directories(avcore PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(avcore PRIVATE av_warnings elfio::elfio)

# Optional YARA rule-scanning support.
if(AV_HAVE_YARA)
    target_sources(avcore PRIVATE src/scan/yara_scanner.cpp)
    target_link_libraries(avcore PUBLIC av::yara)
    target_compile_definitions(avcore PUBLIC AV_HAVE_YARA=1)
endif()
