include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

find_package(Threads REQUIRED)

if(AV_BUILD_DAEMON OR AV_BUILD_CLIENT)
    find_package(Boost 1.74 REQUIRED COMPONENTS json)
endif()

if(AV_BUILD_TESTS)
    FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG v2.4.11
        GIT_SHALLOW ON
        SYSTEM)
    FetchContent_MakeAvailable(doctest)
    list(APPEND CMAKE_MODULE_PATH "${doctest_SOURCE_DIR}/scripts/cmake")
endif()

FetchContent_Declare(
    elfio
    GIT_REPOSITORY https://github.com/serge1/ELFIO.git
    GIT_TAG Release_3.12
    GIT_SHALLOW ON
    SYSTEM)
set(ELFIO_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ELFIO_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(elfio)

if(AV_BUILD_CLIENT)
    FetchContent_Declare(
        Slint
        GIT_REPOSITORY https://github.com/slint-ui/slint.git
        GIT_TAG release/1
        SOURCE_SUBDIR api/cpp
        SYSTEM)
    FetchContent_MakeAvailable(Slint)
endif()

find_path(MAGIC_INCLUDE_DIR magic.h)
find_library(MAGIC_LIBRARY NAMES magic)
if(MAGIC_INCLUDE_DIR AND MAGIC_LIBRARY)
    add_library(av::magic INTERFACE IMPORTED)
    target_include_directories(av::magic INTERFACE "${MAGIC_INCLUDE_DIR}")
    target_link_libraries(av::magic INTERFACE "${MAGIC_LIBRARY}")
    set(AV_HAVE_MAGIC ON)
else()
    message(WARNING "libmagic not found; file-type detection will be disabled")
    set(AV_HAVE_MAGIC OFF)
endif()

if(AV_ENABLE_YARA)
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(YARA IMPORTED_TARGET yara)
    endif()
    if(TARGET PkgConfig::YARA)
        add_library(av::yara ALIAS PkgConfig::YARA)
        set(AV_HAVE_YARA ON)
    else()
        find_path(YARA_INCLUDE_DIR yara.h)
        find_library(YARA_LIBRARY NAMES yara)
        if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
            add_library(av::yara INTERFACE IMPORTED)
            target_include_directories(av::yara INTERFACE "${YARA_INCLUDE_DIR}")
            target_link_libraries(av::yara INTERFACE "${YARA_LIBRARY}")
            set(AV_HAVE_YARA ON)
        else()
            message(WARNING "YARA requested but not found; disabling YARA support")
            set(AV_HAVE_YARA OFF)
        endif()
    endif()
else()
    set(AV_HAVE_YARA OFF)
endif()

if(AV_BUILD_CLIENT AND AV_ENABLE_TRAY)
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(SDBUS IMPORTED_TARGET libsystemd)
    endif()
    if(TARGET PkgConfig::SDBUS)
        add_library(av::sdbus ALIAS PkgConfig::SDBUS)
        set(AV_HAVE_SNI ON)
    else()
        message(WARNING "libsystemd not found; the GUI tray icon will be disabled")
        set(AV_HAVE_SNI OFF)
    endif()
else()
    set(AV_HAVE_SNI OFF)
endif()

if(AV_ENABLE_EBPF)
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBBPF IMPORTED_TARGET libbpf)
    endif()
    find_program(BPF_CLANG NAMES clang)
    if(TARGET PkgConfig::LIBBPF AND BPF_CLANG)
        add_library(av::bpf ALIAS PkgConfig::LIBBPF)
        set(AV_HAVE_EBPF ON)
    else()
        message(WARNING "eBPF requested but libbpf and/or clang not found; disabling")
        set(AV_HAVE_EBPF OFF)
    endif()
else()
    set(AV_HAVE_EBPF OFF)
endif()
