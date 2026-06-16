cmake_minimum_required(VERSION 3.24)

project(
    LinuxAntivirus
    VERSION 0.1.0
    DESCRIPTION "Modular antivirus for Linux: scanning core, monitoring daemon and GUI client"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE
        "RelWithDebInfo"
        CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(AV_BUILD_TESTS "Build the Doctest test suite" ON)
option(AV_BUILD_DAEMON "Build the monitoring daemon (Linux only)" ON)
option(AV_BUILD_CLIENT "Build the Slint GUI client" ON)
option(AV_ENABLE_YARA "Enable YARA rule scanning in the core" ON)
option(AV_ENABLE_EBPF "Enable the eBPF syscall monitor in the daemon" OFF)
option(AV_ENABLE_TRAY "Enable the system-tray icon in the GUI client (sd-bus)" ON)
option(AV_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

add_library(av_warnings INTERFACE)
target_compile_options(
    av_warnings
    INTERFACE -Wall
              -Wextra
              -Wpedantic
              -Wconversion
              -Wshadow)
if(AV_WARNINGS_AS_ERRORS)
    target_compile_options(av_warnings INTERFACE -Werror)
endif()

include(Dependencies)

add_subdirectory(libs/avcore)
add_subdirectory(apps)

set(AV_DAEMON_ENABLED OFF)
if(AV_BUILD_DAEMON AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(AV_DAEMON_ENABLED ON)
elseif(AV_BUILD_DAEMON)
    message(WARNING "AV_BUILD_DAEMON requested but target is not Linux; skipping daemon")
endif()

# avipc is needed by anything that speaks the IPC protocol.
if(AV_DAEMON_ENABLED OR AV_BUILD_CLIENT)
    add_subdirectory(libs/avipc)
endif()

if(AV_DAEMON_ENABLED)
    add_subdirectory(daemon)
endif()

if(AV_BUILD_CLIENT)
    add_subdirectory(client)
endif()

if(AV_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
