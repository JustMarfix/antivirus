# Doctest suite.

include(doctest)

add_executable(
    avcore_tests
    test_main.cpp
    hex_tests.cpp
    path_tests.cpp
    hashing_tests.cpp
    aho_corasick_tests.cpp
    scan_tests.cpp
    elf_tests.cpp
    unique_fd_tests.cpp
    quarantine_tests.cpp
    exclusion_tests.cpp
    yara_tests.cpp)

target_link_libraries(avcore_tests PRIVATE av::core doctest::doctest av_warnings)

if(TARGET av::ipc)
    target_sources(avcore_tests PRIVATE ipc_tests.cpp)
    target_link_libraries(avcore_tests PRIVATE av::ipc)
endif()

if(TARGET av::daemon_core)
    target_sources(avcore_tests PRIVATE inotify_watcher_tests.cpp ebpf_event_tests.cpp)
    target_link_libraries(avcore_tests PRIVATE av::daemon_core)
endif()

doctest_discover_tests(avcore_tests)
