# avdaemon: the privileged real-time monitoring service.

add_library(
    avdaemon_core STATIC
    src/daemon.cpp
    src/fanotify_monitor.cpp
    src/inotify_watcher.cpp
    src/recursive_watcher.cpp
    src/ipc_server.cpp
    src/ebpf_event.cpp)
add_library(av::daemon_core ALIAS avdaemon_core)

target_include_directories(
    avdaemon_core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/bpf")
target_link_libraries(
    avdaemon_core
    PUBLIC av::core av::ipc Boost::json Threads::Threads
    PRIVATE av_warnings)

if(AV_HAVE_EBPF)
    set(bpf_src "${CMAKE_CURRENT_SOURCE_DIR}/bpf/syscall_monitor.bpf.c")
    set(bpf_obj "${CMAKE_CURRENT_BINARY_DIR}/syscall_monitor.bpf.o")
    set(bpf_embed "${CMAKE_CURRENT_BINARY_DIR}/syscall_monitor_bpf.c")

    add_custom_command(
        OUTPUT "${bpf_obj}"
        COMMAND "${BPF_CLANG}" -target bpf -D__TARGET_ARCH_x86 -O2 -g
                -I "${CMAKE_CURRENT_SOURCE_DIR}/bpf" -c "${bpf_src}" -o "${bpf_obj}"
        DEPENDS "${bpf_src}" "${CMAKE_CURRENT_SOURCE_DIR}/bpf/syscall_event.h"
        COMMENT "Compiling BPF program (clang -target bpf)"
        VERBATIM)

    add_custom_command(
        OUTPUT "${bpf_embed}"
        COMMAND
            "${CMAKE_COMMAND}" -DINPUT=${bpf_obj} -DOUTPUT=${bpf_embed}
            -DSYMBOL=av_syscall_monitor_bpf -P "${CMAKE_SOURCE_DIR}/cmake/EmbedFile.cmake"
        DEPENDS "${bpf_obj}" "${CMAKE_SOURCE_DIR}/cmake/EmbedFile.cmake"
        COMMENT "Embedding BPF object into the daemon"
        VERBATIM)

    target_sources(avdaemon_core PRIVATE src/ebpf_monitor.cpp "${bpf_embed}")
    target_link_libraries(avdaemon_core PUBLIC av::bpf)
    target_compile_definitions(avdaemon_core PUBLIC AV_HAVE_EBPF=1)
endif()

add_executable(avdaemon src/main.cpp)
target_link_libraries(avdaemon PRIVATE av::daemon_core av_warnings)

install(TARGETS avdaemon RUNTIME DESTINATION bin)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/avdaemon.service"
        DESTINATION lib/systemd/system)
