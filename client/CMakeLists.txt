# avclient: the Slint GUI front-end.

set(AVCLIENT_SOURCES src/main.cpp src/ipc_client.cpp src/desktop_notifier.cpp)
if(AV_HAVE_SNI)
    list(APPEND AVCLIENT_SOURCES src/tray_icon.cpp)
endif()

add_executable(avclient ${AVCLIENT_SOURCES})

if(AV_HAVE_SNI)
    target_compile_definitions(avclient PRIVATE AV_HAVE_SNI)
    target_link_libraries(avclient PRIVATE av::sdbus)
endif()

target_link_libraries(
    avclient
    PRIVATE av::core
            av::ipc
            Boost::json
            Threads::Threads
            Slint::Slint)

slint_target_sources(avclient ui/app.slint)

install(TARGETS avclient RUNTIME DESTINATION bin)
