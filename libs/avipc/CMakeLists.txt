# avipc: the IPC message protocol (JSON over a length-prefixed framing) shared
# by the daemon and the GUI client.

add_library(avipc STATIC src/codec.cpp)
add_library(av::ipc ALIAS avipc)

target_include_directories(avipc PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(avipc PUBLIC av::core Boost::json PRIVATE av_warnings)
