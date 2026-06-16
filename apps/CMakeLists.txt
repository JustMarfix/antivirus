# Command-line front-ends to the avcore engine.

add_executable(avscan avscan/main.cpp)
target_link_libraries(avscan PRIVATE av::core av_warnings)
