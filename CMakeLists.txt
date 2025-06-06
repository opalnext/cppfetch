cmake_minimum_required(VERSION 3.10)
project(BMPtoASCII)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(cppfetch src/main.cpp)

# Define the output directory for the executable (optional, usually it's in CMAKE_BINARY_DIR)
set_target_properties(cppfetch PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Copy the icons folder next to the executable after build
add_custom_command(TARGET cppfetch POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/icons
    $<TARGET_FILE_DIR:cppfetch>/icons
)
