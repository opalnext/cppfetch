cmake_minimum_required(VERSION 3.10)
project(BMPtoASCII)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(cppfetch src/main.cpp)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/icons DESTINATION .)
