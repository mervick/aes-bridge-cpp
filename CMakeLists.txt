cmake_minimum_required(VERSION 3.10)

project(AesBridge CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

add_library(AesBridge STATIC
    src/common.cpp
    src/gcm.cpp
    src/cbc.cpp
    src/legacy.cpp
)

target_link_libraries(AesBridge
    OpenSSL::Crypto
    OpenSSL::SSL
)

target_include_directories(AesBridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

option(BUILD_AESBRIDGE_CLI "Build CLI for AesBridge library" OFF)

if(BUILD_AESBRIDGE_CLI)
    add_subdirectory(cli)
endif()

option(BUILD_AESBRIDGE_TESTS "Build tests for AesBridge library" OFF)

if(BUILD_AESBRIDGE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
