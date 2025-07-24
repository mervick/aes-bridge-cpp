cmake_minimum_required(VERSION 3.10)

project(AesBridgeCli CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

add_executable(cli
    cli.cpp
    ../src/common.cpp
    ../src/gcm.cpp
    ../src/cbc.cpp
    ../src/legacy.cpp
)

target_link_libraries(cli PRIVATE
    OpenSSL::Crypto
    OpenSSL::SSL
)

target_include_directories(cli PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/
)
