cmake_minimum_required(VERSION 3.10)

project(AesBridge_Tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(GTest REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)


add_executable(aes_bridge_tests
    aes_bridge_tests.cpp
    ../src/common.cpp
    ../src/gcm.cpp
    ../src/cbc.cpp
    ../src/legacy.cpp
)

target_link_libraries(aes_bridge_tests PRIVATE
    GTest::gtest_main
    GTest::gtest
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
    OpenSSL::SSL
)

target_include_directories(aes_bridge_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/
)

add_test(NAME run_tests COMMAND aes_bridge_tests)
