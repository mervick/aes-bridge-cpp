cmake_minimum_required(VERSION 3.10)

project(AES_BRIDGE CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# COMPONENTS specify which parts of OpenSSL are needed (Crypto, SSL)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

add_executable(aes_bridge_app
    src/main.cpp
    src/common.cpp
    src/gcm.cpp
    src/cbc.cpp
    src/legacy.cpp
)

target_link_libraries(aes_bridge_app
    OpenSSL::Crypto
    OpenSSL::SSL
)

target_include_directories(aes_bridge_app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Optional: Install rules to install executable
# install(TARGETS aes_bridge_app DESTINATION bin)
