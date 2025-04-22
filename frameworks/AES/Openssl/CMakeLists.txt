cmake_minimum_required(VERSION 3.16)

project(AES_OpenSSL C)

set(CMAKE_C_STANDARD 11)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# add utils directory
add_subdirectory(utils)

include_directories(${CMAKE_SOURCE_DIR})
# Gather source files
set(SOURCES
    src/aes_encrypt.c
)

add_executable(aes_encrypt ${SOURCES})
target_link_libraries(aes_encrypt OpenSSL::Crypto utils)
