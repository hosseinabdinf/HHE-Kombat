cmake_minimum_required(VERSION 3.10)
project(TinyAES C)

# Add AES CBC mode
add_definitions(-DCBC=1)

set(TINY_SRC
    aes.c
)

add_library(tiny STATIC ${TINY_SRC})

target_include_directories(tiny PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")