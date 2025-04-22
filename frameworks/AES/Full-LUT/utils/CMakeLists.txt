cmake_minimum_required(VERSION 3.10)
project(Utils C)

message(STATUS ">>>> Building Utils")
set(UTILS_SRC
    utils.c
    printer.cpp
)

add_library(utils STATIC ${UTILS_SRC})

target_include_directories(utils PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")