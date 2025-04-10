cmake_minimum_required(VERSION 3.10)
project(BENCH_Utils C)

set(BENCH_UTILS_SRC
    bench_utils.c
    bench_printer.cpp
)

add_library(bench_utils STATIC ${BENCH_UTILS_SRC})

target_include_directories(bench_utils PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
