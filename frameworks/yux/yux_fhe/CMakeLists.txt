cmake_minimum_required(VERSION 3.16)

project(Yux LANGUAGES CXX)

## Use -std=c++17 as default.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

## if Debug
set(CMAKE_BUILD_TYPE "Debug")

find_package(helib 2.2.0 QUIET)

if (NOT helib_FOUND)
    add_subdirectory(thirdparty)
endif ()

# Import HElib
find_package(helib 2.2.0 REQUIRED
        # Optionally providing a path so this can be built without installing HElib
        PATHS ${Yux_SOURCE_DIR}/thirdparty/HElib/install/share/cmake/helib
)

set(M4RI_PREFIX "${CMAKE_SOURCE_DIR}/thirdparty/m4ri/installed")
set(M4RI_INCLUDE_DIR "${M4RI_PREFIX}/include")
set(M4RI_LIB "${M4RI_PREFIX}/lib/libm4ri.so")


if (helib_FOUND)
    get_target_property(HELIB_INCLUDE_DIRS helib INTERFACE_INCLUDE_DIRECTORIES)
endif ()


# add symmetric library
aux_source_directory("${CMAKE_SOURCE_DIR}/symmetric" SYMMETRIC_SRC_LIST)
add_library(Symmetric ${SYMMETRIC_SRC_LIST})

aux_source_directory("${CMAKE_SOURCE_DIR}/transciphering" TRANSCIPHER_SRC_LIST)
add_library(Transcipher ${TRANSCIPHER_SRC_LIST})
# add NTL include directory
target_include_directories(Transcipher PUBLIC ${HELIB_INCLUDE_DIRS})

message(STATUS "beark 1: ${TRANSCIPHER_SRC_LIST}")

add_subdirectory(utils)

add_subdirectory(tests)

#aux_source_directory("Symmetric/" SYMMETRIC_FILES)
