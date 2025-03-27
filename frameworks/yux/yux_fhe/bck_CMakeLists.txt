cmake_minimum_required(VERSION 3.16)

project(Yux LANGUAGES CXX)

## Use -std=c++17 as default.
set(CMAKE_CXX_STANDARD 17)
## Disable C++ extensions
set(CMAKE_CXX_EXTENSIONS OFF)
## Require full C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)

## if Debug 
set(CMAKE_BUILD_TYPE "Debug")


#set(CMAKE_CXX_)
#add_compile_options("-ferror-limit=40")

find_package(helib 2.2.0)
if (helib_NOTFOUND)
    message("helib have not found")
else()
    message("helib ${HELIB_VERSION} have found.)")
endif()


# add symmetric library
aux_source_directory("${CMAKE_SOURCE_DIR}/symmetric" SYMMETRIC_SRC_LIST)
add_library(Symmetric ${SYMMETRIC_SRC_LIST})

aux_source_directory("${CMAKE_SOURCE_DIR}/transciphering" TRANSCIPHER_SRC_LIST)
add_library(Transcipher ${TRANSCIPHER_SRC_LIST})
# add NTL include directory
target_include_directories(Transcipher PUBLIC "/usr/local/include")

message(STATUS "beark 1: ${TRANSCIPHER_SRC_LIST}")

add_subdirectory(tests)

#aux_source_directory("Symmetric/" SYMMETRIC_FILES)