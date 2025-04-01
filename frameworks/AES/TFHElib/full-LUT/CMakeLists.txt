cmake_minimum_required( VERSION 3.19.2 )
set(CMAKE_BUILD_TYPE Release)

project (AES)

add_subdirectory(thirdparty)

set(TFHE_PREFIX "${CMAKE_SOURCE_DIR}/thirdparty/tfhe/installed")
message(STATUS ">>>>> TFHE_PREFIX: ${TFHE_PREFIX}")
set(TFHE_INCLUDE_DIR "${TFHE_PREFIX}/include")
set(TFHE_LIB "${TFHE_PREFIX}/lib/libtfhe-spqlios-avx.so")

add_subdirectory(utils)
add_subdirectory(sources)




