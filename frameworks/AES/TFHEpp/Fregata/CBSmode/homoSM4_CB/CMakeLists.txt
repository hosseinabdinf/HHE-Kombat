# file(GLOB test_sources RELATIVE "${CMAKE_CURRENT_LIST_DIR}" "*.cpp")


# add_executable(homosm4 SM4.cpp SM4_homo.cpp)
# target_link_libraries(homosm4 tfhe++ utils)
include_directories(${CMAKE_SOURCE_DIR})

add_executable(sym_aes sym_aes.cpp AES.cpp)
target_link_libraries(sym_aes utils)

add_executable(hom_aes hom_aes.cpp AES.cpp)
target_link_libraries(hom_aes tfhe++ utils)

