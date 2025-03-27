include_directories(${CMAKE_SOURCE_DIR})
include_directories("${CMAKE_SOURCE_DIR}/symmetric")
include_directories("${CMAKE_SOURCE_DIR}/transciphering")


add_executable(test-blockcipher         test-blockcipher.cpp)
add_executable(test-blockcipher-F_p     test-blockcipher-F_p.cpp)

add_executable(test-trans-F_p-16        test-transciphering-F_p-16.cpp)
add_executable(test-trans-F_p-1         test-transciphering-F_p-1.cpp)

add_executable(test-transciphering16    test-transciphering16.cpp)
add_executable(test-transciphering4     test-transciphering4.cpp)
add_executable(test-transciphering1     test-transciphering1.cpp)
add_executable(test-expand16            test-expand16.cpp)

#message("${SYMMETRIC_FILES}")
#message("${CMAKE_SOURCE_DIR}/Symmetric/")

target_link_libraries(test-blockcipher Symmetric)
target_link_libraries(test-blockcipher-F_p Symmetric)
target_link_libraries(test-trans-F_p-16 PUBLIC Transcipher Symmetric helib utils)
target_link_libraries(test-trans-F_p-1 PUBLIC Transcipher Symmetric helib utils)

target_link_libraries(test-transciphering16 PUBLIC Transcipher Symmetric helib)
target_link_libraries(test-transciphering4  PUBLIC Transcipher Symmetric helib)
target_link_libraries(test-transciphering1  PUBLIC Transcipher Symmetric helib)
target_link_libraries(test-expand16         PUBLIC Transcipher Symmetric helib)
