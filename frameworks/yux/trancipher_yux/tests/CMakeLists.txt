include_directories(${CMAKE_SOURCE_DIR})
include_directories("${CMAKE_SOURCE_DIR}/symmetric")
include_directories("${CMAKE_SOURCE_DIR}/transciphering")


add_executable(test-Yu2x-8         test-Yu2x-8.cpp)
add_executable(test-Yu2x-16        test-Yu2x-16.cpp)
add_executable(test-Yupx-p         test-Yupx-p.cpp)

add_executable(test-trans-Yupx-p-16        test-trans-Yupx-p-C16.cpp)

add_executable(test-trans-Yu2x-16-C16    test-trans-Yu2x-16-C16.cpp)

add_executable(test-trans-Yu2x-8-C16    test-trans-Yu2x-8-C16.cpp)
add_executable(test-trans-Yu2x-8-C4     test-trans-Yu2x-8-C4.cpp)
add_executable(test-trans-Yu2x-8-C1     test-trans-Yu2x-8-C1.cpp)
add_executable(test-expand16            test-expand16.cpp)

#message("${SYMMETRIC_FILES}")
#message("${CMAKE_SOURCE_DIR}/Yux/")

target_link_libraries(test-Yu2x-8                   Symmetric)
target_link_libraries(test-Yu2x-16      PUBLIC  Symmetric helib)
target_link_libraries(test-Yupx-p                   Symmetric)

target_link_libraries(test-trans-Yupx-p-16  PUBLIC Transcipher Symmetric helib)

target_link_libraries(test-trans-Yu2x-16-C16 PUBLIC Transcipher Symmetric helib)

target_link_libraries(test-trans-Yu2x-8-C16 PUBLIC Transcipher Symmetric helib)
target_link_libraries(test-trans-Yu2x-8-C4  PUBLIC Transcipher Symmetric helib)
target_link_libraries(test-trans-Yu2x-8-C1  PUBLIC Transcipher Symmetric helib)

target_link_libraries(test-expand16         PUBLIC Transcipher Symmetric helib)

add_executable(test-findM    findM.cpp)

target_link_libraries(test-findM         PUBLIC Transcipher helib)


