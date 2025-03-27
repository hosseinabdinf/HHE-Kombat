# HELib Ciphers ==================================================================
foreach(cipher IN ITEMS ${HELIB_CIPHS})
    message(STATUS ">>>  HELib cipher: ${cipher}/${cipher}_helib.cpp")
    set(HELib_SRCS ${HELib_SRCS} ${cipher}/${cipher}_helib.cpp)
endforeach()

add_library(helibciphers STATIC ${HELib_SRCS})
target_include_directories(helibciphers PRIVATE ${GMP_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/.. ${M4RI_INCLUDE_DIR})
target_link_libraries(helibciphers helib ${M4RI_LIB} ${GMP_LIBRARIES} utils)

foreach(cipher IN ITEMS ${HELIB_CIPHS})
    set(BINARY_DIR ${CMAKE_BINARY_DIR}/${cipher}_helib_bin)
    file(MAKE_DIRECTORY ${BINARY_DIR}) # Create binary directory

    add_executable(${cipher}_helib_test ${cipher}/${cipher}_helib.cpp)
    target_include_directories(${cipher}_helib_test PRIVATE ${GMP_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/.. ${M4RI_INCLUDE_DIR})
    target_link_libraries(${cipher}_helib_test helib ${M4RI_LIB} ${GMP_LIBRARIES} utils)
    set_target_properties(${cipher}_helib_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BINARY_DIR})

    # Copy text files
    file(GLOB TXT_FILES "${CMAKE_SOURCE_DIR}/hhe/${cipher}/matrix_*.txt")
    foreach(txt_file IN LISTS TXT_FILES)
        # message(STATUS "Copying ${txt_file} to ${BINARY_DIR}")
        configure_file(${txt_file} ${BINARY_DIR} COPYONLY)
    endforeach()
endforeach()

# TFHE Ciphers ==================================================================
foreach(cipher IN ITEMS ${TFHE_CIPHS})
    message(STATUS ">>>  TFHE cipher: ${cipher}/${cipher}.c")
    set(TFHE_SRCS ${TFHE_SRCS} ${cipher}/${cipher}.c)
endforeach()

add_library(tfheciphers STATIC ${TFHE_SRCS})
target_include_directories(tfheciphers PRIVATE ${TFHE_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/..)
target_link_libraries(tfheciphers ${TFHE_LIB} utils)

foreach(cipher IN ITEMS ${TFHE_CIPHS})
    set(BINARY_DIR ${CMAKE_BINARY_DIR}/${cipher}_bin)
    file(MAKE_DIRECTORY ${BINARY_DIR})

    add_executable(${cipher}_test ${cipher}/${cipher}.c)
    target_include_directories(${cipher}_test PRIVATE ${TFHE_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/..)
    target_link_libraries(${cipher}_test ${TFHE_LIB} utils)
    set_target_properties(${cipher}_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BINARY_DIR})

    file(GLOB TXT_FILES "${CMAKE_SOURCE_DIR}/hhe/${cipher}/matrix_*.txt")
    foreach(txt_file IN LISTS TXT_FILES)
        configure_file(${txt_file} ${BINARY_DIR} COPYONLY)
    endforeach()
endforeach()
# ===============================================================================