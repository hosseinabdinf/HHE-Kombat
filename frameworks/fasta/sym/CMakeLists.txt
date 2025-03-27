foreach(cipher IN ITEMS ${SYM_CIPHS})
    message(STATUS "Plain cipher: ${cipher}.c")
    set(SYM_SRCS ${SYM_SRCS}
        ${cipher}.c
    )
endforeach()

add_library(symciphers STATIC ${SYM_SRCS})
target_include_directories(symciphers PRIVATE ${GMP_INCLUDE_DIRS})
target_link_libraries(symciphers ${GMP_LIBRARIES} utils)

# Define where the input files are located
set(INPUT_FILES "originalPlaintext.txt")

# Copy input files to the build directory after building
add_custom_target(copy_input_files ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_SOURCE_DIR}/sym/${INPUT_FILES} ${CMAKE_BINARY_DIR}/
)

foreach(cipher IN ITEMS ${SYM_CIPHS})
    add_executable(fasta_sym_test ${cipher}.c Fasta.c bitVector.c)
    target_include_directories(fasta_sym_test PRIVATE ${GMP_INCLUDE_DIRS})
    target_link_libraries(fasta_sym_test ${GMP_LIBRARIES} utils)
    # Make sure input files are copied before the executable runs
    add_dependencies(fasta_sym_test copy_input_files)
endforeach()
