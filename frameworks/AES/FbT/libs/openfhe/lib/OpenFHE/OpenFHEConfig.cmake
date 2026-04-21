# - Config file for the OpenFHE package
# It defines the following variables
#  OpenFHE_INCLUDE_DIRS - include directories for OpenFHE
#  OpenFHE_LIBRARIES    - libraries to link against

get_filename_component(OpenFHE_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Our library dependencies (contains definitions for IMPORTED targets)
if(NOT OpenFHE_BINARY_DIR)
  include("${OpenFHE_CMAKE_DIR}/OpenFHETargets.cmake")
endif()

# These are IMPORTED targets created by OpenFHETargets.cmake
set(OpenFHE_INCLUDE "/root/Hossein/implementations/HHE-Kombat/frameworks/AES/FbT/libs/openfhe/include/openfhe")
set(OpenFHE_LIBDIR "/root/Hossein/implementations/HHE-Kombat/frameworks/AES/FbT/libs/openfhe/lib")
set(OpenFHE_LIBRARIES OPENFHEcore_static;OPENFHEpke_static;OPENFHEbinfhe_static  )
set(OpenFHE_STATIC_LIBRARIES OPENFHEcore_static;OPENFHEpke_static;OPENFHEbinfhe_static  )
set(OpenFHE_SHARED_LIBRARIES   )
set(BASE_OPENFHE_VERSION 1.1.1)

set(OPENMP_INCLUDES "" )
set(OPENMP_LIBRARIES "" )

set(OpenFHE_CXX_FLAGS " -Wall -Werror -O3 -march=native -DOPENFHE_VERSION=1.1.1  -Wno-unused-private-field -Wno-shift-op-parentheses -DMATHBACKEND=4 -Wno-unknown-pragmas")
set(OpenFHE_C_FLAGS " -Wall -Werror -O3 -march=native -DOPENFHE_VERSION=1.1.1 -DMATHBACKEND=4 -Wno-unknown-pragmas")

if( "OFF" STREQUAL "Y" )
	set(OpenFHE_CXX_FLAGS "${OpenFHE_CXX_FLAGS} -DWITH_NTL" )
	set(OpenFHE_C_FLAGS "${OpenFHE_C_FLAGS} -DWITH_NTL")
endif()

set (OpenFHE_EXE_LINKER_FLAGS "")

# CXX info
set(OpenFHE_CXX_STANDARD "17")
set(OpenFHE_CXX_COMPILER_ID "Clang")
set(OpenFHE_CXX_COMPILER_VERSION "16.0.6")

# Build Options
set(OpenFHE_STATIC "ON")
set(OpenFHE_SHARED "OFF")
set(OpenFHE_TCM "OFF")
set(OpenFHE_OPENMP "OFF")
set(OpenFHE_NATIVE_SIZE "64")
set(OpenFHE_CKKS_M_FACTOR "1")
set(OpenFHE_NATIVEOPT "ON")

# Math Backend
set(OpenFHE_BACKEND "4")

# Build Details
set(OpenFHE_EMSCRIPTEN "")
set(OpenFHE_ARCHITECTURE "x86_64")
set(OpenFHE_BACKEND_FLAGS_BASE "-DMATHBACKEND=4")

# Compile Definitions

if( "OFF" )
	set(OpenFHE_BINFHE_COMPILE_DEFINITIONS "")
	set(OpenFHE_CORE_COMPILE_DEFINITIONS "")
	set(OpenFHE_PKE_COMPILE_DEFINITIONS "")
	set(OpenFHE_COMPILE_DEFINITIONS
			${OpenFHE_BINFHE_COMPILE_DEFINITIONS}
			${OpenFHE_CORE_COMPILE_DEFINITIONS}
			${OpenFHE_PKE_COMPILE_DEFINITIONS})
endif()

if( "ON" )
	set(OpenFHE_BINFHE_COMPILE_DEFINITIONS_STATIC "_compile_defs_static-NOTFOUND")
	set(OpenFHE_CORE_COMPILE_DEFINITIONS_STATIC "_compile_defs_static-NOTFOUND")
	set(OpenFHE_PKE_COMPILE_DEFINITIONS_STATIC "_compile_defs_static-NOTFOUND")
	set(OpenFHE_COMPILE_DEFINITIONS_STATIC
			${OpenFHE_BINFHE_COMPILE_DEFINITIONS_STATIC}
			${OpenFHE_CORE_COMPILE_DEFINITIONS_STATIC}
			${OpenFHE_PKE_COMPILE_DEFINITIONS_STATIC})
endif()
