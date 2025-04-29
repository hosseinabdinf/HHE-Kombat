#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "OPENFHEcore_static" for configuration "Release"
set_property(TARGET OPENFHEcore_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OPENFHEcore_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C;CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libOPENFHEcore_static.a"
  )

list(APPEND _cmake_import_check_targets OPENFHEcore_static )
list(APPEND _cmake_import_check_files_for_OPENFHEcore_static "${_IMPORT_PREFIX}/lib/libOPENFHEcore_static.a" )

# Import target "OPENFHEpke_static" for configuration "Release"
set_property(TARGET OPENFHEpke_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OPENFHEpke_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libOPENFHEpke_static.a"
  )

list(APPEND _cmake_import_check_targets OPENFHEpke_static )
list(APPEND _cmake_import_check_files_for_OPENFHEpke_static "${_IMPORT_PREFIX}/lib/libOPENFHEpke_static.a" )

# Import target "OPENFHEbinfhe_static" for configuration "Release"
set_property(TARGET OPENFHEbinfhe_static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OPENFHEbinfhe_static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libOPENFHEbinfhe_static.a"
  )

list(APPEND _cmake_import_check_targets OPENFHEbinfhe_static )
list(APPEND _cmake_import_check_files_for_OPENFHEbinfhe_static "${_IMPORT_PREFIX}/lib/libOPENFHEbinfhe_static.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
