# utcp_core: the sans-I/O protocol core. No system calls, no I/O, no threads,
# no clocks, no global mutable state, no exceptions (DESIGN §2.2, §13).
# tests/CMakeLists.txt checks the archive's undefined symbols against
# cmake/CheckCoreSymbols.cmake and the sources for floating point
# (ci/check-no-float.sh). Sources: every *.cpp under src/core.
utcp_glob_sources(utcp_core_sources ${CMAKE_CURRENT_SOURCE_DIR})
add_library(utcp_core STATIC ${utcp_core_sources})
add_library(utcp::core ALIAS utcp_core)

target_include_directories(utcp_core
  PUBLIC ${PROJECT_SOURCE_DIR}/include
  PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_options(utcp_core PRIVATE -fno-exceptions)
utcp_target_warnings(utcp_core STRICT)

# The core's internal headers (#include "core/..."), for the simulator, tests,
# test support and fuzz targets.
add_library(utcp_core_internal INTERFACE)
target_include_directories(utcp_core_internal INTERFACE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(utcp_core_internal INTERFACE utcp_core)

# Every core and public header compiles on its own with the core's flags:
# the interface headers of src/core/tcp are handed to other tasks before any
# source file includes them. One generated file per header, compiled only.
file(GLOB_RECURSE utcp_core_headers CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp ${PROJECT_SOURCE_DIR}/include/utcp/*.hpp)
list(SORT utcp_core_headers)
set(utcp_header_check_sources "")
foreach(header IN LISTS utcp_core_headers)
  file(RELATIVE_PATH rel ${PROJECT_SOURCE_DIR} ${header})
  string(MAKE_C_IDENTIFIER ${rel} id)
  set(check_src ${CMAKE_CURRENT_BINARY_DIR}/header_check/${id}.cpp)
  file(CONFIGURE OUTPUT ${check_src} CONTENT "#include \"${header}\"\n")
  list(APPEND utcp_header_check_sources ${check_src})
endforeach()
add_library(utcp_core_header_check OBJECT ${utcp_header_check_sources})
target_include_directories(utcp_core_header_check PRIVATE
  ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
target_compile_options(utcp_core_header_check PRIVATE -fno-exceptions)
utcp_target_warnings(utcp_core_header_check STRICT)
