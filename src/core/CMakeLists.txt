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
