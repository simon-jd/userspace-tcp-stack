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

# Every core header and every public header of the core compiles on its own
# with the core's flags: the interface headers of src/core/tcp are handed to
# other tasks before any source file includes them. The backend's headers
# (event_loop.hpp, tun_device.hpp) and the simulator's (include/utcp/sim/)
# are checked with their own libraries' flags in src/backend and src/sim.
file(GLOB_RECURSE utcp_core_headers CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.hpp)
file(GLOB utcp_core_public_headers CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/include/utcp/*.hpp ${PROJECT_SOURCE_DIR}/include/utcp/defs/*.hpp)
list(FILTER utcp_core_public_headers EXCLUDE REGEX "/include/utcp/(event_loop|tun_device)\\.hpp$")
utcp_header_check(utcp_core_header_check
  HEADERS ${utcp_core_headers} ${utcp_core_public_headers}
  STRICT NO_EXCEPTIONS
  INCLUDE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)
