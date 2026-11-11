# utcp_core: the sans-I/O protocol core. No system calls, no I/O, no threads,
# no clocks, no global mutable state. tests/CMakeLists.txt checks the archive's
# undefined symbols against cmake/CheckCoreSymbols.cmake.
add_library(utcp_core STATIC
  checksum.cpp)
add_library(utcp::core ALIAS utcp_core)

target_include_directories(utcp_core PUBLIC ${PROJECT_SOURCE_DIR}/include)
utcp_target_warnings(utcp_core STRICT)
