# GoogleTest comes from the distro source package `googletest` (version pinned
# in testbed/Dockerfile). It is built here with the same compiler, standard and
# sanitizer flags as the project, so no prebuilt ABI has to match.
set(UTCP_GTEST_SOURCE_DIR /usr/src/googletest CACHE PATH "GoogleTest source tree")
if(NOT EXISTS ${UTCP_GTEST_SOURCE_DIR}/CMakeLists.txt)
  message(FATAL_ERROR
    "GoogleTest sources not found at ${UTCP_GTEST_SOURCE_DIR}. Build inside the "
    "utcp-testbed image, or set UTCP_GTEST_SOURCE_DIR, or configure with -DUTCP_BUILD_TESTS=OFF.")
endif()
set(BUILD_GMOCK OFF)
set(INSTALL_GTEST OFF)
add_subdirectory(${UTCP_GTEST_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/googletest
  EXCLUDE_FROM_ALL SYSTEM)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  # gtest-printers.h:528 in GoogleTest 1.17 converts char8_t to char32_t,
  # which clang 21 warns about when compiling gtest itself.
  target_compile_options(gtest PRIVATE -Wno-character-conversion)
endif()

include(GoogleTest)

add_subdirectory(unit)

# The core must not call into the OS (see src/core/CMakeLists.txt). Check the
# archive's undefined symbols, and check that the checker catches a library
# that does.
add_test(NAME core.forbidden_symbols
  COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DARCHIVE=$<TARGET_FILE:utcp_core>
          -P ${PROJECT_SOURCE_DIR}/cmake/CheckCoreSymbols.cmake)

add_library(utcp_symbol_check_bad STATIC symbol_check_bad.cpp)
utcp_target_warnings(utcp_symbol_check_bad)
# Passes only if every planted call is reported.
add_test(NAME core.forbidden_symbols_selftest
  COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DARCHIVE=$<TARGET_FILE:utcp_symbol_check_bad>
          -DEXPECT=write,std::chrono::_V2::steady_clock::now,std::random_device
          -P ${PROJECT_SOURCE_DIR}/cmake/CheckCoreSymbols.cmake)
