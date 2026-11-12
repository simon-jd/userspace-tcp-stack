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

add_subdirectory(support)
add_subdirectory(unit)
add_subdirectory(sim)
if(UTCP_FUZZ)
  add_subdirectory(fuzz)
endif()

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

# Integer arithmetic only in the core and in the simulator's generator and
# link pipeline (DESIGN §2.2, §13.1). The self-tests check that a planted
# `double` is found and that the words in comments and strings are not.
add_test(NAME core.no_float
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-no-float.sh)
add_test(NAME core.no_float_selftest_bad
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-no-float.sh --files
          ${CMAKE_CURRENT_SOURCE_DIR}/selftest/no_float/planted.cpp)
set_tests_properties(core.no_float_selftest_bad PROPERTIES WILL_FAIL TRUE)
add_test(NAME core.no_float_selftest_ok
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-no-float.sh --files
          ${CMAKE_CURRENT_SOURCE_DIR}/selftest/no_float/comments_only.cpp)

# Test files link into two binaries, so suite names start with the file stem
# and are unique per binary (ci/check-test-names.sh).
add_test(NAME ci.test_names
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-test-names.sh)
add_test(NAME ci.test_names_selftest_duplicate
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-test-names.sh
          ${CMAKE_CURRENT_SOURCE_DIR}/selftest/test_names/duplicate)
set_tests_properties(ci.test_names_selftest_duplicate PROPERTIES WILL_FAIL TRUE)
add_test(NAME ci.test_names_selftest_prefix
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-test-names.sh
          ${CMAKE_CURRENT_SOURCE_DIR}/selftest/test_names/prefix)
set_tests_properties(ci.test_names_selftest_prefix PROPERTIES WILL_FAIL TRUE)
add_test(NAME ci.test_names_selftest_good
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-test-names.sh
          ${CMAKE_CURRENT_SOURCE_DIR}/selftest/test_names/good)
