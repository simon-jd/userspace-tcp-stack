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
add_subdirectory(interop)
if(UTCP_FUZZ)
  add_subdirectory(fuzz)
endif()

# The core must not call into the OS (see src/core/CMakeLists.txt). Check the
# archive's undefined symbols, and check that the checker catches a library
# that does.
# Symbols that utcp_backend or utcp_appkit define are forbidden as well (the
# backend's headers are on the core's include path).
add_test(NAME core.forbidden_symbols
  COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DARCHIVE=$<TARGET_FILE:utcp_core>
          -DPROVIDERS=$<TARGET_FILE:utcp_backend>,$<TARGET_FILE:utcp_appkit>
          -P ${PROJECT_SOURCE_DIR}/cmake/CheckCoreSymbols.cmake)

add_library(utcp_symbol_check_bad STATIC symbol_check_bad.cpp)
target_include_directories(utcp_symbol_check_bad PRIVATE ${PROJECT_SOURCE_DIR}/include)
utcp_target_warnings(utcp_symbol_check_bad)
# Passes only if every planted call is reported.
add_test(NAME core.forbidden_symbols_selftest
  COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DARCHIVE=$<TARGET_FILE:utcp_symbol_check_bad>
          -DPROVIDERS=$<TARGET_FILE:utcp_backend>,$<TARGET_FILE:utcp_appkit>
          -DEXPECT=write,std::chrono::_V2::steady_clock::now,std::random_device,clock,timespec_get,utcp::mono_now
          -P ${PROJECT_SOURCE_DIR}/cmake/CheckCoreSymbols.cmake)

# Integer arithmetic only in the core and in the simulator (DESIGN §2.2,
# §13.1; simulator files outside the generator and link pipeline may opt out).
# The self-tests check that a planted `double` is found and that the words in
# comments and strings are not.
add_test(NAME core.no_float
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-no-float.sh)
add_test(NAME core.no_float_selftest_bad
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-no-float.sh --files
          ${CMAKE_CURRENT_SOURCE_DIR}/selftest/no_float/planted.cpp)
set_tests_properties(core.no_float_selftest_bad PROPERTIES WILL_FAIL TRUE)
add_test(NAME core.no_float_selftest_ok
  COMMAND ${PROJECT_SOURCE_DIR}/ci/check-no-float.sh --files
          ${CMAKE_CURRENT_SOURCE_DIR}/selftest/no_float/comments_only.cpp)
# Every simulator file is checked, whatever its name; a file with the
# opt-out marker is skipped.
add_test(NAME core.no_float_selftest_sim_bad
  COMMAND ${CMAKE_COMMAND} -E env
          UTCP_NO_FLOAT_ROOT=${CMAKE_CURRENT_SOURCE_DIR}/selftest/no_float/sim_tree_bad
          ${PROJECT_SOURCE_DIR}/ci/check-no-float.sh)
set_tests_properties(core.no_float_selftest_sim_bad PROPERTIES WILL_FAIL TRUE)
add_test(NAME core.no_float_selftest_sim_exempt
  COMMAND ${CMAKE_COMMAND} -E env
          UTCP_NO_FLOAT_ROOT=${CMAKE_CURRENT_SOURCE_DIR}/selftest/no_float/sim_tree_exempt
          ${PROJECT_SOURCE_DIR}/ci/check-no-float.sh)
set_tests_properties(core.no_float_selftest_sim_exempt PROPERTIES
  PASS_REGULAR_EXPRESSION "check-no-float: ok \\(1 files checked\\)")

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
# A program's test in apps/<name>/ shares utcp_unit_tests with tests/unit.
add_test(NAME ci.test_names_selftest_app_duplicate
  COMMAND ${CMAKE_COMMAND} -E env
          UTCP_TEST_NAMES_ROOT=${CMAKE_CURRENT_SOURCE_DIR}/selftest/test_names/app_tree
          ${PROJECT_SOURCE_DIR}/ci/check-test-names.sh)
set_tests_properties(ci.test_names_selftest_app_duplicate PROPERTIES WILL_FAIL TRUE)
