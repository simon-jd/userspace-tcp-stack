# utcp_unit_tests: every tests/unit/*_test.cpp, plus the tests of the
# programs' logic in apps/<name>/*_test.cpp (apps/common is tested from
# tests/unit) linked against the libraries registered with utcp_app_logic()
# (cmake/Targets.cmake). Suite names start with the file stem and are unique
# across all these files (ci/check-test-names.sh); helpers go in anonymous
# namespaces.
utcp_glob_sources(utcp_unit_test_sources ${CMAKE_CURRENT_SOURCE_DIR} "*_test.cpp")
file(GLOB utcp_app_test_sources CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/apps/*/*_test.cpp)
list(FILTER utcp_app_test_sources EXCLUDE REGEX "/apps/common/")
list(SORT utcp_app_test_sources)
get_property(utcp_app_logic_libs GLOBAL PROPERTY UTCP_APP_LOGIC_LIBS)
add_executable(utcp_unit_tests ${utcp_unit_test_sources} ${utcp_app_test_sources})
target_link_libraries(utcp_unit_tests PRIVATE
  utcp_core_internal utcp_backend utcp_appkit utcp_test_support ${utcp_app_logic_libs}
  GTest::gtest_main)
utcp_target_warnings(utcp_unit_tests)

# One ctest entry per test case, listed by running the binary at test time.
gtest_discover_tests(utcp_unit_tests
  TEST_PREFIX "unit."
  DISCOVERY_MODE PRE_TEST)
