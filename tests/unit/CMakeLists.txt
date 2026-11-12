# utcp_unit_tests: every tests/unit/*_test.cpp. Suite names start with the
# file stem (ci/check-test-names.sh); helpers go in anonymous namespaces.
utcp_glob_sources(utcp_unit_test_sources ${CMAKE_CURRENT_SOURCE_DIR} "*_test.cpp")
add_executable(utcp_unit_tests ${utcp_unit_test_sources})
target_link_libraries(utcp_unit_tests PRIVATE
  utcp_core_internal utcp_backend utcp_appkit utcp_test_support GTest::gtest_main)
utcp_target_warnings(utcp_unit_tests)

# One ctest entry per test case, listed by running the binary at test time.
gtest_discover_tests(utcp_unit_tests
  TEST_PREFIX "unit."
  DISCOVERY_MODE PRE_TEST)
