add_executable(utcp_unit_tests
  checksum_test.cpp)
target_link_libraries(utcp_unit_tests PRIVATE utcp_core GTest::gtest_main)
utcp_target_warnings(utcp_unit_tests)

# One ctest entry per test case, listed by running the binary at test time.
gtest_discover_tests(utcp_unit_tests
  TEST_PREFIX "unit."
  DISCOVERY_MODE PRE_TEST)
