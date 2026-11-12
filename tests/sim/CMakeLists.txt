# utcp_sim_tests: every tests/sim/*_test.cpp (simulator tests and directed
# TCP scenarios). Not built while there are none.
utcp_glob_sources(utcp_sim_test_sources ${CMAKE_CURRENT_SOURCE_DIR} "*_test.cpp")
if(utcp_sim_test_sources)
  add_executable(utcp_sim_tests ${utcp_sim_test_sources})
  target_link_libraries(utcp_sim_tests PRIVATE
    utcp_sim utcp_core_internal utcp_test_support GTest::gtest_main)
  target_compile_definitions(utcp_sim_tests PRIVATE
    UTCP_SIM_CORPUS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/corpus")
  utcp_target_warnings(utcp_sim_tests)
  gtest_discover_tests(utcp_sim_tests
    TEST_PREFIX "sim."
    DISCOVERY_MODE PRE_TEST)
endif()
