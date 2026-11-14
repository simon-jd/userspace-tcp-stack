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
    TEST_FILTER "-SimCorpus.EveryEntryPasses"
    DISCOVERY_MODE PRE_TEST)
  # The corpus replays every SIM-BUGS scenario exactly as the sweep found it.
  # sb-0002-209 (a 3 MB stream in one-byte segments) makes the whole replay
  # take about 70 s in a Debug build and about 400 s in gcc-asan, so this one
  # test gets a longer limit than the presets' 300 s.
  gtest_discover_tests(utcp_sim_tests
    TEST_PREFIX "sim."
    TEST_FILTER "SimCorpus.EveryEntryPasses"
    PROPERTIES TIMEOUT 1500
    DISCOVERY_MODE PRE_TEST)
endif()
