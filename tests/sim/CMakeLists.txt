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
    TEST_FILTER "-Corpus/SimCorpusEntry.*:Profiles/TcpRecoveryBulkSim.*"
    DISCOVERY_MODE PRE_TEST)
  # m2a-recovery test 7: 100 MB twice per case (the digest replay), about
  # 60 s per case in gcc-debug and three to four times that with sanitizers.
  gtest_discover_tests(utcp_sim_tests
    TEST_PREFIX "sim."
    TEST_FILTER "Profiles/TcpRecoveryBulkSim.*"
    PROPERTIES TIMEOUT 1500
    DISCOVERY_MODE PRE_TEST)
  # The corpus replays every SIM-BUGS scenario exactly as the sweep found it,
  # one test per entry so that ctest runs them in parallel. The entries with
  # megabytes sent in one-byte writes (sb-0002, sb-0006..sb-0009) take up to
  # about 820 s each in gcc-asan, so these tests get a longer limit than the
  # presets' 300 s.
  gtest_discover_tests(utcp_sim_tests
    TEST_PREFIX "sim."
    TEST_FILTER "Corpus/SimCorpusEntry.*"
    PROPERTIES TIMEOUT 1500
    DISCOVERY_MODE PRE_TEST)
endif()

add_test(NAME sim.RecoveryFaultControls
  COMMAND python3 -I "${CMAKE_CURRENT_SOURCE_DIR}/recovery_controls.py" $<TARGET_FILE:utcp-sim>)

add_test(NAME sim.SweepReplay
  COMMAND python3 -I "${CMAKE_CURRENT_SOURCE_DIR}/sweep_replay.py" $<TARGET_FILE:utcp-sim>
    "${PROJECT_SOURCE_DIR}/tools/sim_sweep.py")
