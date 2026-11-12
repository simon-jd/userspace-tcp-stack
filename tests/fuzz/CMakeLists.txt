# libFuzzer targets (UTCP_FUZZ=ON, clang): one executable per
# tests/fuzz/fuzz_*.cpp, each defining LLVMFuzzerTestOneInput. ctest runs
# each briefly from an empty corpus (fuzz.<name>.smoke); long runs are
# started by hand, e.g. build/clang-fuzz/tests/fuzz/fuzz_ipv4 -max_total_time=60.
utcp_glob_sources(utcp_fuzz_sources ${CMAKE_CURRENT_SOURCE_DIR} "fuzz_*.cpp")
foreach(src IN LISTS utcp_fuzz_sources)
  get_filename_component(name ${src} NAME_WE)
  add_executable(${name} ${src})
  target_link_libraries(${name} PRIVATE utcp_core_internal utcp_test_support)
  target_link_options(${name} PRIVATE -fsanitize=fuzzer)
  utcp_target_warnings(${name})
  add_test(NAME fuzz.${name}.smoke COMMAND ${name} -runs=20000 -seed=1)
endforeach()
