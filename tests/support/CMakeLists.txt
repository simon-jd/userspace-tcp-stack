# utcp_test_support: code shared by tests and fuzz targets (naive reassembler,
# packet builder, two-stack harness). Included as "support/<name>.hpp".
# Sources: every *.cpp here; header-only while there are none.
utcp_glob_library(utcp_test_support
  DIR ${CMAKE_CURRENT_SOURCE_DIR}
  INCLUDE ${PROJECT_SOURCE_DIR}/tests
  LINK utcp_core_internal GTest::gtest)
