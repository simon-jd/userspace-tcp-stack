# Standalone deterministic, valid-input protocol soak. Intentionally not a
# CTest or libFuzzer target: the independent acceptance run controls duration.
add_executable(utcp_positive_protocol_soak positive_protocol_soak.cpp)
target_link_libraries(utcp_positive_protocol_soak PRIVATE utcp_core_internal utcp_test_support)
utcp_target_warnings(utcp_positive_protocol_soak)
