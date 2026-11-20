# utcp-echo (DESIGN §9): the logic in utcp_echo_logic (unit-tested by
# echo_test.cpp against the fake Transport and by echo_kernel_test.cpp over
# loopback with KernelTransport), main() in main.cpp.
add_library(utcp_echo_logic STATIC echo.cpp)
target_link_libraries(utcp_echo_logic PUBLIC utcp_appkit)
target_include_directories(utcp_echo_logic PRIVATE ${PROJECT_SOURCE_DIR}/src)
utcp_target_warnings(utcp_echo_logic)
utcp_app_logic(utcp_echo_logic)

add_executable(utcp-echo main.cpp)
target_link_libraries(utcp-echo PRIVATE utcp_echo_logic)
utcp_target_warnings(utcp-echo)
