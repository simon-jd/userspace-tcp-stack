# utcp-httpd (DESIGN §9): the logic in utcp_httpd_logic (unit-tested by
# httpd_test.cpp against the fake Transport), main() in main.cpp.
add_library(utcp_httpd_logic STATIC httpd.cpp)
target_link_libraries(utcp_httpd_logic PUBLIC utcp_appkit)
utcp_target_warnings(utcp_httpd_logic)
utcp_app_logic(utcp_httpd_logic)

add_executable(utcp-httpd main.cpp)
target_link_libraries(utcp-httpd PRIVATE utcp_httpd_logic)
utcp_target_warnings(utcp-httpd)
