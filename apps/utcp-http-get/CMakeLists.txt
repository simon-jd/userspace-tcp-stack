# utcp-http-get (DESIGN §9): the logic in utcp_http_get_logic (unit-tested by
# http_get_test.cpp against the fake Transport), main() in main.cpp.
add_library(utcp_http_get_logic STATIC http_get.cpp)
target_link_libraries(utcp_http_get_logic PUBLIC utcp_appkit)
utcp_target_warnings(utcp_http_get_logic)
utcp_app_logic(utcp_http_get_logic)

add_executable(utcp-http-get main.cpp)
target_link_libraries(utcp-http-get PRIVATE utcp_http_get_logic)
utcp_target_warnings(utcp-http-get)
