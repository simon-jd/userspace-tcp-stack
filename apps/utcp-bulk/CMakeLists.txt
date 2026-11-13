# utcp-bulk (DESIGN §9): the logic in utcp_bulk_logic (unit-tested by
# bulk_test.cpp against the fake Transport), main() in main.cpp.
add_library(utcp_bulk_logic STATIC bulk.cpp)
target_link_libraries(utcp_bulk_logic PUBLIC utcp_appkit)
utcp_target_warnings(utcp_bulk_logic)
utcp_app_logic(utcp_bulk_logic)

add_executable(utcp-bulk main.cpp)
target_link_libraries(utcp-bulk PRIVATE utcp_bulk_logic)
utcp_target_warnings(utcp-bulk)
