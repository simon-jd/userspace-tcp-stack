# utcp-sim: runs simulator scenarios (DESIGN §7.2, §7.4). One JSONL result
# line per run; tools/sim_sweep.py drives it over seed ranges.
add_executable(utcp-sim main.cpp)
target_link_libraries(utcp-sim PRIVATE utcp_sim utcp_appkit)
utcp_target_warnings(utcp-sim)
