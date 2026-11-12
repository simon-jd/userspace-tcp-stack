# Interop helpers (DESIGN §11): small programs that the container scripts in
# this directory run in the testbed, e.g. m1-backend's UDP echo on
# UtcpTransport. One executable per tests/interop/*.cpp, named after the file
# (backend_udp_echo.cpp -> build/<preset>/tests/interop/backend_udp_echo),
# linked with the app kit (Transport, UtcpTransport, CLI, JSONL), the backend
# and the core. The scripts themselves (*.sh, *.py) are not built.
utcp_glob_sources(utcp_interop_sources ${CMAKE_CURRENT_SOURCE_DIR})
foreach(src IN LISTS utcp_interop_sources)
  get_filename_component(name ${src} NAME_WE)
  add_executable(${name} ${src})
  target_link_libraries(${name} PRIVATE utcp_appkit utcp_backend utcp_core_internal)
  utcp_target_warnings(${name})
endforeach()
