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

# UtcpTransport over a socketpair (no TUN interface, no root): timers, pcap,
# signals, device errors. The pcap file goes to the build directory.
add_test(NAME interop.backend_transport_check
         COMMAND backend_transport_check --tmp ${CMAKE_CURRENT_BINARY_DIR})
# The same with the checks that need the Stack (ICMP and UDP echo, EAGAIN,
# receive clock, outside-run drain, finish_closing), with its own directory
# for the files so that the two can run in parallel.
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/stack)
add_test(NAME interop.backend_transport_check_stack
         COMMAND backend_transport_check --expect-stack --tmp ${CMAKE_CURRENT_BINARY_DIR}/stack)

# The capture summary of the interop runs (m1_pcap_summary.py) over
# hand-written tshark field lines: the RST exemption of fin_ok still fails a
# real RST, window-edge retreats and the PMTU fields (docs/INTEROP.md).
find_package(Python3 3.10 COMPONENTS Interpreter REQUIRED)
add_test(NAME interop.m1_pcap_summary_check
         COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_SOURCE_DIR}/m1_pcap_summary_check.py)
