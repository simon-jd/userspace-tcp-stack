add_executable(tun_probe tun_probe.cpp)
target_link_libraries(tun_probe PRIVATE utcp_core utcp_backend)
utcp_target_warnings(tun_probe)
