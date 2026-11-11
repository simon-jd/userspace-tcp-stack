# utcp_backend: the Linux side (TUN device; the epoll event loop follows in
# M1). Everything that makes system calls lives here or in apps/.
add_library(utcp_backend STATIC
  tun_device.cpp)
add_library(utcp::backend ALIAS utcp_backend)

target_include_directories(utcp_backend PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(utcp_backend PUBLIC utcp_core)
utcp_target_warnings(utcp_backend)
