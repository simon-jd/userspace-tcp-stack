# utcp_backend: the Linux side (TUN device, epoll event loop, monotonic
# clock). Everything that makes system calls lives here or in apps/.
# Sources: every *.cpp under src/backend.
utcp_glob_sources(utcp_backend_sources ${CMAKE_CURRENT_SOURCE_DIR})
add_library(utcp_backend STATIC ${utcp_backend_sources})
add_library(utcp::backend ALIAS utcp_backend)

target_include_directories(utcp_backend PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(utcp_backend PUBLIC utcp_core PRIVATE utcp_core_internal)
utcp_target_warnings(utcp_backend)

# The backend's public headers compile on their own with the backend's flags.
utcp_header_check(utcp_backend_header_check
  HEADERS ${PROJECT_SOURCE_DIR}/include/utcp/event_loop.hpp
          ${PROJECT_SOURCE_DIR}/include/utcp/tun_device.hpp
  INCLUDE ${PROJECT_SOURCE_DIR}/include)
