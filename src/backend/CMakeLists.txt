# utcp_backend: the Linux side (TUN device, epoll event loop, monotonic
# clock). Everything that makes system calls lives here or in apps/.
# Sources: every *.cpp under src/backend.
utcp_glob_sources(utcp_backend_sources ${CMAKE_CURRENT_SOURCE_DIR})
add_library(utcp_backend STATIC ${utcp_backend_sources})
add_library(utcp::backend ALIAS utcp_backend)

target_include_directories(utcp_backend PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(utcp_backend PUBLIC utcp_core)
utcp_target_warnings(utcp_backend)
