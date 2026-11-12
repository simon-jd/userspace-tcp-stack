# utcp_sim: the discrete-event simulator (DESIGN §7) that runs utcp_core
# instances on seeded virtual links. Public headers in include/utcp/sim/.
# Sources: every *.cpp under src/sim. It links the app kit for the JSONL
# writer (§7.4, §10.2).
utcp_glob_library(utcp_sim
  DIR ${CMAKE_CURRENT_SOURCE_DIR}
  INCLUDE ${PROJECT_SOURCE_DIR}/include
  LINK utcp_core_internal utcp_appkit)

# The simulator's public headers compile on their own with its flags.
file(GLOB_RECURSE utcp_sim_headers CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/include/utcp/sim/*.hpp)
utcp_header_check(utcp_sim_header_check
  HEADERS ${utcp_sim_headers}
  INCLUDE ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/apps)
