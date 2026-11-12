# utcp_sim: the discrete-event simulator (DESIGN §7) that runs utcp_core
# instances on seeded virtual links. Public headers in include/utcp/sim/.
# Sources: every *.cpp under src/sim.
utcp_glob_library(utcp_sim
  DIR ${CMAKE_CURRENT_SOURCE_DIR}
  LINK utcp_core_internal)
