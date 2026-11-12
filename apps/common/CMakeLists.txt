# utcp_appkit: the Transport interface and its implementations, the fake
# Transport, JSONL writer, CLI parsing and the app helpers (DESIGN §9).
# Headers are included as "common/<name>.hpp". Sources: every *.cpp here.
utcp_glob_library(utcp_appkit
  DIR ${CMAKE_CURRENT_SOURCE_DIR}
  INCLUDE ${PROJECT_SOURCE_DIR}/apps
  LINK utcp_core utcp_backend)
