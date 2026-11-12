# Every apps/<dir>/ with a CMakeLists.txt is added (one program per directory;
# apps/common is the utcp_appkit library), so tasks never edit this file.
# A program whose logic is unit-tested builds it as a static library,
# registers it with utcp_app_logic(<target>) (cmake/Targets.cmake) and keeps
# the tests in apps/<dir>/*_test.cpp, which go into utcp_unit_tests.
file(GLOB utcp_app_lists CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt)
list(SORT utcp_app_lists)
foreach(list_file IN LISTS utcp_app_lists)
  get_filename_component(app_dir ${list_file} DIRECTORY)
  add_subdirectory(${app_dir})
endforeach()
