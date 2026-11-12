# Globbed targets. M1 tasks add source files in parallel branches, so the
# CMake files list no sources: every library and test binary takes the *.cpp
# files under its directory (GLOB_RECURSE CONFIGURE_DEPENDS, so a new file is
# picked up at the next build without re-running cmake by hand).

# utcp_glob_sources(<out-var> <dir> [<pattern>])
# Sorted list of files under <dir> matching <pattern> (default *.cpp).
function(utcp_glob_sources out dir)
  set(pattern "*.cpp")
  if(ARGC GREATER 2)
    set(pattern "${ARGV2}")
  endif()
  file(GLOB_RECURSE files CONFIGURE_DEPENDS "${dir}/${pattern}")
  list(SORT files)
  set(${out} "${files}" PARENT_SCOPE)
endfunction()

# utcp_glob_library(<name> DIR <dir> [STRICT] [INCLUDE <dirs...>] [LINK <targets...>])
# A static library of the *.cpp files under DIR, or an INTERFACE library while
# DIR has none (header-only so far), so dependents can always link <name>.
# INCLUDE and LINK are public (interface) usage requirements.
function(utcp_glob_library name)
  cmake_parse_arguments(PARSE_ARGV 1 arg "STRICT" "DIR" "INCLUDE;LINK")
  utcp_glob_sources(sources "${arg_DIR}")
  if(sources)
    add_library(${name} STATIC ${sources})
    target_include_directories(${name} PUBLIC ${arg_INCLUDE})
    target_link_libraries(${name} PUBLIC ${arg_LINK})
    if(arg_STRICT)
      utcp_target_warnings(${name} STRICT)
    else()
      utcp_target_warnings(${name})
    endif()
  else()
    add_library(${name} INTERFACE)
    target_include_directories(${name} INTERFACE ${arg_INCLUDE})
    target_link_libraries(${name} INTERFACE ${arg_LINK})
  endif()
endfunction()

# utcp_app_logic(<target>)
# Registers a static library under apps/<name>/ that holds a program's logic
# (its main() stays in the executable). utcp_unit_tests links every
# registered library, and compiles the tests next to it: apps/<name>/*_test.cpp
# (suite names follow ci/check-test-names.sh; keep *_test.cpp out of the
# app's own sources). apps/ is added before tests/, so registrations are
# complete when tests/unit/CMakeLists.txt reads them.
function(utcp_app_logic target)
  set_property(GLOBAL APPEND PROPERTY UTCP_APP_LOGIC_LIBS ${target})
endfunction()

# utcp_header_check(<name> HEADERS <files...> [STRICT] [NO_EXCEPTIONS]
#                   [INCLUDE <dirs...>] [LINK <targets...>])
# An OBJECT library that compiles each header on its own (one generated file
# per header), with the flags of the library the headers belong to: STRICT
# warnings and -fno-exceptions for the core, the default set otherwise. LINK
# brings in usage requirements (include directories) only.
function(utcp_header_check name)
  cmake_parse_arguments(PARSE_ARGV 1 arg "STRICT;NO_EXCEPTIONS" "" "HEADERS;INCLUDE;LINK")
  if(NOT arg_HEADERS)
    return()
  endif()
  list(SORT arg_HEADERS)
  set(check_sources "")
  foreach(header IN LISTS arg_HEADERS)
    file(RELATIVE_PATH rel ${PROJECT_SOURCE_DIR} ${header})
    string(MAKE_C_IDENTIFIER ${rel} id)
    set(check_src ${CMAKE_CURRENT_BINARY_DIR}/${name}/${id}.cpp)
    file(CONFIGURE OUTPUT ${check_src} CONTENT "#include \"${header}\"\n")
    list(APPEND check_sources ${check_src})
  endforeach()
  add_library(${name} OBJECT ${check_sources})
  target_include_directories(${name} PRIVATE ${arg_INCLUDE})
  foreach(t IN LISTS arg_LINK)
    target_include_directories(${name} PRIVATE $<TARGET_PROPERTY:${t},INTERFACE_INCLUDE_DIRECTORIES>)
  endforeach()
  if(arg_NO_EXCEPTIONS)
    target_compile_options(${name} PRIVATE -fno-exceptions)
  endif()
  if(arg_STRICT)
    utcp_target_warnings(${name} STRICT)
  else()
    utcp_target_warnings(${name})
  endif()
endfunction()
