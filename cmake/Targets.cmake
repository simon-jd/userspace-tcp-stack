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
