# Warning policy (see docs/ENVIRONMENT.md, "Warnings").
#
# Every project target gets UTCP_WARNING_FLAGS; warnings are errors on both
# compilers. utcp_core additionally gets UTCP_STRICT_WARNING_FLAGS: the core
# does all the wire-format arithmetic, so implicit narrowing and sign changes
# are errors there. Third-party code (GoogleTest) is built without these flags.

set(UTCP_WARNING_FLAGS
  -Wall
  -Wextra
  -Wpedantic
  -Wshadow
  -Wnon-virtual-dtor
  -Woverloaded-virtual
  -Wimplicit-fallthrough
  -Wformat=2
  -Werror)

set(UTCP_STRICT_WARNING_FLAGS
  -Wconversion
  -Wsign-conversion
  -Wold-style-cast
  -Wcast-qual)

# utcp_target_warnings(<target> [STRICT])
function(utcp_target_warnings target)
  cmake_parse_arguments(PARSE_ARGV 1 arg "STRICT" "" "")
  target_compile_options(${target} PRIVATE ${UTCP_WARNING_FLAGS})
  if(arg_STRICT)
    target_compile_options(${target} PRIVATE ${UTCP_STRICT_WARNING_FLAGS})
  endif()
endfunction()
