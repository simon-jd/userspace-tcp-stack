cmake_minimum_required(VERSION 3.28)

project(utcp
  VERSION 0.1.0
  DESCRIPTION "Userspace TCP/IP stack with a sans-I/O core"
  LANGUAGES CXX)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$")
  message(FATAL_ERROR "Only GCC and Clang are supported (got ${CMAKE_CXX_COMPILER_ID})")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# No C++ modules; skip the module dependency scan.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

option(UTCP_BUILD_TESTS "Build the tests" ON)
option(UTCP_SANITIZE "Build everything with ASan and UBSan, aborting on the first error" OFF)
option(UTCP_DCHECKS "Enable UTCP_DCHECK in every build type (it is always on without NDEBUG)" OFF)
option(UTCP_FUZZ "Build the libFuzzer targets in tests/fuzz (clang only; implies coverage instrumentation)" OFF)

set(UTCP_RING_CHUNK_BYTES "4096" CACHE STRING "Core ByteRing / ChunkPool allocation unit in bytes")
set_property(CACHE UTCP_RING_CHUNK_BYTES PROPERTY STRINGS 2048 4096 8192)
if(NOT UTCP_RING_CHUNK_BYTES MATCHES "^(2048|4096|8192)$")
  message(FATAL_ERROR "UTCP_RING_CHUNK_BYTES must be 2048, 4096 or 8192")
endif()

include(cmake/Warnings.cmake)
include(cmake/Targets.cmake)

# libstdc++ bounds and precondition checks in debug builds (both compilers use libstdc++).
add_compile_definitions($<$<CONFIG:Debug>:_GLIBCXX_ASSERTIONS>)

if(UTCP_SANITIZE)
  # Applied globally so GoogleTest is instrumented as well.
  set(UTCP_SANITIZER_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all)
  add_compile_options(${UTCP_SANITIZER_FLAGS} -fno-omit-frame-pointer)
  add_link_options(${UTCP_SANITIZER_FLAGS})
endif()

if(UTCP_DCHECKS)
  add_compile_definitions(UTCP_DCHECKS=1)
endif()

if(UTCP_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "UTCP_FUZZ needs clang (libFuzzer)")
  endif()
  # Coverage instrumentation everywhere; only the fuzz targets link the
  # libFuzzer runtime (-fsanitize=fuzzer, tests/fuzz/CMakeLists.txt).
  add_compile_options(-fsanitize=fuzzer-no-link)
endif()

add_subdirectory(src/core)
add_subdirectory(src/sim)
add_subdirectory(src/backend)
add_subdirectory(apps)

if(UTCP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
