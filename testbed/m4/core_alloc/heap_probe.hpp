// Linux/glibc, LP64 Itanium C++ ABI. One non-nested measurement window per thread.
#pragma once

#include <cstdint>
#include <cstdio>

enum class HeapApi : unsigned {
  new_scalar, new_array, new_scalar_nt, new_array_nt, new_aligned, new_array_aligned,
  new_aligned_nt, new_array_aligned_nt, malloc_, calloc_, realloc_, aligned_alloc_,
  posix_memalign_, memalign_, valloc_, pvalloc_, reallocarray_, count
};

constexpr unsigned heap_api_count = static_cast<unsigned>(HeapApi::count);
struct utcp_heap_counts {
  // An array new may delegate to scalar new, then malloc. Entries include each
  // observed call; outer counts the single outermost request across both families.
  std::uint64_t entries[heap_api_count]{};
  std::uint64_t outer[heap_api_count]{};
};

extern "C" {
void utcp_heap_start();
void utcp_heap_stop(utcp_heap_counts*);
void utcp_heap_label(unsigned label);
void utcp_heap_sites(bool enable);  // Call before any measurement windows.
bool utcp_heap_write_sites(std::FILE*);
const char* utcp_heap_name(unsigned);
}
