#include "heap_probe.hpp"

#include <cstdlib>
#include <dlfcn.h>
#include <malloc.h>
#include <new>

namespace {
template<typename T> T symbol(unsigned n) {
  auto p = reinterpret_cast<T>(dlsym(RTLD_DEFAULT, utcp_heap_name(n)));
  if (!p) std::abort();
  return p;
}
void* exercise(unsigned n) {
  constexpr std::size_t size = 128;
  using A = std::align_val_t;
  using T = const std::nothrow_t&;
  switch (n) {
    case 0: case 1: case 8: case 14: case 15:
      return symbol<void*(*)(std::size_t)>(n)(size);
    case 2: case 3: return symbol<void*(*)(std::size_t,T)>(n)(size,std::nothrow);
    case 4: case 5: return symbol<void*(*)(std::size_t,A)>(n)(size,A{64});
    case 6: case 7: return symbol<void*(*)(std::size_t,A,T)>(n)(size,A{64},std::nothrow);
    case 9: case 11: case 13:
      return symbol<void*(*)(std::size_t,std::size_t)>(n)(64,size);
    case 10: return symbol<void*(*)(void*,std::size_t)>(n)(nullptr,size);
    case 12: {
      void* out{};
      if (symbol<int(*)(void**,std::size_t,std::size_t)>(n)(&out,64,size)) std::abort();
      return out;
    }
    case 16: return symbol<void*(*)(void*,std::size_t,std::size_t)>(n)(nullptr,4,size);
    default: std::abort();
  }
}
void drop(unsigned n, void* p) {
  if (n == 0 || n == 2) ::operator delete(p);
  else if (n == 1 || n == 3) ::operator delete[](p);
  else if (n == 4 || n == 6) ::operator delete(p,std::align_val_t{64});
  else if (n == 5 || n == 7) ::operator delete[](p,std::align_val_t{64});
  else std::free(p);
}
}
int main(int argc,char**) {
  for (unsigned n=0; n<heap_api_count; ++n) drop(n,exercise(n));
  utcp_heap_sites(argc > 1);
  for (unsigned n=0; n<=heap_api_count; ++n) {
    utcp_heap_label(n);
    utcp_heap_start();
    void* p = n==heap_api_count ? nullptr : exercise(n);
    utcp_heap_counts counts;
    utcp_heap_stop(&counts);
    if (n<heap_api_count && !p) return 1;
    for (unsigned j=0; j<heap_api_count; ++j) {
      if (counts.outer[j] != (j==n)) return 2;
      if (j==n && counts.entries[j]<1) return 3;
      std::printf("control,%u,%u,%llu,%llu\n",n,j,
                  (unsigned long long)counts.outer[j],(unsigned long long)counts.entries[j]);
    }
    utcp_heap_start();
    if (p) drop(n,p);
    utcp_heap_stop(&counts);
    for (auto v:counts.entries) if (v) return 4;
  }
  return utcp_heap_write_sites(stderr) ? 0 : 5;
}
