#include <cstdint>
#include <cstdlib>
#include <dlfcn.h>
#include <new>
#include <malloc.h>
#include <cstdio>
int main() {
  auto read = reinterpret_cast<void (*)(uint64_t*,uint64_t*)>(dlsym(RTLD_DEFAULT,"utcp_counter_read"));
  if (!read) return 2;
  uint64_t first, bytes, last, end;
  read(&first,&bytes);
  void* a = malloc(23);
  void* b = calloc(5,7);
  a = realloc(a,59);
  void* c = nullptr;
  if (posix_memalign(&c,64,128) || !a || !b) return 3;
  void* d = ::operator new(83);
  void* e = ::operator new[](137,std::align_val_t{64},std::nothrow);
  void* z = ::operator new(0,std::nothrow);
  read(&last,&end);
  free(a); free(b); free(c); ::operator delete(d);
  ::operator delete[](e,std::align_val_t{64}); ::operator delete(z);
  if (last-first != 7 || end-bytes != 465) return 1;
  std::puts("mixed C/C++ and zero size: 7 requests, 465 bytes");
  read(&first,&bytes);
  void* c1 = malloc(11);
  c1 = reallocarray(c1,3,17);
  void* c2 = aligned_alloc(32,64);
  void* c3 = memalign(64,15);
  void* c4 = valloc(31);
  void* c5 = pvalloc(33);
  void* p1 = ::operator new(1);
  void* p2 = ::operator new[](2);
  void* p3 = ::operator new(3,std::align_val_t{64});
  void* p4 = ::operator new[](4,std::align_val_t{64});
  void* p5 = ::operator new(5,std::nothrow);
  void* p6 = ::operator new[](6,std::nothrow);
  void* p7 = ::operator new(7,std::align_val_t{64},std::nothrow);
  void* p8 = ::operator new[](8,std::align_val_t{64},std::nothrow);
  read(&last,&end);
  free(c1); free(c2); free(c3); free(c4); free(c5);
  ::operator delete(p1); ::operator delete[](p2);
  ::operator delete(p3,std::align_val_t{64}); ::operator delete[](p4,std::align_val_t{64});
  ::operator delete(p5); ::operator delete[](p6);
  ::operator delete(p7,std::align_val_t{64}); ::operator delete[](p8,std::align_val_t{64});
  if (last-first != 14 || end-bytes != 241) return 1;
  std::puts("extended public C and all eight C++ forms: 14 requests, 241 bytes");
  read(&first,&bytes);
  read(&last,&end);
  if (last!=first || end!=bytes) return 1;
  std::puts("empty interval: 0 requests, 0 bytes");
  return 0;
}
