#include <cstdint>
#include <cstdlib>
#include <dlfcn.h>
#include <new>
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
  return last-first == 7 && end-bytes == 465 ? 0 : 1;
}
