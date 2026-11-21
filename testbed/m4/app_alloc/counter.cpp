// Linux/glibc diagnostic for the single-threaded production app. Each successful
// outer request enters a fixed-size per-return-address table exactly once.
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <dlfcn.h>
#include <fcntl.h>
#include <new>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

extern "C" {
void* __libc_malloc(size_t);
void* __libc_calloc(size_t, size_t);
void* __libc_realloc(void*, size_t);
void* __libc_memalign(size_t, size_t);
}
namespace {
using U = uint64_t;
struct Entry { U address, kind, calls, bytes; };
struct Image {
  U sequence, calls, bytes, overflow;
  U trace_open_calls, trace_open_bytes, trace_close_calls, trace_close_bytes;
  U peak_kib, final;
  Entry entries[4096];
};
Image early{};
Image* counters = &early;
U* legacy = nullptr;
FILE* traced = nullptr;
using Open = FILE* (*)(const char*, const char*);
using Close = int (*)(FILE*);
Open real_open;
Close real_close;
#define CALLER reinterpret_cast<U>(__builtin_return_address(0))

void record(void* ptr, size_t n, U kind, U address) {
  if (!ptr) return;
  auto& data = *counters;
  auto seq = std::atomic_ref(data.sequence);
  seq.fetch_add(1);
  ++data.calls;
  data.bytes += n;
  auto index = ((address >> 3) ^ (kind * 79)) % 4096;
  for (unsigned i = 0; ; ++i) {
    if (i == 4096) { ++data.overflow; break; }
    auto& entry = data.entries[(index + i) % 4096];
    if (entry.address && (entry.address != address || entry.kind != kind)) continue;
    entry.address = address;
    entry.kind = kind;
    ++entry.calls;
    entry.bytes += n;
    break;
  }
  if (legacy) std::atomic_ref(*legacy).store(data.calls, std::memory_order_relaxed);
  seq.fetch_add(1);
}

void* map_new(const char* path, size_t length) {
  const int fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  if (fd < 0 || ftruncate(fd, length)) _exit(125);
  void* out = mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (out == MAP_FAILED) _exit(125);
  return out;
}
__attribute__((constructor)) void init() {
  real_open = reinterpret_cast<Open>(dlsym(RTLD_NEXT, "fopen"));
  real_close = reinterpret_cast<Close>(dlsym(RTLD_NEXT, "fclose"));
  if (!real_open || !real_close) _exit(125);
  const char* path = getenv("UTCP_NEW_COUNTER");
  if (!path) return;
  char full[4096];
  const auto n = strlen(path);
  if (n + sizeof(".all") > sizeof(full)) _exit(125);
  memcpy(full, path, n);
  memcpy(full+n, ".all", sizeof(".all"));
  auto* out = static_cast<Image*>(map_new(full, sizeof(Image)));
  *out = early;
  counters = out;
  legacy = static_cast<U*>(map_new(path, sizeof(U)));
  *legacy = out->calls;
}
__attribute__((destructor)) void finish() {
  rusage usage{};
  if (getrusage(RUSAGE_SELF, &usage) == 0) counters->peak_kib = usage.ru_maxrss;
  counters->final = 1;
}
void* alloc_new(size_t n, size_t align, U kind, U caller) {
  while (true) {
    void* p = align ? __libc_memalign(align, n ? n : 1) : __libc_malloc(n ? n : 1);
    if (p) { record(p, n, kind, caller); return p; }
    if (const auto h = std::get_new_handler()) h();
    else throw std::bad_alloc{};
  }
}
}  // namespace

extern "C" void* malloc(size_t n) noexcept {
  auto* p = __libc_malloc(n); record(p, n, 1, CALLER); return p;
}
extern "C" void* calloc(size_t a, size_t b) noexcept {
  auto* p = __libc_calloc(a,b); record(p, a*b, 2, CALLER); return p;
}
extern "C" void* realloc(void* old, size_t n) noexcept {
  auto* p = __libc_realloc(old,n); record(p,n,3,CALLER); return p;
}
extern "C" void* reallocarray(void* old, size_t a, size_t b) noexcept {
  size_t n;
  if (__builtin_mul_overflow(a,b,&n)) { errno=ENOMEM; return nullptr; }
  auto* p = __libc_realloc(old,n); record(p,n,4,CALLER); return p;
}
extern "C" int posix_memalign(void** out, size_t a, size_t n) noexcept {
  if (a < sizeof(void*) || (a & (a-1))) return EINVAL;
  int saved = errno;
  auto* p = __libc_memalign(a,n);
  errno = saved;
  if (!p) return ENOMEM;
  *out = p; record(p,n,5,CALLER); return 0;
}
extern "C" void* aligned_alloc(size_t a, size_t n) noexcept {
  if (!a || (a & (a-1))) { errno=EINVAL; return nullptr; }
  auto* p = __libc_memalign(a,n); record(p,n,6,CALLER); return p;
}
extern "C" void* memalign(size_t a, size_t n) noexcept {
  auto* p = __libc_memalign(a,n); record(p,n,7,CALLER); return p;
}
extern "C" void* valloc(size_t n) noexcept {
  auto* p = __libc_memalign(getpagesize(),n); record(p,n,8,CALLER); return p;
}
extern "C" void* pvalloc(size_t n) noexcept {
  const auto page = static_cast<size_t>(getpagesize());
  if (n > SIZE_MAX-(page-1)) { errno=ENOMEM; return nullptr; }
  auto* p = __libc_memalign(page,n ? (n+page-1)&~(page-1) : page);
  record(p,n,9,CALLER); return p;
}
#define NEW_FOR(op, kind) \
void* operator op(size_t n) { return alloc_new(n,0,kind,CALLER); } \
void* operator op(size_t n, std::align_val_t a) { return alloc_new(n,static_cast<size_t>(a),kind+2,CALLER); } \
void* operator op(size_t n, const std::nothrow_t&) noexcept { \
  try { return alloc_new(n,0,kind+4,CALLER); } catch(...) { return nullptr; } } \
void* operator op(size_t n, std::align_val_t a, const std::nothrow_t&) noexcept { \
  try { return alloc_new(n,static_cast<size_t>(a),kind+6,CALLER); } catch(...) { return nullptr; } }
NEW_FOR(new, 10)
NEW_FOR(new[], 11)
extern "C" FILE* fopen(const char* path, const char* mode) {
  if (!real_open) real_open = reinterpret_cast<Open>(dlsym(RTLD_NEXT,"fopen"));
  const bool trace = strstr(path,"/events.trace") && mode[0]=='w';
  if (trace) {
    counters->trace_open_calls = counters->calls;
    counters->trace_open_bytes = counters->bytes;
  }
  FILE* fp = real_open(path,mode);
  if (trace) traced = fp;
  return fp;
}
extern "C" int fclose(FILE* fp) {
  if (!real_close) real_close = reinterpret_cast<Close>(dlsym(RTLD_NEXT,"fclose"));
  const bool trace = traced && fp == traced;
  int status = real_close(fp);
  if (trace) {
    counters->trace_close_calls = counters->calls;
    counters->trace_close_bytes = counters->bytes;
    traced = nullptr;
  }
  return status;
}
extern "C" void utcp_counter_read(uint64_t* calls, uint64_t* bytes) {
  *calls = counters->calls; *bytes = counters->bytes;
}
