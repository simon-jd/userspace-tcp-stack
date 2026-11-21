// Interpose the deployed libstdc++ implementations, including new-handler
// semantics. Direct malloc/calloc/realloc calls use their glibc backends so
// loader bootstrap can itself allocate. Other public entries use RTLD_NEXT.
#include "heap_probe.hpp"

#include <array>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <new>
#include <unistd.h>
#include <unwind.h>

extern "C" void* __libc_malloc(std::size_t) noexcept;
extern "C" void* __libc_calloc(std::size_t, std::size_t) noexcept;
extern "C" void* __libc_realloc(void*, std::size_t) noexcept;

namespace {
constexpr std::array<const char*, heap_api_count> names{
    "_Znwm","_Znam","_ZnwmRKSt9nothrow_t","_ZnamRKSt9nothrow_t","_ZnwmSt11align_val_t",
    "_ZnamSt11align_val_t","_ZnwmSt11align_val_tRKSt9nothrow_t","_ZnamSt11align_val_tRKSt9nothrow_t",
    "malloc","calloc","realloc","aligned_alloc","posix_memalign","memalign","valloc","pvalloc","reallocarray"};

struct State {
  bool active;
  bool sites;
  unsigned label;
  unsigned depth;
  utcp_heap_counts counts;
};
// Initial-exec ensures resolving a thread's counters cannot allocate via TLS.
thread_local State state __attribute__((tls_model("initial-exec")));
struct Site {
  std::uint64_t calls;
  unsigned label;
  unsigned api;
  unsigned frames;
  std::uintptr_t pc[20];
};
constexpr unsigned max_sites = 2048;
// Single-thread call-site mode is for the core harness. Counts are TLS; other
// threads must leave call-site mode disabled while one thread records stacks.
Site sites[max_sites]{};
unsigned used;
std::uint64_t overflow;
_Unwind_Reason_Code visit(struct _Unwind_Context* ctx, void* data) {
  auto& site = *static_cast<Site*>(data);
  if (site.frames == std::size(site.pc)) return _URC_END_OF_STACK;
  auto pc = _Unwind_GetIP(ctx);
  if (pc) site.pc[site.frames++] = pc - 1;  // call instruction for addr2line
  return _URC_NO_REASON;
}
void record(unsigned api) {
  Site key{};
  key.api = api;
  key.label = state.label;
  _Unwind_Backtrace(visit, &key);
  for (unsigned i = 0; i < used; ++i) {
    auto& s = sites[i];
    if (s.label == key.label && s.api == key.api && s.frames == key.frames &&
        std::memcmp(s.pc, key.pc, key.frames * sizeof(key.pc[0])) == 0) {
      ++s.calls;
      return;
    }
  }
  key.calls = 1;
  if (used < max_sites) sites[used++] = key;
  else ++overflow;
}
struct Entry {
  bool live;
  explicit Entry(HeapApi api) : live(state.active) {
    if (!live) return;
    auto n = static_cast<unsigned>(api);
    ++state.counts.entries[n];
    if (state.depth++ == 0) {
      ++state.counts.outer[n];
      if (state.sites) record(n);
    }
  }
  ~Entry() { if (live) --state.depth; }
};

template<HeapApi Api, typename Fn>
Fn next() {
  static auto fn = reinterpret_cast<Fn>(dlsym(RTLD_NEXT, names[static_cast<unsigned>(Api)]));
  if (!fn) _exit(125);
  return fn;
}
}

extern "C" const char* utcp_heap_name(unsigned n) { return names.at(n); }
extern "C" void utcp_heap_label(unsigned label) { state.label = label; }
extern "C" void utcp_heap_start() {
  if (state.active || state.depth) std::abort();
  state.counts = {};
  state.active = true;
}
extern "C" void utcp_heap_stop(utcp_heap_counts* out) {
  if (!state.active || state.depth) std::abort();
  state.active = false;
  *out = state.counts;
}
extern "C" void utcp_heap_sites(bool on) { state.sites = on; }
extern "C" bool utcp_heap_write_sites(std::FILE* f) {
  for (unsigned i = 0; i < used; ++i) {
    const auto& s = sites[i];
    std::fprintf(f,"%u,%s,%llu",s.label,names[s.api],static_cast<unsigned long long>(s.calls));
    for (unsigned j = 0; j < s.frames; ++j)
      std::fprintf(f,",%zx",static_cast<std::size_t>(s.pc[j]));
    std::fputc('\n', f);
  }
  return overflow == 0 && std::ferror(f) == 0;
}

extern "C" void* malloc(std::size_t n) noexcept {
  Entry e(HeapApi::malloc_); return __libc_malloc(n);
}
extern "C" void* calloc(std::size_t n, std::size_t size) noexcept {
  Entry e(HeapApi::calloc_); return __libc_calloc(n,size);
}
extern "C" void* realloc(void* p,std::size_t n) noexcept {
  Entry e(HeapApi::realloc_); return __libc_realloc(p,n);
}

#define C_ENTRY(ret, name, params, args) \
extern "C" ret name params noexcept { \
  Entry e(HeapApi::name##_); \
  return next<HeapApi::name##_, decltype(&name)>() args; \
}
C_ENTRY(void*, aligned_alloc, (std::size_t align,std::size_t size), (align,size))
C_ENTRY(int, posix_memalign, (void** p,std::size_t align,std::size_t size), (p,align,size))
C_ENTRY(void*, memalign, (std::size_t align,std::size_t size), (align,size))
C_ENTRY(void*, valloc, (std::size_t size), (size))
C_ENTRY(void*, pvalloc, (std::size_t size), (size))
C_ENTRY(void*, reallocarray, (void* p,std::size_t n,std::size_t size), (p,n,size))

#define CPP_ENTRY(name, api, params, args, spec) \
void* operator new name params spec { \
  Entry e(HeapApi::api); \
  return next<HeapApi::api, void*(*) params>() args; \
}
CPP_ENTRY(,new_scalar,(std::size_t n),(n),)
CPP_ENTRY([],new_array,(std::size_t n),(n),)
CPP_ENTRY(,new_scalar_nt,(std::size_t n,const std::nothrow_t& t),(n,t),noexcept)
CPP_ENTRY([],new_array_nt,(std::size_t n,const std::nothrow_t& t),(n,t),noexcept)
CPP_ENTRY(,new_aligned,(std::size_t n,std::align_val_t a),(n,a),)
CPP_ENTRY([],new_array_aligned,(std::size_t n,std::align_val_t a),(n,a),)
CPP_ENTRY(,new_aligned_nt,(std::size_t n,std::align_val_t a,const std::nothrow_t& t),(n,a,t),noexcept)
CPP_ENTRY([],new_array_aligned_nt,(std::size_t n,std::align_val_t a,const std::nothrow_t& t),(n,a,t),noexcept)
