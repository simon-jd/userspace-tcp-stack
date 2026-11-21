// A fixed event stream makes byte-for-byte comparison across revisions possible.
// The production class and production block size are linked without test knobs.
#include "common/utcp_transport.hpp"
#include <array>
#include <cstdio>
#include <cstdint>
#include <dlfcn.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char** argv) {
  using namespace utcp;
  using namespace utcp::app;
  if (argc != 2 || access(argv[1],F_OK)==0) return 2;
  const auto snapshot = reinterpret_cast<void (*)(uint64_t*,uint64_t*)>(
      dlsym(RTLD_DEFAULT,"utcp_counter_read"));
  if (!snapshot) return 2;
  struct Count {uint64_t calls,bytes;};
  std::array<Count,6> marks{};
  auto mark = [&](size_t i){snapshot(&marks[i].calls,&marks[i].bytes);};
  constexpr size_t capacity = TraceRecorder::block_bytes / sizeof(TraceEvent);
  const std::string path(argv[1]);
  mark(0);
  TraceRecorder r(false);
  mark(1);
  TraceEvent e{};
  e.kind=TraceKind::tx;
  e.tuple.local={Ipv4Addr{0xffffffff},65535};
  e.tuple.remote={Ipv4Addr{0xfedcba98},65432};
  for (size_t i=0;i<capacity;++i) {
    e.seq=static_cast<uint32_t>(i); e.t.ns=static_cast<int64_t>(1000*i);
    r.on_event(e);
  }
  mark(2);
  ++e.seq; e.t.ns+=1000; r.on_event(e);
  mark(3);
  for(int i=0;i<10;++i){++e.seq; e.t.ns+=1000; r.on_event(e);}
  mark(4);
  if (access(argv[1],F_OK)==0 || r.events()!=capacity+11 || r.blocks()!=2) return 3;
  if (!r.write(path)) return 4;
  mark(5);
  rusage rss{}; getrusage(RUSAGE_SELF,&rss);
  std::printf("{\"event_size\":%zu,\"capacity\":%zu,\"events\":%llu,\"rss_hwm_kib\":%ld,\"phases\":[",
              sizeof(e),capacity,static_cast<unsigned long long>(r.events()),rss.ru_maxrss);
  for(size_t i=1;i<marks.size();++i){
    std::printf("%s[%llu,%llu]",i==1?"":",",
      static_cast<unsigned long long>(marks[i].calls-marks[i-1].calls),
      static_cast<unsigned long long>(marks[i].bytes-marks[i-1].bytes));
  }
  std::puts("]}");
}
