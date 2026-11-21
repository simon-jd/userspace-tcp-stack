#pragma once

#include "heap_probe.hpp"

#include <array>
#include <cstdlib>
#include <functional>
#include <type_traits>

enum Phase : unsigned { create, first, warm, steady_a, steady_b, shutdown_, phases };
enum Path : unsigned { stack_ctor, listen_, connect_, accept_, send_, recv_, pop_, release_, event_,
  data_, ack_, control_, next_, advance_, info_, ready_, udp_open_, udp_send_, udp_recv_,
  udp_in_, echo_send_, echo_in_, echo_poll_, close_, partial_, repeat_, sack_drain_, pmtu_, paths };
constexpr const char* phase_name[]{"create","first","warm","steady_a","steady_b","shutdown"};
constexpr const char* path_name[]{"construct","listen","connect","accept","send","recv","pop",
  "release","event","input_data","input_ack","input_control","deadline","advance","info",
  "readiness","udp_open","udp_send","udp_recv","input_udp","icmp_echo","input_icmp","echo_poll",
  "close","partial_sack","repeated_sack","sack_drain","pmtu"};
static_assert(std::size(phase_name)==phases && std::size(path_name)==paths);

inline void require(bool ok,const char* why) {
  if (!ok) { std::fprintf(stderr,"oracle failed: %s\n",why); std::abort(); }
}
struct Row {
  std::uint64_t invocations{}, bytes{}, packets{}, segments{};
  utcp_heap_counts alloc{};
};
class Windows {
public:
  Phase phase = create;
  Row& row(Path p) { return rows[phase][p]; }
  template<class F>
  __attribute__((noinline)) std::invoke_result_t<F> run(Path p,F fn) {
    auto& r = row(p);
    ++r.invocations;
    utcp_heap_label(static_cast<unsigned>(phase) * paths + p);
    utcp_heap_start();
    if constexpr (std::is_void_v<std::invoke_result_t<F>>) {
      fn();
      finish(r);
    } else {
      auto result = fn();
      finish(r);
      return result;
    }
  }
  void print() const {
    std::puts("phase,path,calls,payload_bytes,packets,logical_segments,api,entries,outer");
    for (unsigned s=0;s<phases;++s) for (unsigned p=0;p<paths;++p) {
      const auto& r=rows[s][p];
      if (!r.invocations) continue;
      for (unsigned k=0;k<heap_api_count;++k)
        std::printf("%s,%s,%llu,%llu,%llu,%llu,%s,%llu,%llu\n",phase_name[s],path_name[p],
                    (unsigned long long)r.invocations,(unsigned long long)r.bytes,
                    (unsigned long long)r.packets,(unsigned long long)r.segments,utcp_heap_name(k),
                    (unsigned long long)r.alloc.entries[k],(unsigned long long)r.alloc.outer[k]);
    }
  }
private:
  Row rows[phases][paths]{};
  static void finish(Row& r) {
    utcp_heap_counts delta;
    utcp_heap_stop(&delta);
    for (unsigned i=0;i<heap_api_count;++i) {
      r.alloc.entries[i]+=delta.entries[i];
      r.alloc.outer[i]+=delta.outer[i];
    }
  }
};
