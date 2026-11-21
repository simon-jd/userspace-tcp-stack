// Replay identical legal TCP traffic with three trace configurations. Compare
// wire bytes and virtual times, socket information, counters and resource use.
// The scalar operator-new counter includes allocations by the live test harness.
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <new>

#include "unit/tcp_test_util.hpp"

namespace {
std::size_t allocations;
}
void* operator new(std::size_t n) {
  void* p = std::malloc(std::max<std::size_t>(n, 1));
  if (!p) throw std::bad_alloc();
  ++allocations;
  return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

namespace {
using namespace utcp;
using namespace std::chrono_literals;
namespace t = utcp::test;

struct CountSink final : TraceSink {
  std::size_t count = 0;
  void on_event(const TraceEvent&) override { ++count; }
};

struct Run {
  TcpInfo info;
  StackStats stats;
  StackUsage usage;
  std::vector<t::Sent> packets;
  std::size_t allocations, events;
};

Run replay(CcAlgo cc, int mode) {
  auto a = t::tcpt::config(t::Side::a), b = t::tcpt::config(t::Side::b);
  a.tcp.cc = cc;
  a.trace_mask = mode == 1 ? 0 : trace_bit(TraceKind::cwnd) | trace_bit(TraceKind::recovery) |
                                  trace_bit(TraceKind::rtt);
  CountSink sink;
  t::TcpHarness h(a, b);
  if (mode != 0) h.a().set_trace_sink(&sink);
  h.set_delay(t::Side::a, 2ms);
  h.set_delay(t::Side::b, 3ms);
  unsigned segments = 0;
  h.set_hook([&](t::Side side, t::Bytes& wire) {
    const auto p = t::tcpt::parse(wire);
    return side == t::Side::a && p && t::tcpt::is_data(p->v) && ++segments == 3
               ? t::Verdict::drop : t::Verdict::deliver;
  });
  const auto payload = t::pattern(12'117);
  const auto start = allocations;
  const auto pair = t::tcpt::open(h);
  if (!pair || h.a().tcp_send(pair->client, payload).value() != payload.size()) std::abort();
  h.run_for(3s);
  const auto cost = allocations - start;
  if (t::tcpt::drain(h.b(), pair->server) != payload || h.dropped() != 1) std::abort();
  return {h.a().tcp_info(pair->client).value(), h.a().stats(), h.a().debug_usage(),
          h.log(), cost, sink.count};
}

bool equal(const Run& left, const Run& right) {
  if (left.allocations != right.allocations || left.info != right.info ||
      left.stats != right.stats || left.usage != right.usage ||
      left.packets.size() != right.packets.size()) return false;
  for (std::size_t i = 0; i < left.packets.size(); ++i) {
    const auto& a = left.packets[i];
    const auto& b = right.packets[i];
    if (a.bytes != b.bytes || a.t != b.t || a.verdict != b.verdict || a.from != b.from) return false;
  }
  return true;
}
}  // namespace

int main() {
  for (auto algorithm : {CcAlgo::newreno, CcAlgo::cubic, CcAlgo::bbr}) {
    const auto disabled = replay(algorithm, 0);
    const auto masked = replay(algorithm, 1);
    const auto enabled = replay(algorithm, 2);
    if (!equal(disabled, masked) || !equal(disabled, enabled) || masked.events || disabled.events)
      return 1;
    std::printf("%.*s packets=%zu allocations=%zu masked=%zu enabled=%zu\n",
                int(to_string(algorithm).size()), to_string(algorithm).data(), disabled.packets.size(),
                disabled.allocations, masked.events, enabled.events);
  }
}
