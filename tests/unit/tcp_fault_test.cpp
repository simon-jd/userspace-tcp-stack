// The planted faults of TcpConfig::test_fault (DESIGN §7.3), which the
// simulator's InFlightChecker must catch: seen from the wire, the sender
// with overscaled_peer_window sends past the right edge the receiver
// advertised; without a fault, or with unscaled_peer_window (which only
// sends less), it never does.
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "tcp_test_util.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Endpoint;
using utcp::Seq32;
using utcp::StackConfig;
using utcp::TestFault;
namespace t = utcp::test;
using t::Side;
using namespace utcp::test::tcpt;

struct Wire {
  std::size_t past_edge = 0;  // new data segments from a ending past b's right edge
  std::size_t received = 0;
};

// a sends 300 kB to b, which reads slowly through a 16 KiB buffer; the
// harness log gives b's advertised edges and a's segments in order.
Wire run(TestFault fault) {
  StackConfig ca = config(Side::a);
  ca.tcp.test_fault = fault;
  t::TcpHarness h(ca, config(Side::b));
  h.set_delay(Side::a, 5ms);
  h.set_delay(Side::b, 5ms);
  utcp::TcpSocketOptions small;
  small.rcv_buf = 16 * 1024;
  Wire w;
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 4, small);
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  if (!l || !c) {
    return w;
  }
  const t::Bytes data = t::pattern(300'000, 2);
  std::size_t sent = 0;
  std::optional<utcp::Handle> s;
  std::uint8_t wscale = 0;
  std::optional<Seq32> edge, high;
  for (int i = 0; i < 5000 && w.received < data.size(); ++i) {
    if (!s) {
      if (const auto a = h.b().tcp_accept(*l)) {
        s = *a;
      }
    }
    if (sent < data.size()) {
      if (const auto n = h.a().tcp_send(*c, std::span(data).subspan(sent))) {
        sent += *n;
      }
    }
    h.run_for(5ms);
    for (const t::Sent& e : h.log()) {
      const auto p = parse(e.bytes);
      if (!p) {
        continue;
      }
      const auto& v = p->v;
      if (e.from == Side::b) {
        if (is_synack(v)) {
          wscale = v.opt.wscale.value_or(0);
          edge = v.h.ack + v.h.window;  // SYN windows are not scaled
        } else if (has(v, utcp::wire::tcp_ack)) {
          const Seq32 r = v.h.ack + (std::uint32_t{v.h.window} << wscale);
          if (!edge || after(r, *edge)) {
            edge = r;
          }
        }
      } else if (is_data(v) && edge) {
        const Seq32 end = v.h.seq + static_cast<std::uint32_t>(v.payload.size());
        if (!high || after(end, *high)) {  // new data, not a retransmission
          high = end;
          w.past_edge += after(end, *edge) ? 1u : 0u;
        }
      }
    }
    h.clear_log();
    if (s && i % 4 == 0) {
      std::array<std::byte, 2048> buf{};
      if (const auto r = h.b().tcp_recv(*s, buf)) {
        w.received += *r;
      }
    }
  }
  return w;
}

TEST(TcpFault, OverscaledPeerWindowSendsPastTheEdge) {
  const Wire none = run(TestFault::none);
  EXPECT_EQ(none.past_edge, 0u);
  EXPECT_EQ(none.received, 300'000u);
  const Wire unscaled = run(TestFault::unscaled_peer_window);
  EXPECT_EQ(unscaled.past_edge, 0u);
  const Wire over = run(TestFault::overscaled_peer_window);
  EXPECT_GT(over.past_edge, 0u);
}

}  // namespace
