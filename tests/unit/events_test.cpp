#include "core/events.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <vector>

#include "support/tcp_harness.hpp"
#include "utcp/stack.hpp"

namespace {

using utcp::EventQueue;
using utcp::Handle;
using utcp::Proto;
using utcp::SocketEvent;
namespace t = utcp::test;

Handle tcp(std::uint32_t slot, std::uint32_t gen = 1) { return Handle{slot, gen, Proto::tcp}; }
Handle udp(std::uint32_t slot, std::uint32_t gen = 1) { return Handle{slot, gen, Proto::udp}; }

std::vector<SocketEvent> drain(EventQueue& q) {
  std::vector<SocketEvent> out;
  while (const auto e = q.poll()) {
    out.push_back(*e);
  }
  return out;
}

// m1-ip test 8: sockets come out in first-pending order, each once, with all
// bits raised since it became pending.
TEST(Events, FirstPendingOrderAndCoalescing) {
  EventQueue q;
  q.raise(tcp(4), utcp::ev_readable);
  q.raise(tcp(1), utcp::ev_connected);
  q.raise(tcp(4), utcp::ev_writable);  // coalesced, keeps its place
  q.raise(udp(4), utcp::ev_readable);  // another protocol's slot 4: another socket
  q.raise(tcp(1), utcp::ev_writable);
  q.raise(tcp(4), utcp::ev_readable);
  EXPECT_EQ(q.queued(), 3u);
  EXPECT_EQ(q.pending(tcp(4)), utcp::ev_readable | utcp::ev_writable);
  q.check_invariants();
  const std::vector<SocketEvent> want{
      {tcp(4), utcp::ev_readable | utcp::ev_writable},
      {tcp(1), utcp::ev_connected | utcp::ev_writable},
      {udp(4), utcp::ev_readable}};
  EXPECT_EQ(drain(q), want);
  EXPECT_EQ(q.queued(), 0u);
  // Pending again after the poll: back of the queue.
  q.raise(tcp(1), utcp::ev_readable);
  q.raise(tcp(4), utcp::ev_readable);
  q.raise(tcp(1), utcp::ev_closed);
  const std::vector<SocketEvent> want2{{tcp(1), utcp::ev_readable | utcp::ev_closed},
                                       {tcp(4), utcp::ev_readable}};
  EXPECT_EQ(drain(q), want2);
  q.raise(tcp(2), 0);  // no bits: nothing
  EXPECT_EQ(q.poll(), std::nullopt);
  q.check_invariants();
}

TEST(Events, DropAndSlotReuse) {
  EventQueue q;
  q.raise(tcp(1), utcp::ev_readable);
  q.raise(tcp(2), utcp::ev_readable);
  q.raise(tcp(3), utcp::ev_readable);
  q.drop(tcp(2));
  q.drop(tcp(9));        // nothing pending: no-op
  q.drop(tcp(1, 7));     // another generation: no-op
  EXPECT_EQ(q.queued(), 2u);
  q.check_invariants();
  // Slot 3 reused by a new handle before its events were polled: the old
  // bits are replaced and the new socket queues at the back.
  q.raise(tcp(3, 2), utcp::ev_connected);
  EXPECT_EQ(q.pending(tcp(3, 1)), 0);
  EXPECT_EQ(q.pending(tcp(3, 2)), utcp::ev_connected);
  // Slot 2 pending again after the drop: at the back.
  q.raise(tcp(2), utcp::ev_writable);
  const std::vector<SocketEvent> want{{tcp(1), utcp::ev_readable},
                                      {tcp(3, 2), utcp::ev_connected},
                                      {tcp(2), utcp::ev_writable}};
  EXPECT_EQ(drain(q), want);
  q.check_invariants();
}

TEST(Events, ManySocketsAndStaleEntries) {
  EventQueue q;
  for (std::uint32_t i = 0; i < 1000; ++i) {
    q.raise(tcp(i), utcp::ev_readable);
    if (i % 3 == 0) {
      q.drop(tcp(i));
    }
  }
  q.check_invariants();
  std::uint32_t want = 0;
  std::uint32_t n = 0;
  while (const auto e = q.poll()) {
    while (want % 3 == 0) {
      ++want;
    }
    EXPECT_EQ(e->h, tcp(want));
    ++want;
    ++n;
  }
  EXPECT_EQ(n, 666u);
  q.check_invariants();
}

// Through the stack: UDP sockets raise ev_readable in the order their first
// datagram arrived, once until polled.
TEST(Events, StackDeliversUdpEventsInFirstPendingOrder) {
  t::TcpHarness h;
  auto& a = h.a();
  auto& b = h.b();
  const auto s1 = b.udp_open(utcp::Endpoint{{}, 7001});
  const auto s2 = b.udp_open(utcp::Endpoint{{}, 7002});
  const auto tx = a.udp_open(utcp::Endpoint{});
  ASSERT_TRUE(s1 && s2 && tx);
  const auto payload = t::pattern(10);
  ASSERT_TRUE(a.udp_send_to(*tx, utcp::Endpoint{h.addr(t::Side::b), 7002}, payload));
  ASSERT_TRUE(a.udp_send_to(*tx, utcp::Endpoint{h.addr(t::Side::b), 7001}, payload));
  ASSERT_TRUE(a.udp_send_to(*tx, utcp::Endpoint{h.addr(t::Side::b), 7002}, payload));
  h.settle();
  EXPECT_EQ(b.debug_usage().events_queued, 2u);
  const std::vector<SocketEvent> want{{*s2, utcp::ev_readable}, {*s1, utcp::ev_readable}};
  std::vector<SocketEvent> got;
  while (const auto e = b.poll_event()) {
    got.push_back(*e);
  }
  EXPECT_EQ(got, want);
  EXPECT_EQ(a.poll_event(), std::nullopt);  // a sending socket gets nothing
  b.debug_check();
}

}  // namespace
