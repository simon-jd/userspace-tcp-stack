// The Stack host interface and the IPv4 layer (DESIGN §3.4, §4.4 first
// paragraph): validation and counters, the time contract, the transmit queue
// with pool backpressure and the blocked FIFO, determinism, debug_usage.
#include "core/ip.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/stack_impl.hpp"
#include "core/timer/timer_heap.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "support/packet_builder.hpp"
#include "support/tcp_harness.hpp"
#include "utcp/checksum.hpp"
#include "utcp/stack.hpp"
#include "utcp/trace.hpp"

namespace {

using utcp::Endpoint;
using utcp::Ipv4Addr;
using utcp::Seq32;
using utcp::Stack;
using utcp::StackImpl;
using utcp::Time;
using namespace std::chrono_literals;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;

const Ipv4Addr peer = Ipv4Addr::from_octets(192, 0, 2, 50);
const Time t0{3'000'000'000};

utcp::StackConfig config() { return t::TcpHarness::default_config(Side::a); }

std::vector<t::Bytes> drain(StackImpl& s) {
  std::vector<t::Bytes> out;
  while (auto p = s.pop_transmit()) {
    const auto b = p->buf.bytes();
    out.emplace_back(b.begin(), b.end());
  }
  return out;
}

t::Bytes echo(Ipv4Addr dst, std::uint16_t seq, std::size_t n = 8) {
  return t::icmp_echo_request(peer, dst, 1, seq, t::pattern(n));
}

t::IpSpec ip_to(Ipv4Addr dst) {
  t::IpSpec ip;
  ip.src = peer;
  ip.dst = dst;
  ip.proto = utcp::ip_proto_icmp;
  return ip;
}

// m1-ip test 4: dropped and counted, nothing sent back.
TEST(StackIp, MalformedDatagramsAreDroppedAndCounted) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const auto& st = s.core.stats();
  const t::Bytes msg = t::icmp(w::icmp_echo_request, 0, 1, t::pattern(8));

  t::IpSpec frag = ip_to(us);
  frag.mf = true;  // first fragment
  s.receive(t0, t::ipv4(frag, msg));
  frag.mf = false;
  frag.frag_off = 185;  // last fragment
  s.receive(t0, t::ipv4(frag, msg));
  EXPECT_EQ(st.frag_dropped, 2u);

  t::IpSpec bad = ip_to(us);
  bad.corrupt_checksum = true;
  s.receive(t0, t::ipv4(bad, msg));
  EXPECT_EQ(st.IpExtInCsumErrors, 1u);
  EXPECT_EQ(st.IpInHdrErrors, 1u);

  s.receive(t0, t::ipv4(ip_to(Ipv4Addr::from_octets(10, 0, 0, 99)), msg));
  s.receive(t0, t::ipv4(ip_to(Ipv4Addr::from_octets(255, 255, 255, 255)), msg));
  EXPECT_EQ(st.IpInAddrErrors, 2u);

  // Truncated: shorter than 20 bytes, shorter than IHL*4, total length beyond
  // the buffer.
  const t::Bytes good = t::ipv4(ip_to(us), msg);
  s.receive(t0, std::span<const std::byte>(good).first(19));
  s.receive(t0, std::span<const std::byte>());
  t::IpSpec opts = ip_to(us);
  opts.options = t::pattern(8);
  const t::Bytes with_opts = t::ipv4(opts, msg);
  s.receive(t0, std::span<const std::byte>(with_opts).first(24));  // IHL 7 = 28 bytes
  EXPECT_EQ(st.IpInHdrErrors, 4u);
  s.receive(t0, std::span<const std::byte>(good).first(good.size() - 1));
  EXPECT_EQ(st.IpExtInTruncatedPkts, 1u);

  // Version, IHL < 5, total length below the header.
  t::IpSpec v6 = ip_to(us);
  v6.version = 6;
  s.receive(t0, t::ipv4(v6, msg));
  t::IpSpec ihl4 = ip_to(us);
  ihl4.ihl = 4;
  s.receive(t0, t::ipv4(ihl4, msg));
  t::IpSpec short_total = ip_to(us);
  short_total.total_len = 19;
  s.receive(t0, t::ipv4(short_total, msg));
  EXPECT_EQ(st.IpInHdrErrors, 7u);

  // Every datagram is counted on arrival, before any check (ip_rcv_core): 2
  // fragments, 1 bad checksum, 2 wrong destinations, 4 truncated, 3 bad headers.
  EXPECT_EQ(st.IpInReceives, 12u);
  EXPECT_EQ(st.IpInDelivers, 0u);
  EXPECT_TRUE(drain(s).empty());

  // TCP header errors: TcpInSegs counts every segment, TcpInErrs the bad ones.
  t::TcpSpec seg;
  seg.src = Endpoint{peer, 1234};
  seg.dst = Endpoint{us, 80};
  seg.flags = w::tcp_syn;
  seg.corrupt_checksum = true;
  s.receive(t0, t::tcp_datagram(seg));
  EXPECT_EQ(st.TcpInCsumErrors, 1u);
  t::Bytes doff = t::tcp_datagram(t::TcpSpec{seg.src, seg.dst});
  doff[w::ipv4_header_len + 12] = std::byte{0x40};  // data offset 4
  t::fix_checksums(doff);
  s.receive(t0, doff);
  doff[w::ipv4_header_len + 12] = std::byte{0xf0};  // 60 bytes, beyond the segment
  t::fix_checksums(doff);
  s.receive(t0, doff);
  s.receive(t0, t::raw_datagram(peer, us, utcp::ip_proto_tcp, t::pattern(19)));
  EXPECT_EQ(st.TcpInSegs, 4u);
  EXPECT_EQ(st.TcpInErrs, 4u);
  // A valid segment reaches the engine (no listener: it answers with an RST).
  seg.corrupt_checksum = false;
  s.receive(t0, t::tcp_datagram(seg));
  EXPECT_EQ(st.TcpInSegs, 5u);
  EXPECT_EQ(st.TcpInErrs, 4u);
  // With RxMeta::csum_verified a bad checksum is not seen.
  seg.corrupt_checksum = true;
  s.receive(t0, t::tcp_datagram(seg), utcp::RxMeta{true, false, 0});
  s.receive(t0, t::tcp_datagram(seg), utcp::RxMeta{false, true, 0});
  EXPECT_EQ(st.TcpInErrs, 4u);
  EXPECT_EQ(st.IpInDelivers, 7u);
  s.debug_check();
}

TEST(StackIp, OptionsAndLinkPaddingAreSkipped) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  t::IpSpec ip = ip_to(us);
  ip.options = t::Bytes{std::byte{7}, std::byte{7}, std::byte{4}, std::byte{0}, std::byte{0},
                        std::byte{0}, std::byte{0}};  // record route, padded to 8
  t::Bytes d = t::ipv4(ip, t::icmp(w::icmp_echo_request, 0, 0x00020003, t::pattern(12)));
  d.resize(d.size() + 18, std::byte{0});  // Ethernet minimum-frame padding
  s.receive(t0, d);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  const auto reply = w::parse_ipv4(out[0]);
  ASSERT_TRUE(reply.has_value());
  EXPECT_EQ(reply->ihl, 5);
  EXPECT_EQ(reply->payload.size(), 8u + 12u);
}

// m1-ip test 4: `now` going backwards.
TEST(StackIp, TimeRegressionIsClampedAndCounted) {
  auto cfg = config();
  cfg.assert_time_monotonic = false;
  StackImpl s(cfg);
  s.advance(t0);
  s.advance(t0 - 1ms);
  EXPECT_EQ(s.core.now(), t0);
  EXPECT_EQ(s.core.stats().time_regressions, 1u);
  s.receive(t0 - 1s, echo(s.core.local_addr(), 1));
  EXPECT_EQ(s.core.now(), t0);
  EXPECT_EQ(s.core.stats().time_regressions, 2u);
  EXPECT_EQ(drain(s).size(), 1u);  // processed at the clamped time
  s.advance(t0);                   // equal is fine
  s.advance(t0 + 1ns);
  EXPECT_EQ(s.core.stats().time_regressions, 2u);
  EXPECT_EQ(s.core.now(), t0 + 1ns);
  Stack pub(cfg);
  pub.advance(t0);
  pub.receive(t0 - 1ns, echo(cfg.local_addr, 1));
  EXPECT_EQ(pub.now(), t0);
  EXPECT_EQ(pub.stats().time_regressions, 1u);
}

TEST(StackIpDeathTest, TimeRegressionAssertsWhenAsked) {
  auto cfg = config();
  cfg.assert_time_monotonic = true;
  Stack s(cfg);
  s.advance(t0);
  EXPECT_DEATH(s.advance(t0 - 1ns), "assert_time_monotonic");
  EXPECT_DEATH(s.receive(t0 - 1ns, echo(cfg.local_addr, 1)), "assert_time_monotonic");
}

// m1-ip test 8: datagrams leave in production order.
TEST(StackIp, PopTransmitInProductionOrder) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const utcp::Handle u = *s.udp.open(Endpoint{{}, 9000});
  for (std::uint16_t i = 0; i < 10; ++i) {
    if (i % 3 == 0) {
      ASSERT_TRUE(s.udp.send_to(u, Endpoint{peer, 53}, t::pattern(i)));
    } else {
      s.receive(t0, echo(us, i));
    }
  }
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 10u);
  for (std::uint16_t i = 0; i < 10; ++i) {
    const auto ip = w::parse_ipv4(out[i]);
    ASSERT_TRUE(ip.has_value());
    if (i % 3 == 0) {
      EXPECT_EQ(ip->h.proto, utcp::ip_proto_udp);
      EXPECT_EQ(ip->payload.size(), 8u + i);
    } else {
      const auto m = w::parse_icmp(ip->payload, true);
      ASSERT_TRUE(m.has_value());
      EXPECT_EQ(m->h.echo_seq(), i);
    }
  }
  EXPECT_EQ(s.core.stats().IpOutRequests, 10u);
}

// m1-ip test 8: pool exhaustion drops control packets and counts them; the
// host still holds the packets it popped.
TEST(StackIp, PoolExhaustionDropsControlPackets) {
  auto cfg = config();
  cfg.pool_buffers = 4;
  StackImpl s(cfg);
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  for (std::uint16_t i = 0; i < 6; ++i) {
    s.receive(t0, echo(us, i));
  }
  EXPECT_EQ(s.core.tx_queue().size(), 4u);
  EXPECT_EQ(s.core.stats().IpOutDiscards, 2u);
  // The host pops but does not drop yet: buffers are still out.
  std::vector<utcp::TxPacket> held;
  while (auto p = s.pop_transmit()) {
    held.push_back(std::move(*p));
  }
  s.receive(t0, echo(us, 7));
  EXPECT_EQ(s.core.stats().IpOutDiscards, 3u);
  EXPECT_FALSE(s.core.can_transmit());
  held.pop_back();  // one buffer back
  EXPECT_TRUE(s.core.can_transmit());
  s.receive(t0, echo(us, 9));
  EXPECT_EQ(s.core.tx_queue().size(), 1u);
  held.clear();
  drain(s);
  EXPECT_EQ(s.debug_usage().pool_buffers_free, 4u);
  // Queue limit: same counter.
  auto cfg2 = config();
  cfg2.tx_queue_packets = 3;
  StackImpl q(cfg2);
  q.advance(t0);
  for (std::uint16_t i = 0; i < 5; ++i) {
    q.receive(t0, echo(us, i));
  }
  EXPECT_EQ(q.core.tx_queue().size(), 3u);
  EXPECT_EQ(q.core.stats().IpOutDiscards, 2u);
  s.debug_check();
  q.debug_check();
}


// A producer standing in for TCP connections: it sends data packets while
// there is space, then a pure ACK if one is pending, and joins the blocked
// FIFO when anything is left (what the engine does, §3.4).
class FakeProducer final : public utcp::TxSpaceListener {
public:
  struct Conn {
    std::uint32_t pending = 0;
    bool ack_pending = false;
    char tag = 0;
  };

  explicit FakeProducer(utcp::StackCore& core) : core_(core) {}

  void produce(std::uint32_t slot) {
    Conn& c = conns[slot];
    while (c.pending > 0 && core_.can_transmit()) {
      send(slot, c.tag, false);
      --c.pending;
    }
    if (c.pending == 0 && c.ack_pending && core_.can_transmit()) {
      send(slot, c.tag, true);
      c.ack_pending = false;
    }
    if (c.pending > 0 || c.ack_pending) {
      core_.block_tx(slot);
    }
  }

  void on_tx_space(Time, std::uint32_t slot) override {
    resumed.push_back(slot);
    if (on_resume) {
      on_resume(slot);
    } else {
      produce(slot);
    }
  }

  std::map<std::uint32_t, Conn> conns;
  std::vector<std::uint32_t> resumed;
  // Replaces produce() in on_tx_space when set.
  std::function<void(std::uint32_t)> on_resume;

private:
  void send(std::uint32_t slot, char tag, bool ack) {
    auto buf = core_.alloc_packet(2, 0);
    ASSERT_TRUE(buf.has_value());
    std::byte* p = buf->prepend(2);
    p[0] = static_cast<std::byte>(tag);
    p[1] = static_cast<std::byte>(ack ? 1 : 0);
    EXPECT_TRUE(core_.send_ipv4(peer, 253, 0, std::move(*buf), slot));
  }

  utcp::StackCore& core_;
};

// The (tag, is_ack) of each queued packet of the fake producer.
std::string drain_tags(StackImpl& s) {
  std::string out;
  while (auto p = s.pop_transmit()) {
    const auto b = p->buf.bytes();
    out += static_cast<char>(b[w::ipv4_header_len]);
    if (b[w::ipv4_header_len + 1] == std::byte{1}) {
      out += '!';
    }
  }
  return out;
}

// m1-ip test 8: fill the queue, drain one packet, next_deadline() == now(),
// and the next advance resumes blocked producers in FIFO order; a pure ACK
// that does not fit stays pending.
TEST(StackIp, BackpressureResumesBlockedProducersInFifoOrder) {
  auto cfg = config();
  cfg.tx_queue_packets = 4;
  StackImpl s(cfg);
  s.advance(t0);
  FakeProducer f(s.core);
  s.core.set_tx_listener(&f);
  f.conns[1] = {5, false, 'A'};
  f.conns[2] = {3, false, 'B'};
  f.conns[3] = {0, true, 'C'};  // only a pure ACK
  f.produce(1);
  f.produce(2);
  f.produce(3);
  EXPECT_EQ(s.core.tx_queue().size(), 4u);
  EXPECT_EQ(s.core.queued_for(1), 4u);
  EXPECT_EQ(s.debug_usage().blocked_conns, 3u);
  EXPECT_TRUE(f.conns[3].ack_pending);  // did not fit: kept, not dropped
  EXPECT_EQ(s.next_deadline(), Time::never());
  {
    auto one = s.pop_transmit();  // drained, not yet released: queue space only
    ASSERT_TRUE(one.has_value());
    EXPECT_EQ(s.next_deadline(), s.core.now());
  }
  EXPECT_EQ(s.next_deadline(), s.core.now());
  s.advance(s.core.now());
  // A got the one free place; B and C were not resumed (no space left).
  EXPECT_EQ(f.resumed, (std::vector<std::uint32_t>{1}));
  EXPECT_EQ(f.conns[1].pending, 0u);
  EXPECT_EQ(s.next_deadline(), Time::never());
  EXPECT_EQ(drain_tags(s), "AAAA");
  EXPECT_EQ(s.next_deadline(), s.core.now());
  s.advance(s.core.now() + 1us);
  // FIFO order: B (2 sent... all 3 fit) then C's ACK.
  EXPECT_EQ(f.resumed, (std::vector<std::uint32_t>{1, 2, 3}));
  EXPECT_EQ(drain_tags(s), "BBBC!");
  EXPECT_EQ(s.debug_usage().blocked_conns, 0u);
  EXPECT_EQ(s.next_deadline(), Time::never());
  s.debug_check();
}

// A producer that blocks again during its resume waits for the next advance
// and goes behind those already waiting.
TEST(StackIp, ReblockedProducerGoesToTheBack) {
  auto cfg = config();
  cfg.tx_queue_packets = 4;
  StackImpl s(cfg);
  s.advance(t0);
  FakeProducer f(s.core);
  s.core.set_tx_listener(&f);
  f.conns[7] = {12, false, 'X'};
  f.conns[4] = {2, false, 'Y'};
  f.produce(7);
  f.produce(4);
  EXPECT_EQ(drain_tags(s), "XXXX");
  s.advance(s.core.now());
  EXPECT_EQ(f.resumed, (std::vector<std::uint32_t>{7}));  // filled the queue again
  EXPECT_EQ(drain_tags(s), "XXXX");
  s.advance(s.core.now());
  EXPECT_EQ(f.resumed, (std::vector<std::uint32_t>{7, 4, 7}));
  EXPECT_EQ(drain_tags(s), "YYXX");
  s.advance(s.core.now());
  EXPECT_EQ(drain_tags(s), "XX");
  EXPECT_EQ(s.debug_usage().blocked_conns, 0u);
  // unblock_tx removes a freed producer from the FIFO.
  s.core.block_tx(1);
  s.core.block_tx(2);
  s.core.block_tx(3);
  s.core.unblock_tx(2);
  s.core.unblock_tx(9);
  s.advance(s.core.now());
  EXPECT_EQ(f.resumed, (std::vector<std::uint32_t>{7, 4, 7, 7, 1, 3}));
}

// Each producer blocked when advance() starts is resumed at most once, even
// when a resumed one removes a later one (unblock_tx) and blocks again; one
// that blocks for the first time during the call also waits for the next.
TEST(StackIp, ResumeRunsEachBlockedProducerAtMostOnce) {
  StackImpl s(config());
  s.advance(t0);
  FakeProducer f(s.core);
  s.core.set_tx_listener(&f);
  f.on_resume = [&](std::uint32_t slot) {
    if (slot == 1) {
      s.core.unblock_tx(2);
      s.core.block_tx(1);
    }
  };
  s.core.block_tx(1);
  s.core.block_tx(2);
  s.advance(s.core.now());
  EXPECT_EQ(f.resumed, (std::vector<std::uint32_t>{1}));
  EXPECT_TRUE(s.core.blocked().contains(1));
  EXPECT_FALSE(s.core.blocked().contains(2));
  EXPECT_EQ(s.next_deadline(), s.core.now());
  f.on_resume = [&](std::uint32_t slot) {
    if (slot == 1) {
      s.core.block_tx(5);
    }
  };
  s.advance(s.core.now());
  EXPECT_EQ(f.resumed, (std::vector<std::uint32_t>{1, 1}));
  EXPECT_TRUE(s.core.blocked().contains(5));
  s.advance(s.core.now());
  EXPECT_EQ(f.resumed, (std::vector<std::uint32_t>{1, 1, 5}));
  EXPECT_TRUE(s.core.blocked().empty());
  EXPECT_EQ(s.next_deadline(), Time::never());
  s.debug_check();
}

// §3.4, §6: advance() resumes blocked producers before it fires the timers
// due at the same time.
TEST(StackIp, AdvanceResumesProducersBeforeFiringTimers) {
  auto cfg = config();
  cfg.tx_queue_packets = 1;
  cfg.trace_mask = utcp::trace_bit(utcp::TraceKind::timer);
  StackImpl s(cfg);
  s.advance(t0);
  std::vector<std::string> order;
  class Sink final : public utcp::TraceSink {
  public:
    explicit Sink(std::vector<std::string>& order) : order_(order) {}
    void on_event(const utcp::TraceEvent& e) override {
      if (e.timer == utcp::TraceTimer::pmtu_expiry && e.timer_op == utcp::TimerOp::fired) {
        order_.emplace_back("pmtu_expiry fired");
      }
    }

  private:
    std::vector<std::string>& order_;
  } sink(order);
  s.core.set_trace_sink(&sink);
  FakeProducer f(s.core);
  s.core.set_tx_listener(&f);
  f.on_resume = [&](std::uint32_t slot) {
    order.push_back("resume " + std::to_string(slot));
    f.produce(slot);
  };
  s.core.pmtu_lower(peer, 1000);  // pmtu_expiry due at t0 + 10 min
  f.conns[4] = {2, false, 'A'};
  f.produce(4);  // one packet fills the queue; 4 blocks
  EXPECT_TRUE(s.core.blocked().contains(4));
  EXPECT_EQ(drain_tags(s), "A");  // space again
  s.advance(t0 + 10min);
  EXPECT_EQ(order, (std::vector<std::string>{"resume 4", "pmtu_expiry fired"}));
  EXPECT_EQ(s.core.pmtu(peer), 1500);
  EXPECT_EQ(drain_tags(s), "A");
  s.debug_check();
}

// A connection's queued packets stop counting for its slot once the engine
// releases the slot, so the next connection in that slot starts at 0; the
// packets are still sent.
TEST(StackIp, ReleasedSlotsPacketsDoNotCountForTheNextConnection) {
  StackImpl s(config());
  s.advance(t0);
  FakeProducer f(s.core);
  f.conns[3] = {2, false, 'O'};
  f.produce(3);
  EXPECT_EQ(s.core.queued_for(3), 2u);
  s.core.release_tx_owner(3);
  EXPECT_EQ(s.core.queued_for(3), 0u);
  s.debug_check();
  f.conns[3] = {1, false, 'N'};  // a new connection in slot 3
  f.produce(3);
  EXPECT_EQ(s.core.queued_for(3), 1u);
  s.core.release_tx_owner(4);  // nothing queued: no-op
  EXPECT_EQ(drain_tags(s), "OON");
  EXPECT_EQ(s.core.queued_for(3), 0u);
  s.debug_check();
}

// §6: due timers fire in (deadline, arm_seq) order with handlers that
// cancel a due timer, re-arm one later and arm a new one after now.
TEST(StackIp, DueTimerRunnerFiresInKeyOrder) {
  utcp::TimerHeap heap;
  utcp::DueTimerRunner runner;
  std::vector<utcp::TimerId> id;
  for (std::uint32_t owner = 0; owner < 6; ++owner) {
    id.push_back(heap.create(owner, utcp::TimerKind::delack));
  }
  heap.arm(id[2], t0 - 2ms);
  heap.arm(id[1], t0 - 5ms);
  heap.arm(id[3], t0 - 2ms);  // same deadline as 2, armed later: fires after it
  heap.arm(id[4], t0);
  heap.arm(id[5], t0 - 1ms);
  std::vector<std::uint32_t> fired;
  runner.run(heap, t0, [&](const utcp::FiredTimer& f) {
    fired.push_back(f.owner);
    if (f.owner == 1) {
      heap.cancel(id[5]);
      heap.arm(id[4], t0 + 1ms);
      heap.arm(id[0], t0 + 1ns);
    }
  });
  EXPECT_EQ(fired, (std::vector<std::uint32_t>{1, 2, 3}));
  EXPECT_EQ(heap.next_deadline(), t0 + 1ns);
  // The same timer may fire again in a later run.
  heap.arm(id[1], t0 + 2ms);
  runner.run(heap, t0 + 2ms, [&](const utcp::FiredTimer& f) { fired.push_back(f.owner); });
  EXPECT_EQ(fired, (std::vector<std::uint32_t>{1, 2, 3, 0, 4, 1}));
  heap.check_invariants();
}

// §6: a handler that arms a timer at or before now aborts.
TEST(StackIpDeathTest, HandlerArmingATimerAtOrBeforeNowAborts) {
  // The handled timer re-armed at now (once, so that without the check the
  // run ends instead of looping).
  EXPECT_DEATH(
      {
        utcp::TimerHeap heap;
        utcp::DueTimerRunner runner;
        const utcp::TimerId a = heap.create(1, utcp::TimerKind::delack);
        heap.arm(a, t0 - 1ms);
        int fired = 0;
        runner.run(heap, t0, [&](const utcp::FiredTimer&) {
          if (fired++ == 0) {
            heap.arm(a, t0);
          }
        });
      },
      "UTCP_CHECK");
  // Another timer armed before the handled timer's deadline.
  EXPECT_DEATH(
      {
        utcp::TimerHeap heap;
        utcp::DueTimerRunner runner;
        const utcp::TimerId a = heap.create(1, utcp::TimerKind::delack);
        const utcp::TimerId b = heap.create(2, utcp::TimerKind::delack);
        heap.arm(a, t0 - 1ms);
        runner.run(heap, t0, [&](const utcp::FiredTimer& f) {
          if (f.id == a) {
            heap.arm(b, t0 - 2ms);
          }
        });
      },
      "UTCP_CHECK");
  // Another timer armed between the handled timer's deadline and now: only
  // the next_arm_seq() mark catches it.
  EXPECT_DEATH(
      {
        utcp::TimerHeap heap;
        utcp::DueTimerRunner runner;
        const utcp::TimerId a = heap.create(1, utcp::TimerKind::delack);
        const utcp::TimerId b = heap.create(2, utcp::TimerKind::delack);
        heap.arm(a, t0 - 2ms);
        runner.run(heap, t0, [&](const utcp::FiredTimer& f) {
          if (f.id == a) {
            heap.arm(b, t0 - 1ms);
          }
        });
      },
      "UTCP_CHECK");
}

// Pool space counts like queue space: a host that keeps popped packets
// blocks producers until it releases them.
TEST(StackIp, BufferReleaseResumesProducers) {
  auto cfg = config();
  cfg.pool_buffers = 3;
  StackImpl s(cfg);
  s.advance(t0);
  FakeProducer f(s.core);
  s.core.set_tx_listener(&f);
  f.conns[1] = {5, false, 'A'};
  f.produce(1);
  std::vector<utcp::TxPacket> held;
  while (auto p = s.pop_transmit()) {
    held.push_back(std::move(*p));
  }
  EXPECT_EQ(held.size(), 3u);
  EXPECT_TRUE(s.core.tx_queue().empty());
  EXPECT_EQ(s.next_deadline(), Time::never());  // queue empty, pool empty
  held.pop_back();
  EXPECT_EQ(s.next_deadline(), s.core.now());
  s.advance(s.core.now());
  EXPECT_EQ(f.conns[1].pending, 1u);
  EXPECT_EQ(s.next_deadline(), Time::never());  // the new packet took the buffer
  held.clear();
  EXPECT_EQ(s.next_deadline(), s.core.now());
  s.advance(s.core.now());
  EXPECT_EQ(drain_tags(s), "AA");
  EXPECT_EQ(f.conns[1].pending, 0u);
  EXPECT_EQ(s.next_deadline(), Time::never());
}

// m1-ip test 9: the same inputs to fresh stacks give the same output bytes.
std::vector<t::Bytes> scripted_run(const utcp::StackConfig& cfg) {
  Stack s(cfg);
  std::vector<t::Bytes> out;
  auto collect = [&] {
    while (auto p = s.pop_transmit()) {
      const auto b = p->buf.bytes();
      out.emplace_back(b.begin(), b.end());
    }
    while (auto e = s.poll_event()) {
      out.push_back(t::Bytes{std::byte{0xEE}, static_cast<std::byte>(e->h.slot),
                             static_cast<std::byte>(e->events)});
    }
  };
  const Ipv4Addr us = cfg.local_addr;
  Time now = t0;
  s.advance(now);
  const auto u1 = s.udp_open(Endpoint{{}, 0});
  const auto u2 = s.udp_open(Endpoint{{}, 7777});
  for (int round = 0; round < 40; ++round) {
    const auto r = static_cast<std::uint16_t>(round);
    now += std::chrono::microseconds(137 * (round % 7 + 1));
    s.advance(now);
    s.receive(now, echo(us, r, static_cast<std::size_t>(round)));
    s.receive(now, t::udp_datagram(t::UdpSpec{Endpoint{peer, 1000}, Endpoint{us, 7777},
                                              t::pattern(static_cast<std::size_t>(round) * 13)}));
    s.receive(now, t::udp_datagram(t::UdpSpec{Endpoint{peer, 1000}, Endpoint{us, 7778}, t::pattern(3)}));
    s.receive(now, t::raw_datagram(peer, us, 200, t::pattern(5)));
    if (round % 5 == 0) {
      const t::Bytes sent = t::udp_datagram(t::UdpSpec{Endpoint{us, 7777}, Endpoint{peer, 53},
                                                       t::pattern(1472)});
      s.receive(now, t::icmp_error(peer, us, w::icmp_dest_unreach, w::icmp_frag_needed,
                                   static_cast<std::uint32_t>(1400 - 10 * round), sent, 28));
    }
    (void)s.udp_send_to(*u1, Endpoint{peer, 53}, t::pattern(static_cast<std::size_t>(round)));
    (void)s.icmp_echo(peer, 3, r, t::pattern(16));
    t::Bytes buf(2000);
    if (round % 3 == 0) {
      while (s.udp_recv_from(*u2, buf)) {
      }
    }
    collect();
  }
  s.advance(now + 11min);  // PMTU entries expire
  (void)s.udp_send_to(*u1, Endpoint{peer, 53}, t::pattern(1472));
  collect();
  s.debug_check();
  return out;
}

TEST(StackIp, SameInputsGiveIdenticalOutputBytes) {
  const auto cfg = config();
  const auto first = scripted_run(cfg);
  const auto second = scripted_run(cfg);
  EXPECT_GT(first.size(), 150u);
  EXPECT_EQ(first, second);
  // Another seed changes the ephemeral port, so the output differs.
  auto other = cfg;
  other.seed = utcp::Seed::from_u64(99);
  EXPECT_NE(scripted_run(other), first);
}

TEST(StackIp, HarnessRunsAreDeterministic) {
  auto run = [] {
    t::TcpHarness h;
    h.set_delay(Side::a, 2ms);
    h.set_delay(Side::b, 3ms);
    const auto ua = h.a().udp_open(Endpoint{});
    const auto ub = h.b().udp_open(Endpoint{{}, 4000});
    std::vector<t::Bytes> log;
    for (std::uint16_t i = 0; i < 50; ++i) {
      (void)h.a().udp_send_to(*ua, Endpoint{h.addr(Side::b), static_cast<std::uint16_t>(3999 + i % 2)},
                              t::pattern(i));
      (void)h.b().icmp_echo(h.addr(Side::a), 1, i, t::pattern(i));
      h.run_for(std::chrono::microseconds(700));
    }
    h.run_for(1s);
    for (const auto& sent : h.log()) {
      log.push_back(sent.bytes);
    }
    (void)ub;
    return log;
  };
  const auto a = run();
  EXPECT_EQ(a, run());
  EXPECT_EQ(a.size(), 50u + 25u + 50u + 50u);  // UDP, port unreachables, echoes, replies
}

// m1-ip test 10: debug_usage reports pool, queue and event counts.
TEST(StackIp, DebugUsageReportsResources) {
  auto cfg = config();
  cfg.pool_buffers = 64;
  StackImpl s(cfg);
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const auto u = s.udp.open(Endpoint{{}, 100});
  (void)s.udp.open(Endpoint{{}, 101});
  for (std::uint16_t i = 0; i < 3; ++i) {
    s.receive(t0, echo(us, i));
  }
  s.receive(t0, t::udp_datagram(t::UdpSpec{Endpoint{peer, 1}, Endpoint{us, 100}, t::pattern(10)}));
  s.receive(t0, t::udp_datagram(t::UdpSpec{Endpoint{peer, 1}, Endpoint{us, 101}, t::pattern(10)}));
  t::IpSpec ip = ip_to(us);
  s.receive(t0, t::ipv4(ip, t::icmp(w::icmp_echo_reply, 0, 1, t::pattern(1))));
  s.core.pmtu_lower(peer, 1000);
  const utcp::StackUsage got = s.debug_usage();
  utcp::StackUsage want;
  want.udp_slots = 2;
  want.pool_buffers = 64;
  want.pool_buffers_free = 61;
  want.chunks = 2;
  want.chunks_free = 0;
  want.tx_queued = 3;
  want.events_queued = 2;
  want.echo_replies_queued = 1;
  want.stack_timers_armed = 1;
  EXPECT_EQ(got, want);
  // Draining gives everything back.
  drain(s);
  while (s.poll_event()) {
  }
  t::Bytes buf(64);
  while (s.udp.recv_from(*u, buf)) {
  }
  (void)s.icmp.poll_echo_reply();
  const utcp::StackUsage after = s.debug_usage();
  EXPECT_EQ(after.tx_queued, 0u);
  EXPECT_EQ(after.pool_buffers_free, 64u);
  EXPECT_EQ(after.events_queued, 0u);
  EXPECT_EQ(after.echo_replies_queued, 0u);
  EXPECT_EQ(after.chunks - after.chunks_free, 1u);  // socket 101 still holds its datagram
  s.debug_check();
}

}  // namespace
