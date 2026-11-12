#include "core/pmtu_cache.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <utility>
#include <vector>

#include "core/stack_impl.hpp"
#include "core/wire/icmp.hpp"
#include "support/packet_builder.hpp"
#include "utcp/checksum.hpp"
#include "utcp/config.hpp"
#include "utcp/trace.hpp"

namespace {

using utcp::Endpoint;
using utcp::Ipv4Addr;
using utcp::PmtuCache;
using utcp::Time;
using namespace std::chrono_literals;
namespace t = utcp::test;

const Ipv4Addr dst1 = Ipv4Addr::from_octets(192, 0, 2, 1);
const Ipv4Addr dst2 = Ipv4Addr::from_octets(192, 0, 2, 2);
const Ipv4Addr us = Ipv4Addr::from_octets(10, 0, 0, 1);
const Time t0{10'000'000'000};

TEST(PmtuCache, LowerNeverRaise) {
  PmtuCache c(1500, 552, 10min);
  EXPECT_EQ(c.get(dst1, t0), 1500);
  EXPECT_TRUE(c.lower(dst1, 1400, t0));
  EXPECT_EQ(c.get(dst1, t0), 1400);
  // RFC 1191 §6: a larger value never raises the estimate.
  EXPECT_FALSE(c.lower(dst1, 1450, t0 + 1s));
  EXPECT_FALSE(c.lower(dst1, 1400, t0 + 1s));
  EXPECT_FALSE(c.lower(dst2, 1500, t0));  // not below the interface MTU
  EXPECT_FALSE(c.lower(dst2, 9000, t0));
  EXPECT_EQ(c.size(), 1u);
  EXPECT_TRUE(c.lower(dst1, 1300, t0 + 2s));
  EXPECT_EQ(c.get(dst1, t0 + 2s), 1300);
  EXPECT_EQ(c.get(dst2, t0), 1500);
  c.check_invariants();
}

TEST(PmtuCache, ClampsAtMinPmtu) {
  PmtuCache c(1500, 552, 10min);
  EXPECT_TRUE(c.lower(dst1, 68, t0));
  EXPECT_EQ(c.get(dst1, t0), 552);
  EXPECT_FALSE(c.lower(dst1, 0, t0));  // already at the floor
  EXPECT_TRUE(c.lower(dst2, 551, t0));
  EXPECT_EQ(c.get(dst2, t0), 552);
  c.check_invariants();
}

TEST(PmtuCache, ExpiresAfterTheExpiryTime) {
  PmtuCache c(1500, 552, 10min);
  c.lower(dst1, 1400, t0);
  c.lower(dst2, 1200, t0 + 1min);
  EXPECT_EQ(c.next_expiry(), t0 + 10min);
  EXPECT_EQ(c.get(dst1, t0 + 10min - 1ns), 1400);
  EXPECT_EQ(c.get(dst1, t0 + 10min), 1500);  // expired: interface MTU
  EXPECT_EQ(c.size(), 2u);                   // get() does not remove
  EXPECT_EQ(c.lookup(dst1, t0 + 10min), 1500);
  EXPECT_EQ(c.size(), 1u);                   // lookup() does
  EXPECT_EQ(c.next_expiry(), t0 + 11min);
  std::vector<Ipv4Addr> gone;
  EXPECT_EQ(c.expire(t0 + 11min, [&](Ipv4Addr a) { gone.push_back(a); }), 1u);
  EXPECT_EQ(gone, std::vector<Ipv4Addr>{dst2});
  EXPECT_EQ(c.next_expiry(), Time::never());
  // Lowering again restarts the expiry from the update.
  c.lower(dst1, 1400, t0);
  c.lower(dst1, 1300, t0 + 5min);
  EXPECT_EQ(c.next_expiry(), t0 + 15min);
}

TEST(PmtuCache, FullCacheEvictsTheOldestUpdate) {
  PmtuCache c(1500, 552, 10min, 4);
  for (std::uint8_t i = 0; i < 4; ++i) {
    c.lower(Ipv4Addr::from_octets(192, 0, 2, static_cast<std::uint8_t>(10 + i)), 1400,
            t0 + std::chrono::seconds(4 - i));  // .13 is the oldest
  }
  c.lower(Ipv4Addr::from_octets(192, 0, 2, 1), 1400, t0 + 10s);
  EXPECT_EQ(c.size(), 4u);
  EXPECT_EQ(c.get(Ipv4Addr::from_octets(192, 0, 2, 13), t0 + 10s), 1500);
  EXPECT_EQ(c.get(Ipv4Addr::from_octets(192, 0, 2, 1), t0 + 10s), 1400);
  // Ties: the lowest address goes first.
  PmtuCache d(1500, 552, 10min, 2);
  d.lower(dst2, 1400, t0);
  d.lower(dst1, 1400, t0);
  d.lower(Ipv4Addr::from_octets(192, 0, 2, 3), 1400, t0);
  EXPECT_EQ(d.get(dst1, t0), 1500);
  EXPECT_EQ(d.get(dst2, t0), 1400);
  c.check_invariants();
  d.check_invariants();
}

utcp::StackConfig stack_config() {
  utcp::StackConfig cfg;
  cfg.local_addr = us;
  cfg.seed = utcp::Seed::from_u64(11);
  return cfg;
}

// m1-ip test 5: expiry after 10 min of virtual time, through advance and the
// stack's pmtu_expiry timer.
TEST(PmtuCache, StackTimerRestoresTheMtuAfterTenMinutes) {
  utcp::StackImpl s(stack_config());
  s.advance(t0);
  EXPECT_EQ(s.next_deadline(), Time::never());
  s.core.pmtu_lower(dst1, 1400);
  EXPECT_EQ(s.core.pmtu(dst1), 1400);
  EXPECT_TRUE(s.core.pmtu_timer_armed());
  EXPECT_EQ(s.next_deadline(), t0 + 10min);
  EXPECT_EQ(s.debug_usage().stack_timers_armed, 1u);
  s.advance(t0 + 5min);
  s.core.pmtu_lower(dst2, 1300);
  EXPECT_EQ(s.next_deadline(), t0 + 10min);
  s.advance(t0 + 10min - 1ns);
  EXPECT_EQ(s.core.pmtu_cache().size(), 2u);
  s.advance(t0 + 10min);
  EXPECT_EQ(s.core.pmtu_cache().size(), 1u);
  EXPECT_EQ(s.core.pmtu(dst1), 1500);
  EXPECT_EQ(s.core.pmtu(dst2), 1300);
  EXPECT_EQ(s.next_deadline(), t0 + 15min);
  s.advance(t0 + 15min);
  EXPECT_EQ(s.core.pmtu(dst2), 1500);
  EXPECT_FALSE(s.core.pmtu_timer_armed());
  EXPECT_EQ(s.next_deadline(), Time::never());
  EXPECT_EQ(s.debug_usage().stack_timers_armed, 0u);
  s.debug_check();
}

// The pmtu_expiry timer is traced when it is armed (or moved), fires and is
// cancelled (§10.2: TraceKind::timer).
TEST(PmtuCache, TimerArmFireAndCancelAreTraced) {
  class Sink final : public utcp::TraceSink {
  public:
    void on_event(const utcp::TraceEvent& e) override {
      EXPECT_EQ(e.kind, utcp::TraceKind::timer);
      EXPECT_EQ(e.timer, utcp::TraceTimer::pmtu_expiry);
      ops.emplace_back(e.t, e.timer_op);
    }
    std::vector<std::pair<Time, utcp::TimerOp>> ops;
  } sink;
  auto cfg = stack_config();
  cfg.trace_mask = utcp::trace_bit(utcp::TraceKind::timer);
  utcp::StackImpl s(cfg);
  s.core.set_trace_sink(&sink);
  s.advance(t0);
  s.core.pmtu_lower(dst1, 1400);  // armed for t0 + 10 min
  s.advance(t0 + 5min);
  s.core.pmtu_lower(dst2, 1300);  // expires later: the deadline stays
  s.core.pmtu_lower(dst1, 1300);  // dst1 now expires at t0 + 15 min too: moved
  EXPECT_EQ(s.next_deadline(), t0 + 15min);
  s.advance(t0 + 15min);          // fires; nothing left, so not re-armed
  EXPECT_FALSE(s.core.pmtu_timer_armed());
  s.core.pmtu_lower(dst1, 1400);  // armed for t0 + 25 min
  t::Bytes probe = t::udp_datagram(t::UdpSpec{Endpoint{dst2, 1}, Endpoint{us, 9}, {}});
  s.receive(t0 + 26min, probe);   // no advance: the timer is still armed
  EXPECT_EQ(s.core.pmtu(dst1), 1500);  // lazy expiry cancels it
  using Op = utcp::TimerOp;
  const std::vector<std::pair<Time, Op>> want{{t0, Op::armed},
                                              {t0 + 5min, Op::armed},
                                              {t0 + 15min, Op::fired},
                                              {t0 + 15min, Op::armed},
                                              {t0 + 26min, Op::cancelled}};
  EXPECT_EQ(sink.ops, want);
  s.debug_check();
}

// A lookup after the expiry but before advance() drops the entry and the
// timer follows.
TEST(PmtuCache, LazyExpiryKeepsTheTimerExact) {
  utcp::StackImpl s(stack_config());
  s.advance(t0);
  s.core.pmtu_lower(dst1, 1400);
  t::Bytes probe = t::udp_datagram(t::UdpSpec{Endpoint{dst2, 1}, Endpoint{us, 9}, {}});
  s.receive(t0 + 11min, probe);  // a call at a later time, no advance
  EXPECT_EQ(s.core.pmtu(dst1), 1500);
  EXPECT_FALSE(s.core.pmtu_timer_armed());
  s.debug_check();
}

// Frag-needed for a UDP datagram of a bound socket lowers the cache (Linux
// __udp4_lib_err); the next-hop MTU 0 of an old router gives the RFC 1191 §7
// plateau; a value above the current estimate never raises it.
TEST(PmtuCache, FragNeededForUdpLowersTheCache) {
  utcp::StackImpl s(stack_config());
  s.advance(t0);
  const auto h = s.udp.open(Endpoint{us, 5000});
  ASSERT_TRUE(h.has_value());
  auto offending = [&](std::uint16_t sport, std::size_t payload) {
    return t::udp_datagram(t::UdpSpec{Endpoint{us, sport}, Endpoint{dst1, 53}, t::pattern(payload)});
  };
  const Ipv4Addr router = Ipv4Addr::from_octets(192, 0, 2, 254);
  auto frag_needed = [&](std::uint16_t mtu, const t::Bytes& d) {
    return t::icmp_error(router, us, utcp::wire::icmp_dest_unreach, utcp::wire::icmp_frag_needed,
                         mtu, d, 28);
  };
  // Unbound source port: counted only.
  s.receive(t0, frag_needed(1400, offending(5001, 1472)));
  EXPECT_EQ(s.core.pmtu(dst1), 1500);
  EXPECT_EQ(s.core.stats().udp_icmp_errors, 1u);
  // A value above the current estimate: nothing changes.
  s.receive(t0, frag_needed(1600, offending(5000, 1472)));
  EXPECT_EQ(s.core.pmtu(dst1), 1500);
  // Next-hop MTU 0: the plateau below the quoted total length (1500 -> 1492).
  s.receive(t0, frag_needed(0, offending(5000, 1472)));
  EXPECT_EQ(s.core.pmtu(dst1), 1492);
  s.receive(t0, frag_needed(1400, offending(5000, 1464)));
  EXPECT_EQ(s.core.pmtu(dst1), 1400);
  // A forged tiny MTU is clamped at min_pmtu.
  s.receive(t0, frag_needed(100, offending(5000, 1372)));
  EXPECT_EQ(s.core.pmtu(dst1), 552);
  EXPECT_EQ(s.core.stats().udp_icmp_errors, 5u);
  // udp_send_to follows the cache: 552 - 28 bytes fit, one more does not.
  EXPECT_TRUE(s.udp.send_to(*h, Endpoint{dst1, 53}, t::pattern(524)).has_value());
  EXPECT_EQ(s.udp.send_to(*h, Endpoint{dst1, 53}, t::pattern(525)),
            std::unexpected(utcp::Error::message_too_big));
  s.debug_check();
}

}  // namespace
