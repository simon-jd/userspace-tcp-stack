#include "core/tcp/cc_newreno.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string_view>
#include <utility>
#include <vector>

#include "core/tcp/cc.hpp"

namespace {

using utcp::AckOutcome;
using utcp::CcConn;
using utcp::NewReno;

CcConn conn(std::uint32_t cwnd, std::uint32_t ssthresh) {
  CcConn c;
  c.cwnd = cwnd;
  c.ssthresh = ssthresh;
  c.cwnd_limited = true;
  return c;
}

AckOutcome delivered(std::uint32_t n) {
  AckOutcome o;
  o.delivered = n;
  return o;
}

TEST(CcNewreno, SlowStartAddsDeliveredUpToSsthresh) {
  NewReno r;
  CcConn c = conn(10, 15);
  r.cong_avoid(c, delivered(3));
  EXPECT_EQ(c.cwnd, 13u);
  EXPECT_EQ(c.cwnd_cnt, 0u);
  // 4 more: 2 reach ssthresh, the other 2 count toward congestion avoidance.
  r.cong_avoid(c, delivered(4));
  EXPECT_EQ(c.cwnd, 15u);
  EXPECT_EQ(c.cwnd_cnt, 2u);
  // Infinite initial ssthresh: pure doubling per window.
  CcConn d = conn(10, utcp::cwnd_infinite);
  r.cong_avoid(d, delivered(10));
  EXPECT_EQ(d.cwnd, 20u);
}

TEST(CcNewreno, ProfileThresholdAndDelayedAck) {
  NewReno r;
  for (auto flavor : {utcp::CcFlavor::rfc, utcp::CcFlavor::linux}) {
    CcConn c = conn(20, 30);
    c.flavor = flavor;
    c.packets_out = 12;
    const bool rfc = flavor == utcp::CcFlavor::rfc;
    EXPECT_EQ(r.ssthresh(c), rfc ? 6u : 10u);
    r.cong_avoid(c, delivered(2));
    EXPECT_EQ(c.cwnd, rfc ? 21u : 22u);
    EXPECT_EQ(c.cwnd_cnt, 0u);
    c.cwnd = 29;
    c.cwnd_cnt = 29;
    r.cong_avoid(c, delivered(3));
    EXPECT_EQ(c.cwnd, 31u);  // one packet reached ssthresh, two entered AI
    EXPECT_EQ(c.cwnd_cnt, 1u);
  }
}

TEST(CcNewreno, CongestionAvoidanceAddsOnePerCwndDelivered) {
  NewReno r;
  CcConn c = conn(20, 10);
  for (int i = 0; i < 19; ++i) {
    r.cong_avoid(c, delivered(1));
  }
  EXPECT_EQ(c.cwnd, 20u);
  EXPECT_EQ(c.cwnd_cnt, 19u);
  r.cong_avoid(c, delivered(1));
  EXPECT_EQ(c.cwnd, 21u);
  EXPECT_EQ(c.cwnd_cnt, 0u);
  // A stretch ACK of 45 packets at cwnd 21: two increments, 3 left.
  r.cong_avoid(c, delivered(45));
  EXPECT_EQ(c.cwnd, 23u);
  EXPECT_EQ(c.cwnd_cnt, 3u);
  // Credits accumulated at a higher cwnd apply at once at a lower one.
  c.ssthresh = 2;
  c.cwnd = 4;
  c.cwnd_cnt = 10;
  r.cong_avoid(c, delivered(1));
  EXPECT_EQ(c.cwnd, 5u);
  EXPECT_EQ(c.cwnd_cnt, 1u);
}

TEST(CcNewreno, NoGrowthWhenNotCwndLimited) {
  NewReno r;
  CcConn c = conn(10, 100);
  c.cwnd_limited = false;
  r.cong_avoid(c, delivered(10));
  EXPECT_EQ(c.cwnd, 10u);
  CcConn d = conn(20, 10);
  d.cwnd_limited = false;
  r.cong_avoid(d, delivered(100));
  EXPECT_EQ(d.cwnd, 20u);
  EXPECT_EQ(d.cwnd_cnt, 0u);
}

TEST(CcNewreno, SlowStartGrowsBelowTwiceMaxPacketsOut) {
  // Linux tcp_is_cwnd_limited: not cwnd-limited (app- or rwnd-limited), but
  // in slow start cwnd still grows while below 2 * max_packets_out.
  NewReno r;
  CcConn c = conn(10, utcp::cwnd_infinite);
  c.cwnd_limited = false;
  c.max_packets_out = 8;
  r.cong_avoid(c, delivered(4));
  EXPECT_EQ(c.cwnd, 14u);  // tcp_reno_cong_avoid: 10 < 16
  r.cong_avoid(c, delivered(4));
  EXPECT_EQ(c.cwnd, 18u);  // 14 < 16
  r.cong_avoid(c, delivered(4));
  EXPECT_EQ(c.cwnd, 18u);  // 18 >= 16: no growth
  // Not in slow start: max_packets_out does not matter.
  CcConn d = conn(20, 10);
  d.cwnd_limited = false;
  d.max_packets_out = 100;
  r.cong_avoid(d, delivered(40));
  EXPECT_EQ(d.cwnd, 20u);
  EXPECT_EQ(d.cwnd_cnt, 0u);
}

TEST(CcNewreno, IsCwndLimited) {
  struct Row {
    std::uint32_t cwnd, ssthresh, max_packets_out;
    bool limited, expect;
  };
  const Row rows[] = {
      {10, 100, 0, true, true},     {10, 100, 0, false, false},  {10, 100, 5, false, false},
      {10, 100, 6, false, true},    {10, 10, 100, false, false}, {10, 9, 100, true, true},
      {0x7fff'fffe, utcp::cwnd_infinite, 0x7fff'ffff, false, true},
  };
  for (const Row& row : rows) {
    CcConn c = conn(row.cwnd, row.ssthresh);
    c.cwnd_limited = row.limited;
    c.max_packets_out = row.max_packets_out;
    EXPECT_EQ(utcp::is_cwnd_limited(c), row.expect) << row.cwnd << " " << row.max_packets_out;
  }
}

// Logs cwnd_event calls; optionally claims cong_control (BBR).
class EventLog final : public utcp::CongestionControl {
public:
  [[nodiscard]] std::string_view name() const override { return "log"; }
  std::uint32_t ssthresh(const CcConn&) override { return 2; }
  void cong_avoid(CcConn&, const AckOutcome&) override {}
  void cwnd_event(CcConn& c, utcp::CaEvent e) override { events.emplace_back(e, c.cwnd); }
  [[nodiscard]] bool has_cong_control() const override { return own_cwnd; }

  bool own_cwnd = false;
  std::vector<std::pair<utcp::CaEvent, std::uint32_t>> events;  // (event, cwnd at the call)
};

TEST(CcNewreno, CwndRestartRfc5681) {
  using namespace std::chrono_literals;
  EventLog log;
  CcConn c = conn(40, 20);
  // Idle for exactly one RTO: nothing.
  EXPECT_FALSE(utcp::cwnd_restart(c, log, utcp::IdleRestart::rfc5681, 1s, 1s, 10));
  EXPECT_EQ(c.cwnd, 40u);
  EXPECT_TRUE(log.events.empty());
  // Longer: cwnd = min(IW, cwnd), ssthresh unchanged.
  EXPECT_TRUE(utcp::cwnd_restart(c, log, utcp::IdleRestart::rfc5681, 1001ms, 1s, 10));
  EXPECT_EQ(c.cwnd, 10u);
  EXPECT_EQ(c.ssthresh, 20u);
  EXPECT_EQ(log.events, (std::vector<std::pair<utcp::CaEvent, std::uint32_t>>{
                            {utcp::CaEvent::cwnd_restart, 40}}));
  // A cwnd below IW stays.
  CcConn d = conn(4, 20);
  EXPECT_TRUE(utcp::cwnd_restart(d, log, utcp::IdleRestart::rfc5681, 10s, 1s, 10));
  EXPECT_EQ(d.cwnd, 4u);
}

TEST(CcNewreno, CwndRestartLinux) {
  using namespace std::chrono_literals;
  struct Row {
    std::uint32_t cwnd;
    utcp::Duration idle;
    std::uint32_t expect;
  };
  // tcp_cwnd_restart at RTO 200 ms, IW 10: one halving per RTO, whole or
  // partial, of idle time beyond the first; floor min(IW, cwnd).
  const Row rows[] = {
      {40, 200ms, 40},  // not idle long enough
      {40, 201ms, 20},  {40, 400ms, 20}, {40, 401ms, 10}, {40, 500ms, 10},
      {50, 10s, 10},    // 50, 25, 12, 6: floor 10
      {8, 10s, 8},      // below IW: unchanged
      {11, 300ms, 10},  // 11 >> 1 = 5: floor 10
  };
  for (const Row& row : rows) {
    EventLog log;
    CcConn c = conn(row.cwnd, 6);
    c.ca_state = utcp::CaState::open;
    utcp::cwnd_restart(c, log, utcp::IdleRestart::linux, row.idle, 200ms, 10);
    EXPECT_EQ(c.cwnd, row.expect) << row.cwnd << " " << row.idle.count();
    if (row.idle > 200ms) {
      // tcp_current_ssthresh from the cwnd before the restart.
      EXPECT_EQ(c.ssthresh, std::max(6u, (row.cwnd >> 1) + (row.cwnd >> 2))) << row.cwnd;
      EXPECT_EQ(log.events.size(), 1u);
    } else {
      EXPECT_EQ(c.ssthresh, 6u);
    }
  }
  // A CC with cong_control (BBR) keeps its cwnd.
  EventLog bbr;
  bbr.own_cwnd = true;
  CcConn c = conn(40, 6);
  EXPECT_FALSE(utcp::cwnd_restart(c, bbr, utcp::IdleRestart::linux, 10s, 200ms, 10));
  EXPECT_EQ(c.cwnd, 40u);
  EXPECT_TRUE(bbr.events.empty());
}

TEST(CcNewreno, CwndClamp) {
  NewReno r;
  CcConn c = conn(10, 100);
  c.cwnd_clamp = 12;
  r.cong_avoid(c, delivered(10));
  EXPECT_EQ(c.cwnd, 12u);
}

TEST(CcNewreno, SsthreshIsHalfTheFlightSizeAtLeastTwo) {
  NewReno r;
  CcConn c = conn(40, 100);
  c.flavor = utcp::CcFlavor::rfc;
  const std::uint32_t flight[] = {20, 7, 3, 1, 0, 1001};
  const std::uint32_t expect[] = {10, 3, 2, 2, 2, 500};
  for (std::size_t i = 0; i < std::size(flight); ++i) {
    c.packets_out = flight[i];
    EXPECT_EQ(r.ssthresh(c), expect[i]) << flight[i];
  }
}

TEST(CcNewreno, StorageAndCurrentSsthresh) {
  utcp::CcStorage s;
  utcp::cc_select(s, utcp::CcAlgo::newreno);
  EXPECT_EQ(utcp::cc_of(s).name(), "newreno");
  EXPECT_FALSE(utcp::cc_of(s).has_cong_control());
  EXPECT_EQ(utcp::cc_of(s).sndbuf_expand(), 2u);
  EXPECT_EQ(utcp::cc_of(s).min_tso_segs(utcp::CcConn{}), 2u);
  utcp::cc_select(s, utcp::CcAlgo::cubic);
  EXPECT_EQ(utcp::cc_of(s).name(), "cubic");
  CcConn c = conn(40, 10);
  EXPECT_EQ(utcp::current_ssthresh(c), 30u);  // 3/4 cwnd
  c.ssthresh = 50;
  EXPECT_EQ(utcp::current_ssthresh(c), 50u);
  c.ssthresh = 10;
  c.ca_state = utcp::CaState::recovery;
  EXPECT_EQ(utcp::current_ssthresh(c), 10u);
}

}  // namespace
