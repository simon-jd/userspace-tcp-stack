#include "core/tcp/cc_newreno.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <iterator>

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
  EXPECT_EQ(utcp::cc_of(s).min_tso_segs(), 2u);
  EXPECT_DEATH(utcp::cc_select(s, utcp::CcAlgo::cubic), "");
  CcConn c = conn(40, 10);
  EXPECT_EQ(utcp::current_ssthresh(c), 30u);  // 3/4 cwnd
  c.ssthresh = 50;
  EXPECT_EQ(utcp::current_ssthresh(c), 50u);
  c.ssthresh = 10;
  c.ca_state = utcp::CaState::recovery;
  EXPECT_EQ(utcp::current_ssthresh(c), 10u);
}

}  // namespace
