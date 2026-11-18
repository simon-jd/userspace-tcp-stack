#include "core/tcp/cc_newreno.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <limits>

namespace utcp {
// Read-only observations of the integer model, in addition to its public
// window effects. No mutation bypasses the normal CC hooks.
struct CubicTestView {
  static auto k(const Cubic& a) { return a.k_; }
  static auto origin(const Cubic& a) { return a.origin_; }
  static auto prior(const Cubic& a) { return a.prior_; }
  static auto last_max(const Cubic& a) { return a.last_max_; }
  static auto epoch(const Cubic& a) { return a.epoch_; }
  static auto last_time(const Cubic& a) { return a.last_time_; }
  static auto cnt(const Cubic& a) { return a.cnt_; }
  static auto tcp_cwnd(const Cubic& a) { return a.tcp_cwnd_; }
  static auto delay(const Cubic& a) { return a.delay_min_us_; }
  static auto estimate(const Cubic& a) { return a.estimate_; }
  static auto fraction(const Cubic& a) { return a.fraction_; }
};
}  // namespace utcp

namespace {
using namespace std::chrono_literals;
using namespace utcp;
using View = CubicTestView;
constexpr std::uint64_t one = std::uint64_t{1} << 32;

struct Flow {
  explicit Flow(CcFlavor flavor) {
    c.flavor = flavor;
    c.cwnd = c.packets_out = 100;
    c.ssthresh = 100;
    c.cwnd_limited = true;
    c.now = Time{1'000'000'000};
    a.init(c);
  }
  void ack(std::uint32_t n = 1) {
    AckOutcome o;
    o.delivered = n;
    a.cong_avoid(c, o);
  }
  void reduce() { c.cwnd = c.ssthresh = a.ssthresh(c); }
  void sample(Duration rtt) { a.pkts_acked(c, AckSample{1, rtt, 0}); }
  Cubic a;
  CcConn c;
};

TEST(CcCubic, KernelGoldenRootsAndConstants) {
  EXPECT_EQ(cubic_beta_scale, 15u);
  EXPECT_EQ(cube_rtt_scale, 410u);
  EXPECT_EQ(cube_factor, 2681735677u);
  // Literal outputs of tools/golden/cubic_root_gen.c compiled independently
  // against the v7.0 function. Direct-table and normalized lookup paths.
  constexpr unsigned small[] = {
      0, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
      3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
      3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4,
      4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  };
  constexpr unsigned normalized[] = {
      16, 16, 17, 17, 18, 18, 19, 19,
      20, 20, 20, 21, 21, 22, 22, 22,
      23, 23, 23, 24, 24, 24, 24, 25,
      25, 25, 25, 26, 26, 26, 26, 27,
      27, 27, 27, 28, 28, 28, 28, 28,
      29, 29, 29, 29, 29, 30, 30, 30,
      30, 30, 30, 31, 31, 31, 31, 31,
  };
  for (unsigned i = 0; i < 64; ++i) EXPECT_EQ(cubic_root(i), small[i]) << i;
  for (unsigned i = 8; i < 64; ++i)
    EXPECT_EQ(cubic_root(std::uint64_t{i} << 9), normalized[i - 8]) << i;
  // Below, at and above every remaining bit-width transition.
  constexpr unsigned boundary[][3] = {
      {4, 4, 4}, {5, 5, 5}, {6, 6, 6}, {8, 8, 8},
      {10, 10, 10}, {12, 12, 12}, {16, 16, 16}, {20, 20, 20},
      {25, 25, 25}, {32, 32, 32}, {40, 40, 40}, {50, 50, 50},
      {64, 64, 64}, {80, 80, 80}, {101, 101, 101}, {128, 128, 128},
      {161, 161, 161}, {203, 203, 203}, {256, 256, 256}, {322, 322, 322},
      {406, 406, 406}, {512, 512, 512}, {645, 645, 645}, {812, 812, 812},
      {1023, 1024, 1024}, {1290, 1290, 1290}, {1625, 1625, 1625}, {2047, 2048, 2048},
      {2580, 2581, 2581}, {3250, 3251, 3251}, {4095, 4097, 4097}, {5159, 5161, 5161},
      {6500, 6502, 6502}, {8191, 8195, 8195}, {10319, 10323, 10323}, {13001, 13005, 13005},
      {16383, 16391, 16391}, {20639, 20647, 20647}, {26003, 26010, 26010}, {32766, 32783, 32783},
      {41278, 41294, 41294}, {52006, 52021, 52021}, {65533, 65566, 65566}, {82557, 82588, 82588},
      {104012, 104042, 104042}, {131066, 131134, 131134}, {165115, 165178, 165178}, {208024, 208084, 208084},
      {262133, 262267, 262267}, {330231, 330356, 330356}, {416048, 416168, 416168}, {524267, 524535, 524535},
      {660462, 660711, 660711}, {832097, 832337, 832337}, {1048534, 1049071, 1049071}, {1320925, 1321423, 1321423},
      {1664195, 1664674, 1664674}, {2097068, 2098142, 2098142},
  };
  for (unsigned b = 6; b < 64; ++b) {
    const auto n = std::uint64_t{1} << b;
    for (unsigned j = 0; j < 3; ++j)
      EXPECT_EQ(cubic_root(n - 1 + j), boundary[b - 6][j]) << b << " " << j;
  }
  EXPECT_EQ(cubic_root(std::numeric_limits<std::uint64_t>::max()), 2641850u);
  EXPECT_EQ(cubic_root(30 * cube_factor), 4316u);
}

TEST(CcCubic, LinuxMillisecondAckSequenceAndFastConvergence) {
  Flow f(CcFlavor::linux);
  f.sample(20ms);
  f.reduce();
  EXPECT_EQ(f.c.ssthresh, 70u);
  EXPECT_EQ(View::last_max(f.a), 100u);
  // One ACK per ms. At t=0 the 20 ms lookahead gives target 71, cnt 70.
  // Recurrence: truncate the cubic delta; spend Reno credits only above
  // floor(cwnd*15/8); use the resulting cnt for this ACK.
  struct Row { unsigned ms, cnt, estimate, cwnd, carry; };
  constexpr Row rows[] = {{0,70,70,70,1}, {1000,86,76,86,59}, {2000,9600,82,96,108},
                          {4200,10000,94,100,1344}, {6000,10300,103,103,165}};
  unsigned ms = 0;
  for (auto r : rows) {
    while (ms <= r.ms) {
      f.c.now = Time{(1000 + std::int64_t{ms}) * 1'000'000};
      f.ack();
      ++ms;
    }
    EXPECT_EQ(View::k(f.a), 4316u);
    EXPECT_EQ(View::cnt(f.a), r.cnt) << r.ms;
    EXPECT_EQ(View::tcp_cwnd(f.a), r.estimate) << r.ms;
    EXPECT_EQ(f.c.cwnd, r.cwnd) << r.ms;
    EXPECT_EQ(f.c.cwnd_cnt, r.carry) << r.ms;
  }
  f.c.cwnd = 90;
  EXPECT_EQ(f.a.ssthresh(f.c), 63u);
  EXPECT_EQ(View::last_max(f.a), 76u);
}

TEST(CcCubic, LinuxJiffyGatesAndWrap) {
  Flow f(CcFlavor::linux);
  f.c.now = Time{(std::int64_t{1} << 32) * 1'000'000 - 31'000'000};
  f.ack();
  const auto first = jiffies(f.c.now);
  EXPECT_EQ(View::cnt(f.a), 20u);  // no recorded maximum
  f.c.now += 31ms;  // wraps to zero
  f.ack();
  EXPECT_EQ(View::last_time(f.a), first);
  f.c.now += 1ms;
  f.ack();
  EXPECT_EQ(View::last_time(f.a), 1u);
  // A changed cwnd in the same jiffy may run friendliness but must retain
  // the curve from the earlier update (no initial-epoch cap after a loss).
  Flow g(CcFlavor::linux);
  g.reduce();
  g.ack();
  const auto saved = View::cnt(g.a);
  g.c.cwnd = 100;
  g.ack();
  EXPECT_EQ(View::cnt(g.a), saved);
  g.c.now += 1ms;
  g.ack();
  EXPECT_EQ(View::cnt(g.a), 10000u);
}

TEST(CcCubic, LinuxIdleLossAndDelayFilter) {
  Flow f(CcFlavor::linux);
  f.sample(-1ns);
  EXPECT_EQ(View::delay(f.a), 0u);
  f.sample(20ms);
  f.reduce();
  f.ack();
  f.c.now += 999ms;
  f.sample(1ms);
  EXPECT_EQ(View::delay(f.a), 20000u);
  f.c.now += 1ms;
  f.sample(1ms);
  EXPECT_EQ(View::delay(f.a), 1000u);
  f.c.lsndtime = f.c.now;
  f.c.now += 500ms;
  f.a.cwnd_event(f.c, CaEvent::tx_start);
  EXPECT_EQ(View::epoch(f.a), 1500u);
  f.a.set_state(f.c, CaState::loss);
  EXPECT_FALSE(View::epoch(f.a));
  EXPECT_EQ(View::last_max(f.a), 0u);
  EXPECT_EQ(View::delay(f.a), 0u);
  f.sample(0ns);
  EXPECT_EQ(View::delay(f.a), 1u);
}

TEST(CcCubic, RfcFlightSizeAndNoLinuxInitialCap) {
  Flow f(CcFlavor::rfc);
  f.c.packets_out = 20;
  EXPECT_EQ(f.a.ssthresh(f.c), 14u);
  f.c.packets_out = 1;
  EXPECT_EQ(f.a.ssthresh(f.c), 2u);
  Flow start(CcFlavor::rfc);
  for (int i = 0; i < 20; ++i) start.ack();
  EXPECT_EQ(start.c.cwnd, 100u);
}

TEST(CcCubic, RfcSmoothedRttAndTargetClamp) {
  Flow low(CcFlavor::rfc), high(CcFlavor::rfc);
  for (auto* f : {&low, &high}) {
    f->sample(1ms);
    f->ack();
    f->c.now += 1s;
  }
  low.c.srtt = 1ms;
  high.c.srtt = 20s;  // both flows have the same observed minimum
  low.ack();
  high.ack();
  EXPECT_LT(View::fraction(low.a), one / 25);
  EXPECT_EQ(View::fraction(high.a), one / 100 + one / 2);
  high.ack();
  EXPECT_EQ(high.c.cwnd, 101u);
  // Current cwnd above both W_est and target: the curve earns no credit.
  low.c.cwnd = 200;
  const auto before = View::fraction(low.a);
  low.ack();
  EXPECT_EQ(View::fraction(low.a), before);
}

TEST(CcCubic, RfcRenoAlphaChangesAtPriorWindow) {
  Flow f(CcFlavor::rfc);
  f.c.cwnd = f.c.packets_out = 10;
  f.reduce();
  f.c.cwnd = 9;
  f.ack(18);
  constexpr auto alpha = one * 3 * (1024 - 717) / (1024 + 717);
  EXPECT_EQ(View::estimate(f.a), 9 * one + alpha * 2);
  ASSERT_EQ(f.c.cwnd, 10u);
  const auto before = View::estimate(f.a);
  f.ack(10);
  EXPECT_EQ(View::estimate(f.a), before + one);
}

TEST(CcCubic, RfcApplicationLimitedTimeExcludedOnce) {
  Flow f(CcFlavor::rfc);
  f.ack();
  f.c.now += 50ms;
  f.c.cwnd_limited = false;
  f.ack();
  f.c.now += 200ms;
  f.ack();
  f.c.lsndtime = f.c.now;
  f.c.now += 300ms;
  f.a.cwnd_event(f.c, CaEvent::tx_start);
  f.c.now += 100ms;
  f.c.cwnd_limited = true;
  f.ack();
  EXPECT_EQ(View::epoch(f.a), 1600u);
  EXPECT_EQ(jiffies(f.c.now) - *View::epoch(f.a), 50u);
}

TEST(CcCubic, RfcTimeoutRestartsAtZeroK) {
  Flow f(CcFlavor::rfc);
  f.reduce();
  f.ack();
  ASSERT_EQ(View::k(f.a), 4316u);
  f.a.set_state(f.c, CaState::loss);
  f.c.cwnd = f.c.ssthresh = 40;
  f.ack();
  EXPECT_EQ(View::k(f.a), 0u);
  EXPECT_EQ(View::origin(f.a), 40u);
  EXPECT_EQ(View::estimate(f.a) >> 32, 40u);
}

TEST(CcCubic, RfcLossFreeSlowStartExitSetsPriorAndZeroK) {
  Flow f(CcFlavor::rfc);
  f.c.hystart = Hystart::hystart_pp;
  f.c.ssthresh = cwnd_infinite;
  f.c.snd_nxt = 100;
  for (int i = 0; i < 8; ++i) f.sample(20ms);
  f.ack();
  for (int round = 0; round <= 5; ++round) {
    f.c.snd_una = f.c.snd_nxt;
    f.c.snd_nxt += 100;
    for (int i = 0; i < 8; ++i) f.sample(24ms);
  }
  ASSERT_EQ(f.c.ssthresh, 101u);
  f.ack();
  EXPECT_EQ(View::prior(f.a), 101u);
  EXPECT_EQ(View::origin(f.a), 101u);
  EXPECT_EQ(View::k(f.a), 0u);
  EXPECT_EQ(View::estimate(f.a), 101 * one + one / 101);
}
}  // namespace
