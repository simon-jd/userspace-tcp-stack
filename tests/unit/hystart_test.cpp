#include <gtest/gtest.h>

#include "core/tcp/cc_cubic.hpp"
#include "tcp_test_util.hpp"

namespace {
using namespace utcp;
using namespace std::chrono_literals;

struct Flow {
  explicit Flow(Hystart mode) {
    c.hystart = mode;
    c.flavor = mode == Hystart::hystart_classic ? CcFlavor::rfc : CcFlavor::linux;
    c.cwnd = 16;
    c.ssthresh = cwnd_infinite;
    c.cwnd_limited = true;
    c.stats = &stats;
    c.snd_nxt = 100;
    a.init(c);
  }
  void sample(Duration rtt, Duration gap = 3ms) {
    c.now += gap;
    a.pkts_acked(c, {1, rtt, 0});
  }
  void grow(std::uint32_t n) {
    AckOutcome out;
    out.delivered = n;
    a.cong_avoid(c, out);
  }
  void next_round() {
    c.snd_una = c.snd_nxt;
    c.snd_nxt += 100;
  }
  void samples(Duration rtt, int n) {
    for (int i = 0; i < n; ++i) sample(rtt);
  }
  Cubic a;
  CcConn c;
  StackStats stats;
};

TEST(Hystart, ClassicDelayRequiresEightPriorSamplesAndStrictThreshold) {
  for (const Duration elevated : {Duration{24ms}, Duration{24ms + 1us}}) {
    Flow f(Hystart::hystart_classic);
    f.sample(20ms);
    f.next_round();
    ++f.c.snd_una;  // Linux uses after(), not >=.
    f.samples(elevated, 8);
    EXPECT_EQ(f.c.ssthresh, cwnd_infinite);
    f.sample(elevated);
    const bool exit = elevated > 24ms;
    EXPECT_EQ(f.c.ssthresh, exit ? 16u : cwnd_infinite);
    f.sample(elevated);
    EXPECT_EQ(f.stats.TcpExtTCPHystartDelayDetect, exit ? 1u : 0u);
    EXPECT_EQ(f.stats.TcpExtTCPHystartDelayCwnd, exit ? 16u : 0u);
    EXPECT_EQ(f.stats.TcpExtTCPHystartTrainDetect, 0u);
  }
}

TEST(Hystart, ClassicTrainUsesPacingCushionLowWindowAndConfiguredGap) {
  for (const bool paced : {false, true}) {
    Flow f(Hystart::hystart_classic);
    f.c.paced = paced;
    f.c.gso_max_size = 65536;
    f.c.pacing_rate = 1'000'000;  // cushion saturates at 1 ms
    const int boundary = paced ? 21 : 10;
    for (int i = 0; i < boundary; ++i) f.sample(20ms, 1ms);
    EXPECT_EQ(f.c.ssthresh, cwnd_infinite);
    f.sample(20ms, 1ms);
    EXPECT_EQ(f.c.ssthresh, 16u);
    EXPECT_EQ(f.stats.TcpExtTCPHystartTrainDetect, 1u);
    EXPECT_EQ(f.stats.TcpExtTCPHystartTrainCwnd, 16u);
    EXPECT_EQ(f.stats.TcpExtTCPHystartDelayDetect, 0u);
  }
  Flow small(Hystart::hystart_classic);
  small.c.cwnd = 15;
  for (int i = 0; i < 30; ++i) small.sample(20ms, 1ms);
  EXPECT_EQ(small.c.ssthresh, cwnd_infinite);
  Flow tuned(Hystart::hystart_classic);
  tuned.c.hystart_low_window = 17;
  tuned.c.hystart_ack_delta = 500us;
  for (int i = 0; i < 23; ++i) tuned.sample(20ms, 500us);
  EXPECT_EQ(tuned.c.ssthresh, cwnd_infinite);  // cwnd 16, threshold 17
  tuned.c.cwnd = 17;
  tuned.next_round();
  ++tuned.c.snd_una;
  for (int i = 0; i < 40; ++i) tuned.sample(20ms, 1ms);
  EXPECT_EQ(tuned.c.ssthresh, cwnd_infinite);
  tuned.next_round();
  ++tuned.c.snd_una;
  for (int i = 0; i < 23; ++i) tuned.sample(20ms, 500us);
  EXPECT_EQ(tuned.c.ssthresh, 17u);
}

TEST(Hystart, PlusPlusThresholdGrowthCarryAndFiveRoundExit) {
  for (const Duration base : {Duration{20ms}, Duration{200ms}}) {
    const Duration threshold = base == 20ms ? 4ms : 16ms;
    for (const bool paced : {false, true}) {
      Flow f(Hystart::hystart_pp);
      f.c.paced = paced;
      f.samples(base, 8);
      f.next_round();
      f.samples(base + threshold, 7);
      f.sample(base + threshold);
      f.grow(12); // entering ACK still receives slow-start growth
      EXPECT_EQ(f.c.cwnd, paced ? 28u : 24u);
      auto before = f.c.cwnd;
      f.sample(base + threshold);
      f.grow(12);
      EXPECT_EQ(f.c.cwnd - before, paced ? 3u : 2u);
      before = f.c.cwnd;
      for (int i = 0; i < 4; ++i) {
        f.sample(base + threshold);
        f.grow(1);
        EXPECT_EQ(f.c.cwnd - before, i == 3 ? 1u : 0u);
      }
      for (int round = 1; round < 5; ++round) {
        f.next_round();
        f.samples(base + threshold, 8);
        EXPECT_EQ(f.c.ssthresh, cwnd_infinite);
      }
      f.next_round();
      f.sample(base + threshold);
      EXPECT_EQ(f.c.ssthresh, f.c.cwnd);
    }
  }
}

TEST(Hystart, PlusPlusUsesOneEighthBetweenTheClamps) {
  for (const Duration rtt : {Duration{89500us}, Duration{90ms}}) {
    Flow f(Hystart::hystart_pp);
    f.samples(80ms, 8);
    f.next_round();
    f.samples(rtt, 9);
    f.grow(8);
    EXPECT_EQ(f.c.cwnd, rtt < 90ms ? 24u : 18u);
  }
}

TEST(Hystart, PlusPlusCompletesDrainedRoundsOnce) {
  for (bool one_ack_per_flight : {false, true}) {
    SCOPED_TRACE(one_ack_per_flight);
    Flow f(Hystart::hystart_pp);
    f.samples(20ms, 8);
    f.next_round();
    f.samples(24ms, 8);
    for (int round = 1; round <= 5; ++round) {
      f.c.snd_una = f.c.snd_nxt;
      f.sample(24ms);
      const auto expected = round == 5 ? f.c.cwnd : cwnd_infinite;
      EXPECT_EQ(f.c.ssthresh, expected) << round;
      f.sample(-1ns);  // a duplicate of the draining ACK
      EXPECT_EQ(f.c.ssthresh, expected) << round;
      f.c.snd_nxt += 100;
      if (!one_ack_per_flight) {
        f.c.snd_una += 25;
        f.sample(24ms);
        EXPECT_EQ(f.c.ssthresh, expected) << round;
      }
    }
    f.c.snd_una = f.c.snd_nxt;
    f.sample(24ms);  // the write after CSS exit
    EXPECT_EQ(f.c.ssthresh, f.c.cwnd);
  }
}

TEST(Hystart, PlusPlusBelowThresholdRollbackAndLoss) {
  Flow f(Hystart::hystart_pp);
  f.samples(20ms, 8);
  f.next_round();
  f.samples(24ms - 1ns, 10);
  f.grow(8);
  EXPECT_EQ(f.c.cwnd, 24u);
  f.next_round();
  f.samples(30ms, 9);
  f.grow(8);
  EXPECT_EQ(f.c.cwnd, 26u);
  f.next_round();
  f.samples(22ms, 7);
  f.grow(8);
  EXPECT_EQ(f.c.cwnd, 28u);
  f.sample(22ms);
  f.grow(8); // last CSS ACK
  f.sample(22ms);
  f.grow(8);
  EXPECT_EQ(f.c.cwnd, 38u);
  f.c.flavor = CcFlavor::rfc;
  f.c.packets_out = 20;
  f.c.ssthresh = f.a.ssthresh(f.c);
  EXPECT_EQ(f.c.ssthresh, 14u);
  f.a.set_state(f.c, CaState::loss);
  f.c.cwnd = 1;
  f.sample(20ms);
  f.grow(8);
  EXPECT_EQ(f.c.cwnd, 2u);
}

TEST(Hystart, PublicCcOptionsAndListenerInheritance) {
  using namespace utcp::test;
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    for (const auto algorithm : {CcAlgo::cubic, CcAlgo::bbr}) {
      for (const bool explicit_cc : {false, true}) {
        auto a = tcpt::config(Side::a, profile);
        auto b = tcpt::config(Side::b, profile);
        if (!explicit_cc) a.tcp.cc = b.tcp.cc = algorithm;
        TcpHarness h(a,b);
        TcpSocketOptions opts;
        if (explicit_cc) opts.cc = algorithm;
        const auto p = tcpt::open(h, 100ms, opts);
        ASSERT_TRUE(p);
        for (const auto& info : {h.a().tcp_info(p->client), h.b().tcp_info(p->server)}) {
          ASSERT_TRUE(info);
          EXPECT_EQ(info->cc_name_view(), to_string(algorithm));
        }
        opts.cc = algorithm;
        EXPECT_TRUE(h.a().tcp_set_options(p->client, opts));
        opts.cc = CcAlgo::newreno;
        EXPECT_EQ(h.a().tcp_set_options(p->client, opts).error(), Error::invalid_argument);
      }
    }
  }
  {
    constexpr auto bad = static_cast<CcAlgo>(255);
    for (const bool explicit_cc : {false, true}) {
      auto a = tcpt::config(Side::a);
      if (!explicit_cc) a.tcp.cc = bad;
      TcpHarness h(a, tcpt::config(Side::b));
      TcpSocketOptions opts;
      if (explicit_cc) opts.cc = bad;
      EXPECT_EQ(h.a().tcp_listen({{}, tcpt::port}, 1, opts).error(), Error::invalid_argument);
      EXPECT_EQ(h.a().tcp_connect({h.addr(Side::b), tcpt::port}, opts).error(),
                Error::invalid_argument);
    }
  }
}
}  // namespace
