#include "core/tcp/rtt.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

#include "utcp/config.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::ProfileId;
using utcp::RttEstimator;
using utcp::Time;
using utcp::tcp_config;

constexpr std::int64_t ms = 1'000'000;

Time at(Duration d) { return Time{0} + d; }

TEST(Rtt, Rfc6298FirstSampleAndHandComputedTable) {
  RttEstimator r(tcp_config(ProfileId::rfc));
  EXPECT_FALSE(r.has_sample());
  EXPECT_EQ(r.rto(), 1s);  // RFC 6298 §2.1
  // RFC 6298 §2.2: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4 RTTVAR.
  r.on_srtt_sample(800ms, 0, 0);
  EXPECT_TRUE(r.has_sample());
  EXPECT_EQ(r.srtt(), 800ms);
  EXPECT_EQ(r.rttvar(), 400ms);
  EXPECT_EQ(r.rto(), 2400ms);
  // §2.3 by hand: RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - R| (old SRTT), then
  // SRTT = 7/8 SRTT + 1/8 R, RTO = SRTT + 4 RTTVAR; integer nanoseconds.
  struct Row {
    std::int64_t r_ms, srtt_ns, rttvar_ns, rto_ns;
  };
  const Row rows[] = {
      {1200, 850'000'000, 400'000'000, 2'450'000'000},  // |800-1200| = 400
      {400, 793'750'000, 412'500'000, 2'443'750'000},   // (1200 + 450) / 4
      {800, 794'531'250, 310'937'500, 2'038'281'250},   // (1237.5 + 6.25) / 4
      {600, 770'214'843, 281'835'937, 1'897'558'591},   // (932.8125 + 194.53125) / 4
      {2000, 923'937'987, 518'823'242, 2'999'230'955},  // (845.5 + 1229.8) / 4
  };
  for (const Row& row : rows) {
    r.on_srtt_sample(Duration{row.r_ms * ms}, 0, 0);
    EXPECT_EQ(r.srtt().count(), row.srtt_ns) << row.r_ms;
    EXPECT_EQ(r.rttvar().count(), row.rttvar_ns) << row.r_ms;
    EXPECT_EQ(r.rto().count(), row.rto_ns) << row.r_ms;
  }
}

TEST(Rtt, Rfc6298RtoNeverBelowRtoMin) {
  RttEstimator r(tcp_config(ProfileId::rfc));
  r.on_srtt_sample(10ms, 0, 0);
  EXPECT_EQ(r.rto(), 1s);
  for (int i = 0; i < 50; ++i) {
    r.on_srtt_sample(1ms, 0, 0);
    EXPECT_EQ(r.rto(), 1s);
  }
  // A zero sample is valid; RTO stays at rto_min. Negative means none.
  r.on_srtt_sample(0ms, 0, 0);
  EXPECT_EQ(r.rto(), 1s);
  const Duration before = r.srtt();
  r.on_srtt_sample(Duration{-1}, 0, 0);
  EXPECT_EQ(r.srtt(), before);
}

TEST(Rtt, LinuxHandTrace) {
  // tcp_rtt_estimator, rto_min 200 ms. Columns: sample, SND.UNA and SND.NXT
  // offsets, then srtt, mdev (tcpi_rttvar), rttvar_us and the RTO.
  RttEstimator r(tcp_config(ProfileId::linux_compat));
  EXPECT_EQ(r.rto(), 1s);
  struct Row {
    std::int64_t m_ms;
    std::uint64_t una, nxt;
    std::int64_t srtt_ns, mdev_ns, rttvar_ns, rto_ns;
  };
  const Row rows[] = {
      // First sample: srtt = m, mdev = 2m (tcpi_rttvar m/2), rttvar = max(2m,
      // rto_min) = 200 ms, RTO = 300 ms; rtt_seq = 10000.
      {100, 1000, 10'000, 100'000'000, 50'000'000, 200'000'000, 300'000'000},
      // Same round, equal sample: mdev decays 200 -> 150 ms; rttvar stays.
      {100, 2000, 10'000, 100'000'000, 37'500'000, 200'000'000, 300'000'000},
      // Delay spike: error 400, mdev = 150 + (400 - 37.5) = 512.5 ms is a new
      // round maximum and raises rttvar at once.
      {500, 3000, 10'000, 150'000'000, 128'125'000, 512'500'000, 662'500'000},
      // Low samples. Below SRTT the mdev gain is cut by 8: (50 - 128.125) < 0
      // is added whole, mdev 434.375 ms. Round end (una 11000 > 10000):
      // mdev_max 512.5 = rttvar, no decay; mdev_max resets to rto_min.
      {100, 11'000, 20'000, 143'750'000, 108'593'750, 512'500'000, 656'250'000},
      // Round end: mdev_max = 369.53 (this sample's mdev) < rttvar, so rttvar
      // -= (512.5 - 369.53) / 4. max(mdev_max, rto_min) would give 369.53.
      {100, 21'000, 30'000, 138'281'250, 92'382'812, 476'757'813, 615'039'063},
      {100, 31'000, 40'000, 133'496'093, 78'857'422, 436'425'782, 569'921'875},
      {100, 41'000, 50'000, 129'309'082, 67'517'089, 394'836'427, 524'145'509},
  };
  for (const Row& row : rows) {
    r.on_srtt_sample(Duration{row.m_ms * ms}, row.una, row.nxt);
    EXPECT_EQ(r.srtt().count(), row.srtt_ns) << row.una;
    EXPECT_EQ(r.rttvar().count(), row.mdev_ns) << row.una;
    EXPECT_EQ(r.rto().count(), row.rto_ns) << row.una;
    EXPECT_EQ((r.rto() - r.srtt()).count(), row.rttvar_ns) << row.una;
  }
}

TEST(Rtt, LinuxRttvarNeverBelowRtoMin) {
  RttEstimator r(tcp_config(ProfileId::linux_compat));
  std::uint64_t una = 0;
  for (int i = 0; i < 200; ++i) {
    una += 1000;
    r.on_srtt_sample(1ms, una, una + 500);
    EXPECT_GE(r.rto() - r.srtt(), 200ms);
    EXPECT_GE(r.rto(), 200ms);
  }
  EXPECT_EQ(r.srtt(), 1ms);
}

TEST(Rtt, RtoMaxBoundsTheEstimate) {
  for (const auto p : {ProfileId::rfc, ProfileId::linux_compat}) {
    RttEstimator r(tcp_config(p));
    r.on_srtt_sample(100s, 1, 2);
    EXPECT_EQ(r.rto(), tcp_config(p).rto_max);
  }
}

TEST(Rtt, RtoBackedOffCapsAtRtoMax) {
  RttEstimator r(tcp_config(ProfileId::rfc));  // rto 1 s, rto_max 60 s
  const std::int64_t expect_s[] = {1, 2, 4, 8, 16, 32, 60, 60};
  for (std::uint8_t b = 0; b < 8; ++b) {
    EXPECT_EQ(r.rto_backed_off(b), Duration{expect_s[b] * 1000 * ms}) << int{b};
  }
  EXPECT_EQ(r.rto_backed_off(63), 60s);
  EXPECT_EQ(r.rto_backed_off(255), 60s);
  RttEstimator l(tcp_config(ProfileId::linux_compat));
  l.on_srtt_sample(100ms, 1, 2);  // rto 300 ms
  EXPECT_EQ(l.rto_backed_off(3), 2400ms);
  EXPECT_EQ(l.rto_backed_off(9), 120s);  // 153.6 s capped
}

TEST(Rtt, ResetAfterSynRetransmission) {
  RttEstimator r(tcp_config(ProfileId::linux_compat));
  r.reset_after_syn_rexmit();
  EXPECT_EQ(r.rto(), 3s);  // RFC 6298 §5.7
  RttEstimator s(tcp_config(ProfileId::linux_compat));
  s.on_srtt_sample(100ms, 1, 2);
  s.reset_after_syn_rexmit();
  EXPECT_EQ(s.rto(), 300ms);  // a sample exists: unchanged
}

TEST(Rtt, MinRttSkipsMaybeDelayedSamplesAboveTheMinimum) {
  RttEstimator r(tcp_config(ProfileId::linux_compat));
  EXPECT_EQ(r.min_rtt(), Duration::max());
  r.on_min_rtt_sample(10ms, true, at(0s));  // the first sample is always taken
  EXPECT_EQ(r.min_rtt(), 10ms);
  r.on_min_rtt_sample(20ms, true, at(1s));
  EXPECT_EQ(r.min_rtt(), 10ms);
  r.on_min_rtt_sample(5ms, true, at(2s));  // below the minimum: taken
  EXPECT_EQ(r.min_rtt(), 5ms);
  r.on_min_rtt_sample(Duration{-1}, false, at(3s));
  EXPECT_EQ(r.min_rtt(), 5ms);
  // A skipped delayed sample does not become a later choice: when the 10 ms
  // minimum expires the filter holds 40 ms; had the delayed 15 ms sample at
  // 100 s been kept as second choice, it would hold 15 ms.
  RttEstimator d(tcp_config(ProfileId::linux_compat));
  d.on_min_rtt_sample(10ms, false, at(0s));
  d.on_min_rtt_sample(15ms, true, at(100s));
  d.on_min_rtt_sample(40ms, false, at(299s));
  d.on_min_rtt_sample(40ms, false, at(301s));
  EXPECT_EQ(d.min_rtt(), 40ms);
}

TEST(Rtt, MinRttWindowIs300Seconds) {
  RttEstimator r(tcp_config(ProfileId::linux_compat));
  r.on_min_rtt_sample(10ms, false, at(0s));
  r.on_min_rtt_sample(50ms, false, at(100s));
  r.on_min_rtt_sample(50ms, false, at(200s));
  r.on_min_rtt_sample(50ms, false, at(299s));
  EXPECT_EQ(r.min_rtt(), 10ms);
  r.on_min_rtt_sample(50ms, false, at(300s));  // dt = 300 s is still inside
  EXPECT_EQ(r.min_rtt(), 10ms);
  r.on_min_rtt_sample(50ms, false, at(300s + 1ns));
  EXPECT_EQ(r.min_rtt(), 50ms);
  // Second and third choices: a 20 ms sample at 100 s survives the expiry of
  // the 10 ms one.
  RttEstimator s(tcp_config(ProfileId::linux_compat));
  s.on_min_rtt_sample(10ms, false, at(0s));
  s.on_min_rtt_sample(20ms, false, at(100s));
  s.on_min_rtt_sample(40ms, false, at(250s));
  s.on_min_rtt_sample(60ms, false, at(310s));
  EXPECT_EQ(s.min_rtt(), 20ms);
  // Nothing in the window: reset to the new sample.
  s.on_min_rtt_sample(90ms, false, at(1000s));
  EXPECT_EQ(s.min_rtt(), 90ms);
}

}  // namespace
