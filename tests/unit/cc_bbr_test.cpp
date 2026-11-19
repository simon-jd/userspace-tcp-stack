#include <gtest/gtest.h>

#include <chrono>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/cc_newreno.hpp"
#include "core/tcp/send_queue.hpp"

namespace utcp {
namespace {
using namespace std::chrono_literals;

TEST(CcBbr, InitializesPacingFromThePacketWindowAndSrtt) {
  Bbr bbr;
  CcConn c;
  c.cwnd = 10;
  c.ssthresh = 12;
  c.mss = 1448;
  c.srtt = 20ms;
  c.min_rtt = 20ms;
  bbr.init(c);
  EXPECT_TRUE(bbr.has_cong_control());
  EXPECT_TRUE(c.pacing_needed);
  EXPECT_EQ(c.pacing_rate, 2'068'934u);
  EXPECT_EQ(c.ssthresh, cwnd_infinite);
  EXPECT_EQ(bbr.sndbuf_expand(), 3u);
}

// Each step is one ACK. The sampled delivery interval can span many ACKs.
class CcBbrModel : public ::testing::Test {
 protected:
  Bbr b;
  CcConn c;
  Rng rng = Rng::from_state({1, 1ULL << 24, 3, 4});
  RateSample rs;
  void SetUp() override {
    c.rng = &rng;
    c.cwnd = 10;
    c.mss = 1448;
    c.srtt = 20ms;
    c.min_rtt = 20ms;
    c.delivered = (1ULL << 32) + 100;
    b.init(c);
    rs.valid = true;
    rs.delivered = 10;
    rs.interval = 20ms;
    rs.rtt = 20ms;
    rs.acked_sacked = 1;
  }
  void ack(Duration elapsed = 20ms, bool new_round = true) {
    if (new_round) {
      rs.prior_delivered = c.delivered;
    }
    c.delivered += rs.acked_sacked;
    c.lost += rs.losses;
    c.now += elapsed;
    c.delivered_time = c.now;
    b.cong_control(c, {}, rs);
  }
  void probe_bw() {
    for (int i = 0; i < 4; ++i) {
      ack();
    }
    ASSERT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  }
};

TEST_F(CcBbrModel, FullPipeCountsOnlyNonAppLimitedNewRoundsWithLessThanQuarterGrowth) {
  ack();
  EXPECT_EQ(b.info().bandwidth_q24, 8388u);
  EXPECT_EQ(b.info().pacing_gain_q8, 739u);
  EXPECT_EQ(b.info().cwnd_gain_q8, 739u);
  for (int i = 0; i < 4; ++i) {
    ack(20ms, false);
  }
  rs.is_app_limited = true;
  for (int i = 0; i < 12; ++i) {
    rs.delivered = 1;
    ack();
  }
  EXPECT_EQ(b.info().bandwidth_q24, 8388u);
  rs.is_app_limited = false;
  rs.delivered = 10;
  ack();
  ack();
  rs.delivered = 13;
  ack();  // a 30% increase restarts plateau detection
  ack();
  ack();
  EXPECT_EQ(b.info().mode, Bbr::Mode::startup);
  c.in_flight = 100;
  ack();
  EXPECT_EQ(b.info().mode, Bbr::Mode::drain);
  EXPECT_EQ(b.info().pacing_gain_q8, 88u);
  EXPECT_EQ(c.ssthresh, 20u);  // ceil(12.999) + 3*2 rounded to even
  c.in_flight = 21;
  ack();
  EXPECT_EQ(b.info().mode, Bbr::Mode::drain);
  c.wstamp = c.now + 24ms;  // 4 ms beyond next ACK delivers two packets by EDT
  ack();
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  EXPECT_EQ(b.info().cwnd_gain_q8, 512u);
}

TEST_F(CcBbrModel, InvalidRateStillUpdatesRttAndAppliesCwndCaps) {
  rs.valid = false;
  rs.rtt = 11ms;
  c.cwnd_clamp = 6;
  ack();
  EXPECT_EQ(b.info().min_rtt_us, 11000u);
  EXPECT_EQ(b.info().bandwidth_q24, 0u);
  EXPECT_EQ(c.cwnd, 6u);
  rs.valid = true;
  rs.interval = 999ns;
  ack();
  EXPECT_EQ(b.info().bandwidth_q24, 0u);
  rs.interval = 20000999ns;
  ack();
  EXPECT_EQ(b.info().bandwidth_q24, 8388u);
}

TEST_F(CcBbrModel, EightGainPhasesHonorElapsedTimeLossAndDrain) {
  probe_bw();  // Fixed first xoshiro output maps to zero below seven.
  EXPECT_EQ(b.info().pacing_gain_q8, 320u);
  rs.prior_in_flight = 0;
  ack(20ms);
  ack(1us);  // time alone cannot finish the high phase
  EXPECT_EQ(b.info().pacing_gain_q8, 320u);
  rs.losses = 1;
  ack(1us);
  EXPECT_EQ(b.info().pacing_gain_q8, 192u);
  rs.losses = 0;
  rs.prior_in_flight = 16;
  ack(1us);  // low phase can finish early at or below its inflight target
  for (int i = 0; i < 6; ++i) {
    EXPECT_EQ(b.info().pacing_gain_q8, 256u);
    ack(20001us);
  }
  EXPECT_EQ(b.info().pacing_gain_q8, 320u);
  rs.prior_in_flight = 100;
  ack(20001us);
  EXPECT_EQ(b.info().pacing_gain_q8, 192u);
  ack(20ms);
  EXPECT_EQ(b.info().pacing_gain_q8, 192u);
  ack(1us);
  EXPECT_EQ(b.info().pacing_gain_q8, 256u);
}

TEST_F(CcBbrModel, ProbeRttRequiresExpiryLowFlightOneRoundAndStrictlyAfter200ms) {
  probe_bw();
  c.cwnd = 22;
  c.in_flight = 5;
  rs.rtt = 30ms;
  rs.is_ack_delayed = true;
  ack(9920ms);  // exactly 10 s since initial RTprop
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  ack(1ms);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  EXPECT_EQ(b.info().min_rtt_us, 20000u);
  EXPECT_EQ(c.cwnd, 4u);
  EXPECT_EQ(c.app_limited, c.delivered + 5);
  ack(250ms);
  c.in_flight = 4;
  ack();
  ack(200ms, false);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  ack(1ms, false);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  ack(0ms);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  EXPECT_GE(c.cwnd, 22u);
}

TEST_F(CcBbrModel, IdleProbeRestartRestoresCwndWithoutAnAck) {
  c.in_flight = 4;
  c.cwnd = 22;
  ack(10001ms);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  rs.acked_sacked = 0;
  c.now += 200ms;
  b.cwnd_event(c, CaEvent::tx_start);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  c.now += 1ms;
  b.cwnd_event(c, CaEvent::tx_start);
  EXPECT_EQ(b.info().mode, Bbr::Mode::startup);
  EXPECT_EQ(c.cwnd, 22u);
}

TEST_F(CcBbrModel, RecoveryConservesOneRoundAndLossGrowsBeforeRestore) {
  probe_bw();
  c.cwnd = 22;
  const auto saved_thresh = c.ssthresh;
  EXPECT_EQ(b.ssthresh(c), saved_thresh);
  c.ca_state = CaState::recovery;
  c.in_flight = 5;
  rs.acked_sacked = 2;
  ack();
  EXPECT_EQ(c.cwnd, 7u);
  c.in_flight = 7;
  ack(1ms, false);
  EXPECT_EQ(c.cwnd, 9u);
  ack();
  EXPECT_EQ(c.cwnd, 11u);
  c.ca_state = CaState::open;
  ack();
  EXPECT_GE(c.cwnd, 22u);
  c.cwnd = 22;
  EXPECT_EQ(b.ssthresh(c), saved_thresh);
  b.set_state(c, CaState::loss);
  c.ca_state = CaState::loss;
  c.in_flight = 1;
  c.cwnd = c.in_flight + 1;  // tcp_enter_loss sets this before ACKs arrive
  ack();
  EXPECT_EQ(c.cwnd, 4u);
  ack();
  EXPECT_EQ(c.cwnd, 6u);
  c.ca_state = CaState::open;
  ack();
  EXPECT_GE(c.cwnd, 22u);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  EXPECT_EQ(b.undo_cwnd(c), c.cwnd);
}

TEST_F(CcBbrModel, PacingAndBurstBoundaries) {
  c.pacing_rate = 149999;
  EXPECT_EQ(b.min_tso_segs(c), 1u);
  ++c.pacing_rate;
  EXPECT_EQ(b.min_tso_segs(c), 2u);
  c.max_pacing_rate = 100000;
  c.srtt = 0ms;
  b.init(c);
  EXPECT_EQ(c.pacing_rate, 100000u);
  c.max_pacing_rate = 0;
  c.srtt = 20ms;
  ack();
  EXPECT_EQ(c.pacing_rate, 2068934u);
  probe_bw();
  c.app_limited = c.delivered + 1;
  b.cwnd_event(c, CaEvent::tx_start);
  EXPECT_EQ(c.pacing_rate, 716708u);
}

TEST_F(CcBbrModel, PolicerRequiresTwoLossyIntervalsAndExpiresAt48ProbeRounds) {
  probe_bw();
  rs.acked_sacked = 256;
  rs.delivered = 256;
  rs.losses = 50;
  for (int i = 0; i < 7; ++i) {
    ack();
    EXPECT_FALSE(b.info().lt_use_bw);
  }
  ack();
  EXPECT_TRUE(b.info().lt_use_bw);
  EXPECT_EQ(b.info().bandwidth_q24, 214748u);
  EXPECT_EQ(b.info().pacing_gain_q8, 256u);
  rs.losses = 0;
  for (int i = 0; i < 47; ++i) {
    ack();
  }
  EXPECT_TRUE(b.info().lt_use_bw);
  ack();
  EXPECT_FALSE(b.info().lt_use_bw);
}

TEST_F(CcBbrModel, InsufficientLossAndAppLimitedIntervalsBreakPolicerDetection) {
  probe_bw();
  rs.acked_sacked = 256;
  rs.losses = 49;
  for (int i = 0; i < 18; ++i) {
    ack();
  }
  EXPECT_FALSE(b.info().lt_use_bw);
  rs.is_app_limited = true;
  ack();
  rs.is_app_limited = false;
  rs.losses = 50;
  for (int i = 0; i < 4; ++i) {
    ack();
  }
  rs.is_app_limited = true;
  ack();
  rs.is_app_limited = false;
  for (int i = 0; i < 7; ++i) {
    ack();
  }
  EXPECT_FALSE(b.info().lt_use_bw);
  ack();
  EXPECT_TRUE(b.info().lt_use_bw);
}

TEST_F(CcBbrModel, AckBurstBudgetIsCappedAtOneHundredMillisecondsOfBandwidth) {
  probe_bw();
  c.cwnd = 150;
  rs.acked_sacked = 120;
  ack(0ms);
  // 20 BDP packets at gain 2, floor(8388*100000/2^24)=49 bonus,
  // 6 packets for the three TSO budgets, even rounding, 2 for high gain.
  EXPECT_EQ(c.cwnd, 78u);
  rs.acked_sacked = 1;
  ack(260ms);  // the previous 120 ACKs no longer exceed the expected count
  for (int i = 0; i < 10; ++i) {
    ack(21ms);
  }
  EXPECT_LE(c.cwnd, 30u);
}

TEST_F(CcBbrModel, PolicerRelativeConsistencyAllowsExactlyOneEighth) {
  for (const unsigned last_ack : {282u, 283u}) {
    SetUp();
    probe_bw();
    rs.losses = 70;
    rs.acked_sacked = 250;
    for (int i = 0; i < 4; ++i) {
      ack(16ms);
    }
    rs.acked_sacked = 281;
    for (int i = 0; i < 3; ++i) {
      ack(16ms);
    }
    rs.acked_sacked = last_ack;
    ack(16ms);
    // First interval 250/16ms. Second 1125 or 1126 /64ms.
    EXPECT_EQ(b.info().lt_use_bw, last_ack == 282) << last_ack;
  }
}

TEST_F(CcBbrModel, PolicerAbsoluteConsistencyIncludesFiveHundredBytesPerSecond) {
  for (const auto spacing : {680ms, 660ms}) {
    SetUp();
    c.mss = 1060;
    probe_bw();
    rs.losses = 1;
    rs.acked_sacked = 1;
    for (int i = 0; i < 4; ++i) {
      ack(1s);
    }
    for (int i = 0; i < 4; ++i) {
      ack(spacing);
    }
    // Q24 estimates are 16 and 24 or 25. At MSS 1060 a difference
    // of 8 is 500 B/s after the pacing margin; 9 is 562 B/s.
    EXPECT_EQ(b.info().lt_use_bw, spacing == 680ms);
  }
}

TEST_F(CcBbrModel, PolicerAcceptsSixteenRoundIntervalAndDiscardsSeventeen) {
  for (int length : {16, 17}) {
    SetUp();
    probe_bw();
    rs.acked_sacked = 1;
    rs.losses = 1;
    ack();
    rs.losses = 0;
    for (int i = 1; i < length - 1; ++i) {
      ack();
    }
    rs.losses = 4;
    ack();
    for (int i = 0; i < 4; ++i) {
      ack();
    }
    EXPECT_EQ(b.info().lt_use_bw, length == 16);
  }
}

TEST_F(CcBbrModel, ProbeMarkerPropagatesThroughTransmitAndRateGeneration) {
  c.in_flight = 4;
  ack(10001ms);
  ASSERT_EQ(c.app_limited, c.delivered + 4);
  RateState rate;
  rate.delivered = c.delivered;
  rate.app_limited = c.app_limited;
  ChunkPool pool(4);
  SendQueue queue(pool, 8192);
  std::array<std::byte, 1000> payload{};
  queue.write(payload);
  rate_on_send(rate, 0, c.now);
  const auto& sent = queue.on_transmit(0, 1000, false, c.now, rate);
  RateAck sample;
  rate_on_delivered(rate, sample, sent, c.now + 20ms);
  ++rate.delivered;
  const auto next = rate_gen(rate, sample, 1, 0, 1, false, 20ms, 20ms, false, c.now + 20ms);
  ASSERT_TRUE(next.valid);
  EXPECT_TRUE(next.is_app_limited);
  EXPECT_EQ(next.prior_delivered, c.delivered);
}

TEST_F(CcBbrModel, RateDuringStartupNeverFallsUntilFirstSrttOrFullPipe) {
  c.srtt = 0ms;
  b.init(c);
  const auto nominal = c.pacing_rate;
  ack();
  EXPECT_EQ(c.pacing_rate, nominal);
  c.srtt = 20ms;
  ack();
  EXPECT_LT(c.pacing_rate, nominal);
  const auto rate = c.pacing_rate;
  rs.delivered = 1;
  ack();
  EXPECT_EQ(c.pacing_rate, rate);
}

TEST_F(CcBbrModel, ResetsPrePlateauBaselineOnLossAndKeepsPostPlateauLatch) {
  ack();
  ack();
  ack();  // one more flat round would leave STARTUP
  b.set_state(c, CaState::loss);
  c.in_flight = 100;
  for (int i = 0; i < 3; ++i) {
    ack();
  }
  EXPECT_EQ(b.info().mode, Bbr::Mode::startup);
  ack();
  EXPECT_EQ(b.info().mode, Bbr::Mode::drain);
  c.in_flight = 0;
  ack();
  ASSERT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  b.set_state(c, CaState::loss);
  c.ca_state = CaState::loss;
  c.cwnd = 999;
  ack();
  EXPECT_LT(c.cwnd, 50u);  // the full-pipe latch still enforces target cwnd
}

TEST_F(CcBbrModel, TsoBudgetUsesLegacyByteLimitAnd127PacketLimit) {
  for (unsigned mss : {100u, 1000u}) {
    SetUp();
    c.mss = mss;
    rs.delivered = 200000;
    c.in_flight = 10000000;
    for (int i = 0; i < 4; ++i) {
      ack();
    }
    ASSERT_EQ(b.info().mode, Bbr::Mode::drain);
    // BDP 200000 pkts; 65215 bytes permits 65 packets at MSS 1000.
    EXPECT_EQ(c.ssthresh, mss == 100 ? 200382u : 200196u);
  }
}

TEST(CcBbr, SelectionUsesPerConnectionStorage) {
  CcStorage storage;
  cc_select(storage, CcAlgo::bbr);
  EXPECT_TRUE(std::holds_alternative<Bbr>(storage));
  EXPECT_EQ(cc_of(storage).name(), "bbr");
}

TEST_F(CcBbrModel, OldSnapshotWithMatchingLowWordDoesNotStartANewRound) {
  ack();
  rs.prior_delivered = c.delivered - (1ULL << 32);
  for (int i = 0; i < 5; ++i) {
    ack(1ms, false);
  }
  EXPECT_EQ(b.info().mode, Bbr::Mode::startup);
}

TEST_F(CcBbrModel, AppLimitedTransmitResetsTheAggregationEpoch) {
  probe_bw();
  c.cwnd = 100;
  rs.acked_sacked = 20;
  ack(0ms);
  c.app_limited = c.delivered + 1;
  b.cwnd_event(c, CaEvent::tx_start);
  rs.acked_sacked = 1;
  for (int i = 0; i < 10; ++i) {
    ack(0ms);
  }
  EXPECT_EQ(c.cwnd, 38u);  // 20 BDP + 10 since TX_START + 6 TSO + 2 probe
}

TEST_F(CcBbrModel, AckEpochRestartsWhenPacketTotalReachesOneMillionBinary) {
  probe_bw();
  rs.acked_sacked = (1u << 20) - 2;
  c.cwnd = 100;
  ack(0ms);
  rs.acked_sacked = 2;
  ack(0ms);  // clear the epoch before accumulating these two packets
  rs.acked_sacked = 1;
  for (int i = 0; i < 10; ++i) {
    ack(0ms);
  }
  EXPECT_EQ(c.cwnd, 40u);  // 20 BDP + 12 in new epoch + 6 TSO + 2 probe
}

TEST_F(CcBbrModel, IdleRestartSuppressesRttProbeUntilDeliveredAck) {
  probe_bw();
  c.app_limited = c.delivered + 1;
  b.cwnd_event(c, CaEvent::tx_start);
  rs.rtt = -1ns;
  rs.delivered = 0;
  rs.valid = false;
  ack(11s);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  rs.delivered = 1;
  rs.valid = true;
  ack();
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  ack();
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
}

TEST_F(CcBbrModel, JiffiesDeadlineCanCrossThe32BitClockRollover) {
  c.now = Time{} + std::chrono::milliseconds{(1ULL << 32) - 10100};
  b.init(c);
  ack(10000ms);
  EXPECT_EQ(b.info().mode, Bbr::Mode::startup);
  ack(1ms);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  ack(200ms);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  ack(1ms);
  EXPECT_NE(b.info().mode, Bbr::Mode::probe_rtt);
}

TEST_F(CcBbrModel, HighRatePolicerComparisonUsesKernelU32Products) {
  c.now = c.delivered_time = Time{} + 100ms;
  c.srtt = c.min_rtt = 1ms;
  c.cwnd = 10000;
  c.mss = 1000;
  c.delivered = 0;
  rng = Rng{Seed::from_u64(37)};
  b.init(c);
  rs.interval = rs.rtt = 1ms;
  const std::array<unsigned, 9> losses{1, 0, 0, 0, 800, 0, 0, 0, 1600};
  for (std::size_t i = 0; i < losses.size(); ++i) {
    rs.acked_sacked = i < 5 ? 1000 : 2000;
    rs.delivered = rs.acked_sacked;
    rs.losses = losses[i];
    rs.prior_in_flight = rs.acked_sacked + rs.losses;
    ack(1ms);
  }
  EXPECT_TRUE(b.info().lt_use_bw);
  EXPECT_EQ(b.info().bandwidth_q24, 25165824u);
  EXPECT_EQ(c.cwnd, 5696u);
  EXPECT_EQ(c.pacing_rate, 1485000000u);
}

TEST_F(CcBbrModel, ProbeRttDeadlineWrappingToZeroRearmsOnTheNextAck) {
  c.now = c.delivered_time = Time{} + std::chrono::milliseconds{4294957095LL};
  c.mss = 1000;
  c.in_flight = 4;
  c.cwnd = 20;
  c.srtt = c.min_rtt = 1ms;
  c.delivered = 0;
  b.init(c);
  rs.delivered = 1;
  rs.rtt = rs.interval = 1ms;
  rs.prior_in_flight = 5;
  ack(10001ms);
  ack(1ms);
  ack(200ms);
  ASSERT_EQ(jiffies(c.now), 1u);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  EXPECT_EQ(c.cwnd, 4u);
  ack(1ms);
  EXPECT_NE(b.info().mode, Bbr::Mode::probe_rtt);
}

TEST_F(CcBbrModel, StartupInitialWindowExceptionUsesLowWordOfDelivered) {
  c.now = c.delivered_time = Time{} + 100ms;
  c.cwnd = 10;
  c.mss = 1000;
  c.srtt = 100ms;
  c.min_rtt = 1ms;
  c.delivered = (1ULL << 32) - 3;
  b.init(c);
  rs.interval = 1ms;
  rs.rtt = -1ns;
  rs.delivered = rs.prior_in_flight = 1;
  ack(1ms);
  ack(1ms);
  EXPECT_EQ(c.cwnd, 10u);
  ack(1ms);
  ASSERT_EQ(c.delivered, 1ULL << 32);
  EXPECT_EQ(c.cwnd, 11u);
}

TEST_F(CcBbrModel, InitialPacingUsesHighGainBeforeTheFirstGainUpdate) {
  EXPECT_EQ(b.info().pacing_gain_q8, 0u);
  EXPECT_EQ(b.info().cwnd_gain_q8, 0u);
  EXPECT_EQ(c.pacing_rate, 2068934u);
  ack();
  EXPECT_EQ(b.info().pacing_gain_q8, 739u);
  EXPECT_EQ(b.info().cwnd_gain_q8, 739u);
}

TEST_F(CcBbrModel, FullBandwidthThresholdIsNarrowedAfterTheQ8Shift) {
  for (unsigned n : {20479u, 20480u, 20481u, 20500u}) {
    c = CcConn{};
    rng = Rng{Seed::from_u64(37)};
    c.rng = &rng;
    c.now = c.delivered_time = Time{} + 100ms;
    c.cwnd = 30000;
    c.mss = 128;
    c.srtt = 200us;
    c.min_rtt = 100us;
    c.in_flight = 30000 - n;
    b.init(c);
    rs.interval = rs.rtt = 100us;
    rs.delivered = rs.acked_sacked = n;
    rs.prior_in_flight = 30000;
    for (int i = 0; i < 4; ++i) {
      ack(100us);
    }
    EXPECT_EQ(b.info().mode, n > 20480 ? Bbr::Mode::startup : Bbr::Mode::probe_bw) << n;
    if (n == 20481) {
      EXPECT_EQ(c.cwnd, 70962u);
      EXPECT_EQ(c.pacing_rate, 74920522029ULL);
    }
  }
}

TEST_F(CcBbrModel, BandwidthFilterStoresTheLow32BitsOfTheQ24Sample) {
  rs.delivered = 256;
  rs.interval = 1us;
  ack();
  EXPECT_EQ(b.info().bandwidth_q24, 0u);  // exactly 2^32 Q24
  rs.delivered = 257;
  ack();
  EXPECT_EQ(b.info().bandwidth_q24, 1u << 24);
}

TEST_F(CcBbrModel, RateMarginMultiplicationUsesTheKernel64BitAccumulator) {
  c.mss = 9000;
  rs.delivered = 20000;
  rs.interval = 100us;
  ack();
  EXPECT_EQ(b.info().bandwidth_q24, 3355443200u);
  EXPECT_EQ(c.pacing_rate, 746086301396ULL);
}

TEST_F(CcBbrModel, CycleElapsedMicrosecondsWrapsBeforeComparingWithMinRtt) {
  probe_bw();
  ASSERT_EQ(b.info().pacing_gain_q8, 320u);
  c.app_limited = c.delivered + 1;
  b.cwnd_event(c, CaEvent::tx_start);
  rs.prior_in_flight = 100;
  ack(std::chrono::microseconds{1ULL << 32});
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  EXPECT_EQ(b.info().pacing_gain_q8, 320u);  // tcp_stamp_us_delta returned zero
}

TEST_F(CcBbrModel, AggregationExpectedPacketCountWrapsBeforeTheEpochComparison) {
  rng = Rng{Seed::from_u64(37)};
  c.now = c.delivered_time = Time{} + 100ms;
  c.mss = 128;
  c.cwnd = 30000;
  c.srtt = 200us;
  c.min_rtt = 100us;
  c.delivered = 0;
  c.in_flight = 10000;
  b.init(c);
  rs.rtt = rs.interval = 100us;
  rs.delivered = rs.acked_sacked = 12800;
  rs.prior_in_flight = 22800;
  for (int i = 0; i < 6; ++i) {
    ack(100us);
  }
  c.app_limited = 1;
  b.cwnd_event(c, CaEvent::tx_start);
  rs.acked_sacked = 10000;
  rs.prior_in_flight = 20000;
  ack(0us);
  // At 128 packets/us this blackout projects exactly 2^32 packets.
  rs.interval = std::chrono::microseconds{1u << 25};
  c.in_flight = 4;
  rs.delivered = rs.acked_sacked = 8000;
  rs.prior_in_flight = 8004;
  ack(rs.interval);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
  rs.interval = 201ms;
  rs.delivered = rs.acked_sacked = 1;
  rs.prior_in_flight = 5;
  ack(201ms);
  EXPECT_EQ(b.info().mode, Bbr::Mode::probe_bw);
  EXPECT_EQ(c.cwnd, 38783u);
}

TEST_F(CcBbrModel, ProbeRttZeroLowWordMarkerSurvivesTheNextAck) {
  constexpr std::uint64_t wrap = 1ULL << 32;
  for (const std::uint64_t delivered_on_exit : {wrap - 1, wrap, wrap + 1}) {
    c.now = c.delivered_time = Time{} + 100ms;
    c.delivered = delivered_on_exit - 2;
    c.in_flight = 1;
    c.cwnd = 10;
    c.mss = 1000;
    b.init(c);
    rs.delivered = rs.acked_sacked = 1;
    rs.prior_in_flight = 2;
    rs.interval = rs.rtt = 20ms;
    ack(10001ms);
    ASSERT_EQ(b.info().mode, Bbr::Mode::probe_rtt);
    c.in_flight = 0;
    rs.prior_in_flight = 1;
    rs.interval = 201ms;
    ack(201ms);
    ASSERT_NE(b.info().mode, Bbr::Mode::probe_rtt);
    ASSERT_EQ(c.delivered, delivered_on_exit);
    const bool at_wrap = delivered_on_exit == wrap;
    EXPECT_EQ(c.app_limited, at_wrap ? wrap + 1 : delivered_on_exit);
    RateState rate;
    rate.delivered = c.delivered;
    rate.app_limited = c.app_limited;
    ChunkPool pool(4);
    SendQueue queue(pool, 8192);
    std::array<std::byte, 2000> payload{};
    queue.write(payload);
    for (std::uint64_t offset : {0u, 1000u}) {
      rate_on_send(rate, queue.counters().packets_out, c.now);
      queue.on_transmit(offset, 1000, false, c.now, rate);
      c.now += 20ms;
      RateAck newest;
      queue.on_cumulative_ack(offset + 1000, c.now, [&](const TxSeg& segment, bool) {
        rate_on_delivered(rate, newest, segment, c.now);
      });
      ++rate.delivered;
      const auto sample = rate_gen(rate, newest, 1, 0, 1, false, 20ms, 20ms, false, c.now);
      EXPECT_TRUE(sample.valid);
      EXPECT_EQ(sample.is_app_limited, offset == 0 || at_wrap) << delivered_on_exit;
      if (offset == 0) {
        EXPECT_EQ(rate.app_limited, at_wrap ? wrap + 1 : 0);
      }
    }
  }
}

}  // namespace
}  // namespace utcp
