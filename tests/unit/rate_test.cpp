#include "core/tcp/rate.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/send_queue.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::RateAck;
using utcp::RateSample;
using utcp::RateState;
using utcp::Time;
using utcp::TxSeg;

Time at(Duration d) { return Time{5'000'000'000} + d; }

TxSeg seg(std::uint64_t off, std::uint32_t len, Time last_tx, std::uint64_t delivered,
          Time delivered_time, Time first_tx_time) {
  TxSeg s;
  s.off = off;
  s.len = len;
  s.tx_count = 1;
  s.first_tx = s.last_tx = last_tx;
  s.delivered = delivered;
  s.delivered_time = delivered_time;
  s.first_tx_time = first_tx_time;
  return s;
}

TEST(Rate, SendResetsTheIntervalOnlyWithNothingOutstanding) {
  RateState rs;
  utcp::rate_on_send(rs, 0, at(1ms));
  EXPECT_TRUE(rs.has_sent);
  EXPECT_EQ(rs.first_tx_time, at(1ms));
  EXPECT_EQ(rs.delivered_time, at(1ms));
  utcp::rate_on_send(rs, 2, at(2ms));
  EXPECT_EQ(rs.first_tx_time, at(1ms));
  EXPECT_EQ(rs.delivered_time, at(1ms));

  // After an RTO marks everything lost, in-flight is 0 but packets_out is
  // not: the retransmission does not restart the interval.
  utcp::ChunkPool pool(8);
  utcp::SendQueue q(pool, 64 * 1024);
  std::vector<std::byte> data(3000);
  q.write(data);
  RateState r2;
  for (std::uint64_t off = 0; off < 3000; off += 1000) {
    utcp::rate_on_send(r2, q.counters().packets_out, at(10ms));
    q.on_transmit(off, 1000, false, at(10ms), r2);
  }
  for (const TxSeg& s : q.segs()) {
    q.mark_lost(s.off);
  }
  EXPECT_EQ(utcp::packets_in_flight(q.counters()), 0u);
  utcp::rate_on_send(r2, q.counters().packets_out, at(500ms));
  EXPECT_EQ(r2.first_tx_time, at(10ms));
  EXPECT_EQ(r2.delivered_time, at(10ms));
  const TxSeg& re = q.on_transmit(0, 1000, false, at(500ms), r2);
  EXPECT_EQ(re.first_tx_time, at(10ms));
  // Once everything is acknowledged the next send restarts it.
  q.on_cumulative_ack(3000, at(600ms), [](const TxSeg&, bool) {});
  utcp::rate_on_send(r2, q.counters().packets_out, at(700ms));
  EXPECT_EQ(r2.first_tx_time, at(700ms));
}

TEST(Rate, AppLimitedMarkerNeedsAllFourConditions) {
  struct Row {
    std::uint64_t unsent;
    bool queued;
    std::uint32_t in_flight, cwnd, lost, retrans;
    bool marked;
  };
  const Row rows[] = {
      {100, false, 4, 10, 0, 0, true},
      {1448, false, 4, 10, 0, 0, false},  // a full packet is still unsent
      {100, true, 4, 10, 0, 0, false},    // a packet waits in the transmit queue
      {100, false, 10, 10, 0, 0, false},  // cwnd-limited
      {100, false, 4, 10, 2, 1, false},   // a lost packet is not retransmitted
      {100, false, 4, 10, 2, 2, true},
  };
  for (const Row& r : rows) {
    RateState rs;
    rs.delivered = 50;
    utcp::rate_check_app_limited(rs, r.unsent, 1448, r.queued, r.in_flight, r.cwnd, r.lost,
                                 r.retrans);
    EXPECT_EQ(rs.app_limited, r.marked ? 50u + r.in_flight : 0u) << r.unsent;
  }
  // delivered + in_flight == 0 gives 1.
  RateState zero;
  utcp::rate_check_app_limited(zero, 0, 1448, false, 0, 10, 0, 0);
  EXPECT_EQ(zero.app_limited, 1u);
}

TEST(Rate, AppLimitedMarkerClearsOnceDeliveredPassesIt) {
  RateState rs;
  rs.delivered = 50;
  utcp::rate_check_app_limited(rs, 0, 1448, false, 4, 10, 0, 0);
  ASSERT_EQ(rs.app_limited, 54u);
  const RateAck none;
  rs.delivered = 54;
  utcp::rate_gen(rs, none, 4, 0, 4, false, 1ms, Duration{-1}, false, at(1s));
  EXPECT_EQ(rs.app_limited, 54u);  // not past it yet
  rs.delivered = 55;
  utcp::rate_gen(rs, none, 1, 0, 1, false, 1ms, Duration{-1}, false, at(2s));
  EXPECT_EQ(rs.app_limited, 0u);
}

TEST(Rate, DeliveredKeepsTheMostRecentlySentSnapshot) {
  RateState rs;
  rs.has_sent = true;
  rs.first_tx_time = at(0ms);
  RateAck ack;
  const TxSeg a = seg(0, 1000, at(1ms), 3, at(0ms), at(0ms));
  const TxSeg b = seg(1000, 1000, at(2ms), 4, at(0ms), at(0ms));
  TxSeg c = seg(2000, 1000, at(2ms), 5, at(1ms), at(0ms));  // same time as b, higher end
  utcp::rate_on_delivered(rs, ack, b, at(10ms));
  EXPECT_EQ(ack.prior_delivered, 4u);
  EXPECT_EQ(rs.first_tx_time, at(2ms));
  utcp::rate_on_delivered(rs, ack, a, at(10ms));  // sent earlier: ignored
  EXPECT_EQ(ack.prior_delivered, 4u);
  utcp::rate_on_delivered(rs, ack, c, at(10ms));  // tie broken by end offset
  EXPECT_EQ(ack.prior_delivered, 5u);
  EXPECT_EQ(ack.prior_end, 3000u);
  EXPECT_EQ(ack.prior_time, at(1ms));
  // A used snapshot is skipped.
  TxSeg d = seg(3000, 1000, at(3ms), 9, at(2ms), at(0ms));
  d.rate_used = true;
  utcp::rate_on_delivered(rs, ack, d, at(10ms));
  EXPECT_EQ(ack.prior_delivered, 5u);
  c.ever_retrans = true;
  c.app_limited = true;
  RateAck ack2;
  utcp::rate_on_delivered(rs, ack2, c, at(10ms));
  EXPECT_TRUE(ack2.is_retrans);
  EXPECT_TRUE(ack2.is_app_limited);
}

TEST(Rate, SampleValidity) {
  RateState rs;
  rs.has_sent = true;
  rs.first_tx_time = at(0ms);
  // Without a prior snapshot: invalid.
  RateAck none;
  RateSample s = utcp::rate_gen(rs, none, 2, 0, 5, false, 1ms, Duration{-1}, false, at(30ms));
  EXPECT_FALSE(s.valid);
  EXPECT_EQ(s.interval, Duration{-1});
  EXPECT_EQ(s.acked_sacked, 2u);
  EXPECT_EQ(rs.delivered_time, at(30ms));  // delivered changed

  // A snapshot taken at delivered = 10 at 0 ms, sent over [0, 5 ms).
  RateAck ack;
  rs.first_tx_time = at(0ms);
  utcp::rate_on_delivered(rs, ack, seg(0, 1000, at(5ms), 10, at(0ms), at(0ms)), at(30ms));
  rs.delivered = 20;
  // Valid: interval = max(send 5 ms, ack 30 ms) = 30 ms >= min_rtt 20 ms.
  s = utcp::rate_gen(rs, ack, 10, 1, 12, false, 20ms, Duration{-1}, false, at(30ms));
  EXPECT_TRUE(s.valid);
  EXPECT_EQ(s.delivered, 10u);
  EXPECT_EQ(s.prior_delivered, 10u);
  EXPECT_EQ(s.interval, 30ms);
  EXPECT_EQ(s.losses, 1u);
  EXPECT_EQ(s.prior_in_flight, 12u);
  // While reneging: invalid.
  s = utcp::rate_gen(rs, ack, 10, 0, 12, true, 20ms, Duration{-1}, false, at(30ms));
  EXPECT_FALSE(s.valid);
  // Interval below min_rtt: invalid (and before any min_rtt sample).
  s = utcp::rate_gen(rs, ack, 10, 0, 12, false, 31ms, Duration{-1}, false, at(30ms));
  EXPECT_FALSE(s.valid);
  EXPECT_EQ(s.interval, Duration{-1});
  s = utcp::rate_gen(rs, ack, 10, 0, 12, false, Duration::max(), Duration{-1}, false, at(30ms));
  EXPECT_FALSE(s.valid);
  // The send phase wins when it is longer (ACK compression).
  RateAck ack2;
  rs.first_tx_time = at(0ms);
  utcp::rate_on_delivered(rs, ack2, seg(0, 1000, at(40ms), 10, at(25ms), at(0ms)), at(30ms));
  s = utcp::rate_gen(rs, ack2, 10, 0, 12, false, 20ms, Duration{-1}, false, at(30ms));
  EXPECT_TRUE(s.valid);
  EXPECT_EQ(s.interval, 40ms);
}

}  // namespace
