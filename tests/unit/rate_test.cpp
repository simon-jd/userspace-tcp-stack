#include "core/tcp/rate.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/send_queue.hpp"
#include "tcp_test_util.hpp"

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
    rs.app_limited = 0;
    rs.delivered = 50;
    utcp::rate_check_app_limited(rs, r.unsent, 1448, r.queued, r.in_flight, r.cwnd, r.lost,
                                 r.retrans);
    EXPECT_EQ(rs.app_limited, r.marked ? 50u + r.in_flight : 0u) << r.unsent;
  }
  // delivered + in_flight == 0 gives 1.
  RateState zero;
  zero.app_limited = 0;
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

// ---- m2b-rate-pacing acceptance test 1 (M2-DESIGN §2.6, §4.1).

// A sample taken by the full path: `n` segments of `mss` bytes sent at `sent`
// with nothing outstanding before, all cumulatively ACKed at `acked`
// (rate_on_send, SendQueue snapshots, rate_on_delivered, rate_gen as
// process_ack calls them). `app` marks the connection application-limited
// before the sends.
RateSample window(RateState& rs, std::uint32_t n, std::uint32_t mss, Time sent, Time acked,
                  Duration min_rtt, bool app = false) {
  utcp::ChunkPool pool(64);
  utcp::SendQueue q(pool, 1 << 20);
  std::vector<std::byte> data(std::size_t{n} * mss);
  q.write(data);
  if (app) {
    rs.app_limited = rs.delivered + 1;
  }
  for (std::uint32_t i = 0; i < n; ++i) {
    utcp::rate_on_send(rs, q.counters().packets_out, sent);
    q.on_transmit(std::uint64_t{i} * mss, mss, false, sent, rs);
  }
  RateAck ack;
  q.on_cumulative_ack(std::uint64_t{n} * mss, acked,
                      [&](const TxSeg& s, bool) { utcp::rate_on_delivered(rs, ack, s, acked); });
  rs.delivered += n;
  return utcp::rate_gen(rs, ack, n, 0, n, false, min_rtt, Duration{-1}, false, acked);
}

// M2-DESIGN §4.1: 10 packets of 1448 bytes delivered over 20 ms give
// tcpi_delivery_rate = 10 * 1448 * 10^6 / 20000 us = 724 000 bytes/s
// (tcp_compute_delivery_rate), from the record tcp_rate_gen keeps.
TEST(Rate, DeliveryRateOfAScriptedWindow) {
  RateState rs;
  rs.app_limited = 0;
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 0u);  // no record
  const RateSample s = window(rs, 10, 1448, at(0ms), at(20ms), 20ms);
  ASSERT_TRUE(s.valid);
  EXPECT_EQ(s.delivered, 10u);
  EXPECT_EQ(s.interval, 20ms);  // max(send 0, ACK 20 ms)
  EXPECT_FALSE(s.is_app_limited);
  EXPECT_EQ(rs.rate_delivered, 10u);
  EXPECT_EQ(rs.rate_interval, 20ms);
  EXPECT_FALSE(rs.rate_app_limited);
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 724'000u);
  // The interval counts in whole microseconds, as Linux's rate_interval_us:
  // 20 ms + 999 ns is 20000 us.
  RateState r2;
  r2.rate_delivered = 10;
  r2.rate_interval = 20ms + Duration{999};
  EXPECT_EQ(utcp::rate_delivery_rate(r2, 1448), 724'000u);
  r2.rate_interval = Duration{999};  // 0 us: no rate
  EXPECT_EQ(utcp::rate_delivery_rate(r2, 1448), 0u);
}

// tcp_rate_gen (Linux 7.0 tcp_input.c:1791-1797): the record takes every
// sample that is not app-limited, and an app-limited one only if its rate
// (delivered / interval, compared by cross-multiplication) is at least the
// recorded one; its flag is tcpi_delivery_rate_app_limited.
TEST(Rate, RecordKeepsAppLimitedSamplesOnlyIfNotLower) {
  RateState rs;
  rs.app_limited = 0;
  // Not app-limited: 10 packets / 20 ms.
  ASSERT_TRUE(window(rs, 10, 1448, at(0ms), at(20ms), 20ms).valid);
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 724'000u);
  EXPECT_FALSE(rs.rate_app_limited);
  // App-limited and lower (4 / 20 ms): the record stays.
  RateSample s = window(rs, 4, 1448, at(100ms), at(120ms), 20ms, true);
  ASSERT_TRUE(s.valid);
  EXPECT_TRUE(s.is_app_limited);
  EXPECT_EQ(rs.rate_delivered, 10u);
  EXPECT_EQ(rs.rate_interval, 20ms);
  EXPECT_FALSE(rs.rate_app_limited);
  // App-limited and equal (5 / 10 ms against 10 / 20 ms: 5 * 20000 = 10 *
  // 10000): taken, with the flag.
  s = window(rs, 5, 1448, at(200ms), at(210ms), 10ms, true);
  ASSERT_TRUE(s.valid);
  EXPECT_EQ(rs.rate_delivered, 5u);
  EXPECT_EQ(rs.rate_interval, 10ms);
  EXPECT_TRUE(rs.rate_app_limited);
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 724'000u);
  // App-limited and higher (12 / 10 ms): taken.
  s = window(rs, 12, 1448, at(300ms), at(310ms), 10ms, true);
  EXPECT_EQ(rs.rate_delivered, 12u);
  EXPECT_TRUE(rs.rate_app_limited);
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 1'737'600u);
  // Not app-limited and lower (2 / 20 ms): taken (the last such sample).
  s = window(rs, 2, 1448, at(400ms), at(420ms), 10ms);
  ASSERT_TRUE(s.valid);
  EXPECT_FALSE(s.is_app_limited);
  EXPECT_EQ(rs.rate_delivered, 2u);
  EXPECT_EQ(rs.rate_interval, 20ms);
  EXPECT_FALSE(rs.rate_app_limited);
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 144'800u);
}

// Invalid samples leave the record alone: no prior snapshot, SACK reneging,
// an interval below min_rtt (also before any min_rtt sample).
TEST(Rate, InvalidSamplesLeaveTheRecordAlone) {
  RateState rs;
  rs.app_limited = 0;
  ASSERT_TRUE(window(rs, 10, 1448, at(0ms), at(20ms), 20ms).valid);
  const auto unchanged = [&] {
    EXPECT_EQ(rs.rate_delivered, 10u);
    EXPECT_EQ(rs.rate_interval, 20ms);
    EXPECT_FALSE(rs.rate_app_limited);
  };
  // No prior snapshot.
  const RateAck none;
  rs.delivered += 30;
  RateSample s = utcp::rate_gen(rs, none, 30, 0, 30, false, 1ms, Duration{-1}, false, at(50ms));
  EXPECT_FALSE(s.valid);
  unchanged();
  // Interval (10 ms) below min_rtt (20 ms), and min_rtt unset.
  s = window(rs, 40, 1448, at(100ms), at(110ms), 20ms);
  EXPECT_FALSE(s.valid);
  unchanged();
  s = window(rs, 40, 1448, at(200ms), at(210ms), Duration::max());
  EXPECT_FALSE(s.valid);
  unchanged();
  // Reneging.
  utcp::ChunkPool pool(64);
  utcp::SendQueue q(pool, 1 << 20);
  std::vector<std::byte> data(4 * 1448);
  q.write(data);
  for (std::uint32_t i = 0; i < 4; ++i) {
    utcp::rate_on_send(rs, q.counters().packets_out, at(300ms));
    q.on_transmit(std::uint64_t{i} * 1448, 1448, false, at(300ms), rs);
  }
  RateAck ack;
  q.on_cumulative_ack(4 * 1448, at(400ms),
                      [&](const TxSeg& g, bool) { utcp::rate_on_delivered(rs, ack, g, at(400ms)); });
  rs.delivered += 4;
  s = utcp::rate_gen(rs, ack, 4, 0, 4, true, 1ms, Duration{-1}, false, at(400ms));
  EXPECT_FALSE(s.valid);
  unchanged();
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 724'000u);
}

// rs.rtt is the ACK's ca_rtt (tcp_ack_update_rtt: rs->rtt_us = ca_rtt_us)
// and rs.is_ack_delayed its FLAG_ACK_MAYBE_DELAYED, valid sample or not.
TEST(Rate, SampleRttIsTheCaRtt) {
  RateState rs;
  const RateAck none;
  RateSample s = utcp::rate_gen(rs, none, 1, 0, 1, false, 1ms, 7ms, true, at(10ms));
  EXPECT_FALSE(s.valid);
  EXPECT_EQ(s.rtt, 7ms);
  EXPECT_TRUE(s.is_ack_delayed);
  s = utcp::rate_gen(rs, none, 1, 0, 1, false, 1ms, Duration{-1}, false, at(11ms));
  EXPECT_EQ(s.rtt, Duration{-1});
  EXPECT_FALSE(s.is_ack_delayed);
  RateState v;
  v.app_limited = 0;
  utcp::ChunkPool pool(64);
  utcp::SendQueue q(pool, 1 << 20);
  std::vector<std::byte> data(1448);
  q.write(data);
  utcp::rate_on_send(v, 0, at(0ms));
  q.on_transmit(0, 1448, false, at(0ms), v);
  RateAck ack;
  q.on_cumulative_ack(1448, at(20ms),
                      [&](const TxSeg& g, bool) { utcp::rate_on_delivered(v, ack, g, at(20ms)); });
  v.delivered += 1;
  s = utcp::rate_gen(v, ack, 1, 0, 1, false, 20ms, 19ms, false, at(20ms));
  EXPECT_TRUE(s.valid);
  EXPECT_EQ(s.rtt, 19ms);
}

// Linux tcp_init_sock: tp->app_limited = ~0U ("a bubble in the pipe until at
// least the first ACK") and tp->rate_app_limited = 1. Segments sent before
// the first rate_gen carry the app-limited mark; that rate_gen clears the
// marker (after(delivered, ~0U) holds for any delivered below 2^31).
TEST(Rate, NewConnectionStartsAppLimited) {
  RateState rs;
  EXPECT_EQ(rs.app_limited, utcp::rate_app_limited_initial);
  EXPECT_TRUE(rs.rate_app_limited);
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 0u);
  const RateSample s = window(rs, 10, 1448, at(0ms), at(20ms), 20ms);
  ASSERT_TRUE(s.valid);
  EXPECT_TRUE(s.is_app_limited);   // the initial window was sent in the bubble
  EXPECT_EQ(rs.app_limited, 0u);   // cleared by the first rate_gen
  EXPECT_TRUE(rs.rate_app_limited);  // the record took it (any rate beats none)
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 724'000u);
  // The next window is not app-limited.
  const RateSample s2 = window(rs, 10, 1448, at(100ms), at(140ms), 20ms);
  ASSERT_TRUE(s2.valid);
  EXPECT_FALSE(s2.is_app_limited);
  EXPECT_FALSE(rs.rate_app_limited);
  EXPECT_EQ(utcp::rate_delivery_rate(rs, 1448), 362'000u);
}

// TcpInfo::app_limited and delivery_rate are the record's (tcp_get_info),
// not tp->app_limited: after a bulk transfer the record holds a sample that
// is not app-limited; small writes then mark the connection
// application-limited (rate_check_app_limited) and give app-limited samples
// at a lower rate, which the record does not take, so TcpInfo still says
// not app-limited, with the bulk rate.
TEST(Rate, TcpInfoReportsTheRecord) {
  namespace t = utcp::test;
  using namespace utcp::test::tcpt;
  t::TcpHarness h(config(t::Side::a), config(t::Side::b));
  h.set_delay(t::Side::a, 5ms);
  h.set_delay(t::Side::b, 5ms);
  utcp::TcpSocketOptions o;
  o.snd_buf = 4 << 20;  // one write takes the whole transfer
  const auto p = open(h, 100ms, o);
  ASSERT_TRUE(p);
  const t::Bytes bulk = t::pattern(2'000'000, 3);
  const auto n = h.a().tcp_send(p->client, bulk);
  ASSERT_TRUE(n);
  ASSERT_EQ(*n, bulk.size());
  for (int i = 0; i < 400; ++i) {
    h.run_for(5ms);
    drain(h.b(), p->server);
  }
  const auto i1 = h.a().tcp_info(p->client);
  ASSERT_TRUE(i1);
  ASSERT_EQ(i1->unacked, 0u);
  EXPECT_FALSE(i1->app_limited);
  // Faster than one packet per RTT (10 ms), which the small writes give.
  EXPECT_GT(i1->delivery_rate, 10u * 1448 * 100);
  for (int i = 0; i < 5; ++i) {
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(100)));
    h.run_for(50ms);
    drain(h.b(), p->server);
  }
  const auto i2 = h.a().tcp_info(p->client);
  ASSERT_TRUE(i2);
  EXPECT_GT(i2->delivered, i1->delivered + 4);
  EXPECT_FALSE(i2->app_limited);
  EXPECT_EQ(i2->delivery_rate, i1->delivery_rate);
}

}  // namespace
