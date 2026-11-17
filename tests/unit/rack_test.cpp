// m2a-recovery acceptance tests 3 and 4: RACK and the send-time FIFO, and
// the D-SACK reorder window (M2-DESIGN §1.5, §1.6; RFC 8985 §6; Linux 7.0
// tcp_recovery.c, tcp_rack_advance, tcp_rack_update_reo_wnd, tcp_dsack_seen).
#include "core/tcp/rack.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <random>
#include <string>
#include <tuple>
#include <vector>

#include "recovery_rig.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::CaState;
using utcp::Duration;
using utcp::Range;
using utcp::RackState;
using utcp::SendQueue;
using utcp::SentFifo;
using utcp::Time;
using utcp::TxKind;
using utcp::TxSeg;
using utcp::XmitTimer;
using utcp::test::rig::mss;
using utcp::test::rig::off_of;
using utcp::test::rig::Rig;
using Sent = std::vector<std::string>;

// tcp_rack_reo_wnd: min_rtt 20 ms, srtt 100 ms.
TEST(RackReoWnd, Values) {
  RackState r;
  // No reordering seen: 0 in Recovery/Loss, and once sacked_out reaches
  // reordering (the DupThresh rule).
  EXPECT_EQ(utcp::rack_reo_wnd(r, 0, true, 0, 3, 20ms, 100ms), Duration{0});
  EXPECT_EQ(utcp::rack_reo_wnd(r, 0, false, 3, 3, 20ms, 100ms), Duration{0});
  // Otherwise min_rtt / 4 = 5 ms.
  EXPECT_EQ(utcp::rack_reo_wnd(r, 0, false, 2, 3, 20ms, 100ms), 5ms);
  EXPECT_EQ(utcp::rack_reo_wnd(r, 1, true, 5, 3, 20ms, 100ms), 5ms);  // reordering seen
  // Steps 3: 15 ms; capped at srtt 12 ms.
  r.reo_wnd_steps = 3;
  EXPECT_EQ(utcp::rack_reo_wnd(r, 1, false, 0, 3, 20ms, 100ms), 15ms);
  EXPECT_EQ(utcp::rack_reo_wnd(r, 1, false, 0, 3, 20ms, 12ms), 12ms);
  // No min_rtt sample yet (Duration::max()): srtt.
  EXPECT_EQ(utcp::rack_reo_wnd(r, 1, false, 0, 3, Duration::max(), 30ms), 30ms);
}

// tcp_rack_mark_lost's timer: remaining + 2 ms (TCP_TIMEOUT_MIN_US), whole
// milliseconds rounded up (usecs_to_jiffies), at most the RTO (icsk_rto).
TEST(RackReoDeadline, RoundedAndCapped) {
  const Time now{5'000'000'000};
  EXPECT_EQ(utcp::rack_reo_deadline(now, 10ms, 300ms), now + 12ms);
  EXPECT_EQ(utcp::rack_reo_deadline(now, 3200us, 300ms), now + 6ms);  // 5.2 ms up to 6
  EXPECT_EQ(utcp::rack_reo_deadline(now, 1ns, 300ms), now + 3ms);
  // srtt 300 ms and an RTO of 500 ms: 600 ms remaining arms 500 ms.
  EXPECT_EQ(utcp::rack_reo_deadline(now, 600ms, 500ms), now + 500ms);
}

// tcp_rack_advance: the ambiguous skip and the (time, end) ordering.
TEST(RackAdvance, AmbiguousSkipAndOrder) {
  RackState r;
  TxSeg s;
  s.off = 0;
  s.len = 1000;
  s.last_tx = Time{1'000'000'000};
  const Time now = s.last_tx + 30ms;
  // A retransmitted segment delivered 30 ms after its last transmission,
  // below min_rtt 40 ms: the original may have arrived. Skipped.
  s.ever_retrans = true;
  utcp::rack_advance(r, s, now, 40ms);
  EXPECT_FALSE(r.advanced);
  EXPECT_EQ(r.rtt, Duration{-1});
  // At min_rtt 30 ms it is not ambiguous (30 < 30 is false).
  utcp::rack_advance(r, s, now, 30ms);
  EXPECT_TRUE(r.advanced);
  EXPECT_EQ(r.rtt, 30ms);
  EXPECT_EQ(r.xmit_ts, s.last_tx);
  EXPECT_EQ(r.end, 1000u);
  // A never-retransmitted one is never ambiguous.
  TxSeg t = s;
  t.ever_retrans = false;
  t.off = 5000;
  t.last_tx = s.last_tx - 10ms;  // sent earlier: rtt moves, xmit_ts does not
  utcp::rack_advance(r, t, now, 40ms);
  EXPECT_EQ(r.rtt, 40ms);
  EXPECT_EQ(r.xmit_ts, s.last_tx);
  // Same time, higher end: xmit_ts/end move (tcp_skb_sent_after).
  t.last_tx = s.last_tx;
  utcp::rack_advance(r, t, now, 40ms);
  EXPECT_EQ(r.end, 6000u);
}

// M2-DESIGN §1.5 property: after 10^4 random sequences of sends,
// retransmissions (some split first, some loss probes), loss marks, SACKs,
// cumulative ACKs (some inside a segment) and one PMTU split, the live FIFO
// entries in order equal the live segments sorted by (last_tx, off), and
// after each append the FIFO has at most 2 * packets_out + 64 entries.
TEST(RackFifo, PropertyRandomSequences) {
  std::mt19937_64 g(20261115);
  const auto pick = [&](std::uint64_t n) { return std::uniform_int_distribution<std::uint64_t>(0, n - 1)(g); };
  for (int run = 0; run < 10'000; ++run) {
    utcp::ChunkPool pool{64};
    SendQueue q{pool, 1 << 20};
    utcp::RateState rate;
    SentFifo f;
    Time now{1'000'000'000};
    const std::vector<std::byte> data(48'000);
    ASSERT_EQ(q.write(data), data.size());
    const int ops = 30 + static_cast<int>(pick(30));
    const int pmtu_at = static_cast<int>(pick(static_cast<std::uint64_t>(ops)));
    const auto append = [&](std::uint64_t off, std::uint32_t len, bool probe) {
      utcp::rate_on_send(rate, q.counters().packets_out, now);
      const TxSeg& s = q.on_transmit(off, len, false, now, rate, probe);
      f.on_transmit(q, s);
      ASSERT_LE(f.size(), 2 * std::size_t{q.counters().packets_out} + 64) << "run " << run;
    };
    for (int op = 0; op < ops; ++op) {
      const auto segs = q.segs();
      const std::uint64_t k = pick(10);
      if (op == pmtu_at) {
        q.split_to_mss(static_cast<std::uint16_t>(300 + pick(400)));
        f.rebuild(q);
      } else if (k < 3 || segs.empty()) {
        if (q.nxt() < q.end()) {
          const auto len = static_cast<std::uint32_t>(
              std::min<std::uint64_t>(1 + pick(1000), q.end() - q.nxt()));
          append(q.nxt(), len, false);
        }
      } else if (k < 5) {
        // The engine resends a segment without a retransmission in flight
        // that is not SACKed; a loss probe may resend any (tcp_send_loss_probe).
        const TxSeg s = segs[pick(segs.size())];
        const bool probe = s.sacked || s.retrans_inflight || pick(6) == 0;
        if (s.len > 1 && pick(3) == 0) {
          q.split(s.off, static_cast<std::uint32_t>(1 + pick(s.len - 1)));  // retransmit_seg's cut
        }
        append(s.off, q.find(s.off)->len, probe);
      } else if (k == 5) {
        q.mark_lost(segs[pick(segs.size())].off);
      } else if (k == 6) {
        const std::size_t a = pick(segs.size());
        const std::size_t b = std::min(segs.size() - 1, a + pick(3));
        if (segs[a].off > q.una()) {
          const std::vector<utcp::Range> blk{{segs[a].off, segs[b].end()}};
          q.on_sack(blk, now, [](const TxSeg&, bool) {});
        }
      } else if (k == 7) {
        const std::uint64_t una = q.una() + pick(q.nxt() - q.una() + 1);
        q.on_cumulative_ack(una, now, [](const TxSeg&, bool) {});
      } else {
        now += Duration{static_cast<Duration::rep>(pick(3)) * 1'000'000};  // 0: same time
      }
      // Live segments sorted by (last_tx, off).
      std::vector<std::tuple<Time, std::uint64_t>> live;
      for (const TxSeg& s : q.segs()) {
        if (SentFifo::live(s)) {
          live.emplace_back(s.last_tx, s.off);
        }
      }
      std::sort(live.begin(), live.end());
      std::vector<std::uint64_t> want;
      for (const auto& [t, off] : live) {
        want.push_back(off);
      }
      ASSERT_EQ(f.live_offsets(q), want) << "run " << run << " op " << op;
    }
  }
}

// The bound of M2-DESIGN §1.5 where the random sequences above never get
// near it: 100 segments sent, 99 cumulatively acknowledged (their 99 entries
// are dead), then the last one resent 200 times as a loss probe (each resend
// kills the previous entry). packets_out stays 1, so after every append the
// FIFO may hold at most 2 * 1 + 64 = 66 entries; without the filter it would
// reach 300.
TEST(RackFifo, BoundHoldsWithManyDeadEntries) {
  utcp::ChunkPool pool{64};
  SendQueue q{pool, 1 << 20};
  utcp::RateState rate;
  SentFifo f;
  Time now{1'000'000'000};
  const std::vector<std::byte> data(100'000);
  ASSERT_EQ(q.write(data), data.size());
  for (int i = 0; i < 100; ++i) {
    f.on_transmit(q, q.on_transmit(q.nxt(), 1000, false, now, rate));
  }
  ASSERT_EQ(f.size(), 100u);
  now += 10ms;
  q.on_cumulative_ack(99'000, now, [](const TxSeg&, bool) {});
  ASSERT_EQ(q.counters().packets_out, 1u);
  for (int i = 0; i < 200; ++i) {
    now += 1ms;
    f.on_transmit(q, q.on_transmit(99'000, 1000, false, now, rate, true));
    ASSERT_LE(f.size(), 2 * std::size_t{q.counters().packets_out} + 64) << "resend " << i;
  }
  EXPECT_EQ(f.live_offsets(q), std::vector<std::uint64_t>{99'000});
}

// A retransmission split (retransmit_seg, tcp_fragment, which puts the tail
// right after the head in Linux's list): the tail keeps the original's place,
// the resent head goes to the end. A lost tail waits (not live) until resent.
TEST(RackFifo, SplitTailKeepsItsPlace) {
  utcp::ChunkPool pool{64};
  SendQueue q{pool, 1 << 20};
  utcp::RateState rate;
  SentFifo f;
  Time now{1'000'000'000};
  const std::vector<std::byte> data(4000);
  ASSERT_EQ(q.write(data), data.size());
  for (int i = 0; i < 4; ++i) {
    f.on_transmit(q, q.on_transmit(q.nxt(), 1000, false, now, rate));
    now += 1ms;
  }
  // A loss probe of segment 1, cut to 400 bytes: [400, 1000) keeps its first
  // transmission and its place.
  q.split(0, 400);
  f.on_transmit(q, q.on_transmit(0, 400, false, now, rate, true));
  EXPECT_EQ(f.live_offsets(q), (std::vector<std::uint64_t>{400, 1000, 2000, 3000, 0}));
  // Segment 2 lost and resent in two parts: the lost tail is not live until
  // it is resent.
  q.mark_lost(1000);
  q.split(1000, 300);
  now += 1ms;
  f.on_transmit(q, q.on_transmit(1000, 300, false, now, rate));
  EXPECT_EQ(f.live_offsets(q), (std::vector<std::uint64_t>{400, 2000, 3000, 0, 1000}));
  f.on_transmit(q, q.on_transmit(1300, 700, false, now, rate));
  EXPECT_EQ(f.live_offsets(q), (std::vector<std::uint64_t>{400, 2000, 3000, 0, 1000, 1300}));
}

// The REO deadline is capped at the RTO when RACK.rtt + reo_wnd is large: the
// RTO's retransmission of 1 is acknowledged 700 ms after it was sent, when
// 3 (sent 99 ms ago) is SACKed. RACK.xmit_ts is 3's; RACK.rtt is 700 ms
// (the cumulative step comes last). 2, sent 1 ms before 3, has 700 + 10 -
// 100 = 610 ms left; 612 ms is more than the RTO, which arms instead.
TEST(RackPipeline, ReoDeadlineCappedAtRto) {
  Rig r(utcp::test::rig::linux_cfg());
  r.send_new(1);
  r.now += r.rtt.rto_backed_off(0);
  r.fire_rto();
  const Time t1 = r.now;
  r.now = t1 + 600ms;
  r.send_new(1);
  r.now = t1 + 601ms;
  r.send_new(1);
  r.now = t1 + 700ms;
  r.ack(2, {{3, 3}});
  EXPECT_EQ(r.rec.rack().rtt, 700ms);
  EXPECT_EQ(r.rec.rack().xmit_ts, t1 + 601ms);
  EXPECT_FALSE(r.pkt(2).lost);
  const Duration rto = r.rtt.rto_backed_off(0);
  ASSERT_LT(rto, 612ms);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::reo, r.now + rto));
}

// tcp_skb_spurious_retrans: a cumulatively acknowledged retransmission whose
// ACK echoes a TSval older than the retransmission does not advance RACK.
TEST(RackPipeline, SpuriousRetransmissionSkip) {
  for (const bool spurious : {true, false}) {
    SCOPED_TRACE(spurious);
    Rig r(utcp::test::rig::linux_cfg());
    const Time t0 = r.now;
    r.send_new(2);
    r.now = t0 + 300ms;
    r.send_at(0, TxKind::rexmit);
    r.now = t0 + 400ms;
    const auto ts = static_cast<std::uint32_t>((spurious ? t0 : t0 + 300ms).ns / 1'000'000);
    r.ack(2, {}, std::nullopt, ts);
    EXPECT_EQ(r.rec.rack().advanced, !spurious);
    EXPECT_EQ(r.rec.rack().rtt, spurious ? Duration{-1} : Duration{100ms});
  }
}

// tcp_timeout_mark_lost with RACK: the head always, another segment only if
// it was sent at least RACK.rtt (100 ms) ago (tcp_rack_skb_timeout(skb, 0)
// <= 0: exactly RACK.rtt ago is marked, 1 ms less is not).
TEST(RackPipeline, RtoMarksHeadAndOldSegmentsOnly) {
  Rig r(utcp::test::rig::linux_cfg());
  const Time t0 = r.now;
  r.send_new(5);
  r.now = t0 + 100ms;
  r.ack(1, {{2, 2}});
  ASSERT_EQ(r.rec.rack().rtt, 100ms);
  r.now = t0 + 300ms;
  r.send_new(1);                        // 6, exactly 100 ms before the RTO
  r.now = t0 + 301ms;
  r.send_new(1);                        // 7, 99 ms before
  r.now = t0 + 350ms;
  r.send_new(2);                        // 8-9, 50 ms before
  r.now = t0 + 360ms;
  r.send_at(0, TxKind::rexmit);         // the head, resent 40 ms before
  r.now = t0 + 400ms;
  auto c = r.rctx();
  r.rec.on_rto(c);
  EXPECT_TRUE(r.pkt(1).lost);           // the head, however recent
  EXPECT_FALSE(r.pkt(1).retrans_inflight);
  EXPECT_TRUE(r.pkt(2).sacked);
  for (std::uint32_t k = 3; k <= 5; ++k) {
    EXPECT_TRUE(r.pkt(k).lost) << k;    // 400 ms old
  }
  EXPECT_TRUE(r.pkt(6).lost);           // 100 ms: 100 - 100 = 0 <= 0
  for (std::uint32_t k = 7; k <= 9; ++k) {
    EXPECT_FALSE(r.pkt(k).lost) << k;   // 99 and 50 ms old < 100 ms
  }
  EXPECT_EQ(r.rec.state(), CaState::loss);
  // rfc (no RACK): every non-SACKed segment.
  Rig f(utcp::test::rig::rfc_cfg());
  f.send_new(5);
  f.now += 100ms;
  f.ack(1, {{2, 2}});
  f.send_new(3);
  auto d = f.rctx();
  f.rec.on_rto(d);
  EXPECT_EQ(f.q.counters().lost_out, 7u);
}

// With SACK a partial ACK marks nothing by itself in linux_compat either:
// packet 1's original arrives 5 ms after its retransmission (ambiguous for
// RACK, below min_rtt), SND.UNA moves to 5 and 5 stays unmarked.
TEST(RackPipeline, PartialAckDoesNotMarkTheHead) {
  Rig r(utcp::test::rig::linux_cfg());
  const Time t0 = r.now;
  r.send_new(10);
  r.now = t0 + 100ms;
  r.ack(1, {{2, 4}});
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.transmit(), Sent{"R1"});
  r.now = t0 + 105ms;
  r.ack(5);
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_FALSE(r.pkt(5).lost);
  EXPECT_EQ(r.q.counters().lost_out, 0u);
}

// M2-DESIGN §1.7 "Arming on transmission": new data sent after the ACK that
// armed the REO timer leaves it (tcp_event_new_data_sent re-arms only with
// nothing out before or a PTO pending); the timer then enters Recovery
// without an RTO.
TEST(RackPipeline, ReoTimerSurvivesNewDataAndEntersRecovery) {
  Rig r(utcp::test::rig::linux_cfg());
  const Time t0 = r.now;
  r.send_new(10);
  r.now = t0 + 100ms;
  r.ack(1, {{2, 2}});
  ASSERT_EQ(r.timer(), std::make_pair(XmitTimer::reo, t0 + 112ms));
  r.write(5);
  EXPECT_EQ(r.transmit(), (Sent{"N11", "N12", "N13", "N14", "N15"}));
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::reo, t0 + 112ms));
  r.now = t0 + 112ms;
  EXPECT_EQ(r.fire_reo(), Sent{"R1"});
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.stats.TcpExtTCPTimeouts, 0u);
  EXPECT_EQ(r.timer().first, XmitTimer::rto);
}

// M2-DESIGN §1.7: a head retransmission re-arms a full RTO only when the
// pending timer is not REO (tcp_xmit_retransmit_queue, tcp_output.c:3790-
// 3797). Packets 1, 2, 3 at t0, t0 + 15 ms, t0 + 20 ms; at t0 + 120 ms 3 is
// SACKed: RACK.rtt 100 ms, reo_wnd min_rtt / 4 = 10 ms (no reordering seen,
// 1 SACKed < 3). Packet 1 has 100 + 10 - 120 = -10 ms left: lost; packet 2
// has 100 + 10 - 105 = 5 ms: REO at t0 + 120 + 5 + 2 = t0 + 127 ms. Recovery;
// PRR: in_flight 1, sndcnt 1, cwnd 2. R1 goes out and the REO timer stays.
// At t0 + 127 ms the REO expiry marks 2 lost (reo_wnd 0 in Recovery without
// reordering seen) and re-arms the RTO at the head's time left (R1 at
// t0 + 120 ms); with 2 lost and 3 SACKed only R1 is in flight, so PRR's
// cwnd 2 lets R2 go out (not the head: the timer stays). No RTO.
TEST(RackPipeline, HeadRetransmissionKeepsReo) {
  Rig r(utcp::test::rig::linux_cfg());
  const Time t0 = r.now;
  r.send_new(1);
  r.now = t0 + 15ms;
  r.send_new(1);
  r.now = t0 + 20ms;
  r.send_new(1);
  r.now = t0 + 120ms;
  r.ack(1, {{3, 3}});
  ASSERT_EQ(r.rec.rack().rtt, 100ms);
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_TRUE(r.pkt(1).lost);
  EXPECT_FALSE(r.pkt(2).lost);
  ASSERT_EQ(r.timer(), std::make_pair(XmitTimer::reo, t0 + 127ms));
  EXPECT_EQ(r.cc.cwnd, 2u);
  EXPECT_EQ(r.transmit(), Sent{"R1"});
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::reo, t0 + 127ms));
  r.now = t0 + 127ms;
  EXPECT_EQ(r.fire_reo(), Sent{"R2"});
  EXPECT_EQ(r.stats.rack_reo_timeouts, 1u);
  EXPECT_EQ(r.stats.TcpExtTCPTimeouts, 0u);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 120ms + r.rtt.rto_backed_off(0)));
}

// A retransmission lost again in Loss (Linux FLAG_LOST_RETRANS) leaves Loss
// for Recovery: after the RTO, 1-10 are resent at t1; at t1 + 100 ms 3-10 are
// SACKed, so RACK finds the retransmissions of 1 and 2 (sent at t1 with
// lower ends) lost (reo_wnd 0 in Loss).
TEST(RackPipeline, LostRetransmissionInLossEntersRecovery) {
  Rig r(utcp::test::rig::linux_cfg());
  r.send_new(10);
  r.now += 400ms;
  r.fire_rto();
  ASSERT_EQ(r.rec.state(), CaState::loss);
  EXPECT_EQ(r.q.counters().lost_out, 10u);  // RACK.rtt unknown: all of them
  r.cc.cwnd = 10;
  EXPECT_EQ(r.transmit().size(), 9u);  // 2-10
  const Time t1 = r.now;
  r.now = t1 + 100ms;
  r.ack(1, {{3, 10}});
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_TRUE(r.pkt(1).lost);
  EXPECT_FALSE(r.pkt(1).retrans_inflight);
  EXPECT_TRUE(r.pkt(2).lost);
  EXPECT_EQ(r.q.counters().retrans_out, 0u);
  EXPECT_EQ(r.stats.TcpExtTCPSackRecovery, 1u);
}

// ---- Acceptance test 4: the D-SACK reorder window (M2-DESIGN §1.6).

// Packets 1-10 at t0; at +100 packet 1 is ACKed and 4 SACKed; at +101 the
// hole 2-3 is filled: two never-retransmitted packets delivered below the
// highest SACK (end of 4), a distance of 3 packets, not above reordering 3,
// so reordering stays 3 but reord_seen is 1 (tcp_check_sack_reordering).
// Five retransmissions are taken as sent before (total_retrans 5) so that
// D-SACKs pass the dsack_dups <= total_retrans test.
void make_reordered(Rig& r) {
  const Time t0 = r.now;
  r.send_new(10);
  r.ctr.total_retrans = 5;
  r.now = t0 + 100ms;
  r.ack(2, {{4, 4}});
  r.now = t0 + 101ms;
  r.ack(5);
  EXPECT_EQ(r.rec.reord_seen(), 1u);
  EXPECT_EQ(r.rec.reordering(r.cfg), 3u);
  EXPECT_EQ(r.rec.state(), CaState::open);
}

[[nodiscard]] Range dsack_of(std::uint32_t first, std::uint32_t last) {
  return Range{off_of(first), off_of(last + 1)};
}

// tcp_dsack_seen: a valid D-SACK sets dsack_seen once reordering was seen;
// not one of a TLP (FLAG_DSACK_TLP), one longer than the largest window the
// peer offered, or one with more duplicates than retransmissions. The ACKs
// below deliver nothing, so tcp_rack_update_reo_wnd returns at once and
// dsack_seen stays visible.
TEST(RackDsack, WhichDsacksCount) {
  {
    SCOPED_TRACE("valid");
    Rig r(utcp::test::rig::linux_cfg());
    make_reordered(r);
    r.ack(5, {}, dsack_of(3, 3));
    EXPECT_TRUE(r.rec.rack().dsack_seen);
    EXPECT_EQ(r.ctr.dsack_dups, 1u);
  }
  {
    SCOPED_TRACE("no reordering seen");
    Rig r(utcp::test::rig::linux_cfg());
    r.send_new(4);
    r.ctr.total_retrans = 5;
    r.now += 100ms;
    r.ack(2);
    r.ack(2, {}, dsack_of(1, 1));
    EXPECT_EQ(r.rec.reord_seen(), 0u);
    EXPECT_FALSE(r.rec.rack().dsack_seen);
    EXPECT_EQ(r.stats.TcpExtTCPDSACKRecvSegs, 1u);  // valid, but not reordering
  }
  {
    SCOPED_TRACE("TLP");
    // The PTO resends the last packet, 10 (tlp_high_seq = end of 10); its
    // D-SACK, at most one MSS ending at tlp_high_seq, is the probe's.
    Rig r(utcp::test::rig::linux_cfg());
    make_reordered(r);
    r.ctr.total_retrans = 0;
    EXPECT_EQ(r.fire_pto(), Sent{"P10"});
    ASSERT_EQ(r.rec.tlp_high_seq(), off_of(11));
    const auto out = r.ack(5, {}, dsack_of(10, 10));
    EXPECT_NE(out.flags & utcp::ack_dsack_tlp, 0u);
    EXPECT_NE(out.flags & utcp::ack_dsack, 0u);
    EXPECT_FALSE(r.rec.rack().dsack_seen);
  }
  {
    SCOPED_TRACE("longer than the max window");
    Rig r(utcp::test::rig::linux_cfg());
    make_reordered(r);
    r.max_snd_wnd = 1500;
    r.ack(5, {}, dsack_of(2, 3));  // 2000 bytes
    EXPECT_FALSE(r.rec.rack().dsack_seen);
    EXPECT_EQ(r.stats.TcpExtTCPDSACKIgnoredDubious, 1u);
  }
  {
    SCOPED_TRACE("more duplicates than retransmissions");
    Rig r(utcp::test::rig::linux_cfg());
    make_reordered(r);
    r.ctr.total_retrans = 0;
    r.ack(5, {}, dsack_of(3, 3));
    EXPECT_EQ(r.ctr.dsack_dups, 1u);  // counted before the test, as Linux
    EXPECT_FALSE(r.rec.rack().dsack_seen);
    EXPECT_EQ(r.stats.TcpExtTCPDSACKIgnoredDubious, 1u);
  }
}

// One recovery entered by the REO timer and left by a full ACK: packets k to
// k+3 at t; at t+100 k+1..k+3 are SACKed and k waits reo_wnd (reordering seen:
// min_rtt / 4 * steps); the timer marks it lost, Recovery, R<k>; a full ACK
// 100 ms later ends the recovery.
void recovery_episode(Rig& r) {
  const auto k = static_cast<std::uint32_t>(r.q.nxt() / mss + 1);
  const Time t = r.now;
  r.send_new(4);
  r.now = t + 100ms;
  r.ack(k, {{k + 1, k + 3}});
  ASSERT_EQ(r.timer().first, XmitTimer::reo);
  r.now = r.timer().second;
  ASSERT_EQ(r.fire_reo(), Sent{"R" + std::to_string(k)});
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  r.now += 100ms;
  r.ack(k + 4);
  ASSERT_EQ(r.rec.state(), CaState::open);
}

// tcp_rack_update_reo_wnd: a pending D-SACK raises reo_wnd_steps once per
// delivered round (not again until a packet sent after the last step is
// delivered), sets persist to 16; each end of a recovery counts persist down
// (tcp_try_undo_recovery without undo); with persist 0 and no D-SACK the
// next ACK resets the steps to 1.
TEST(RackDsack, StepsOncePerRoundAndPersistOverSixteenRecoveries) {
  Rig r(utcp::test::rig::linux_cfg());
  make_reordered(r);
  const Time t0 = r.now - 101ms;
  EXPECT_EQ(r.rec.rack().reo_wnd_steps, 1u);
  // +102: packet 5 ACKed with a D-SACK. Its snapshot (delivered 0 when sent
  // at t0) is not before last_delivered 0: steps 2, persist 16,
  // last_delivered = delivered after this ACK: 1 + 1 (first ACK) + 2 + 1 +
  // 1 D-SACKed = 6.
  r.now = t0 + 102ms;
  r.ack(6, {}, dsack_of(3, 3));
  EXPECT_EQ(r.rec.rack().reo_wnd_steps, 2u);
  EXPECT_EQ(r.rec.rack().reo_wnd_persist, 16u);
  EXPECT_EQ(r.rec.rack().last_delivered, 6u);
  EXPECT_FALSE(r.rec.rack().dsack_seen);
  // reo_wnd = min_rtt / 4 * 2 = 20 ms.
  // +103: packet 6 with another D-SACK: its snapshot 0 is before 6, less
  // than a round since the step: dropped, steps stay 2.
  r.now = t0 + 103ms;
  r.ack(7, {}, dsack_of(4, 4));
  EXPECT_EQ(r.rec.rack().reo_wnd_steps, 2u);
  EXPECT_FALSE(r.rec.rack().dsack_seen);
  // Packets 11-12 sent at +104 carry delivered 8 (6, then 1 + 1 D-SACKed).
  // +204: everything ACKed with a D-SACK; the newest delivered snapshot is
  // 8, not before 6: steps 3.
  r.now = t0 + 104ms;
  r.send_new(2);
  r.now = t0 + 204ms;
  r.ack(13, {}, dsack_of(5, 5));
  EXPECT_EQ(r.rec.rack().reo_wnd_steps, 3u);
  EXPECT_EQ(r.rec.rack().reo_wnd_persist, 16u);
  // Sixteen recoveries: steps stay 3 while persist counts 16 -> 0.
  for (int i = 0; i < 16; ++i) {
    SCOPED_TRACE(i);
    recovery_episode(r);
    if (HasFatalFailure()) {
      return;
    }
    EXPECT_EQ(r.rec.rack().reo_wnd_persist, 15u - static_cast<unsigned>(i));
    EXPECT_EQ(r.rec.rack().reo_wnd_steps, 3u);
  }
  // The next ACK that delivers something resets the steps.
  r.send_new(1);
  r.now += 100ms;
  r.ack(static_cast<std::uint32_t>(r.q.nxt() / mss + 1));
  EXPECT_EQ(r.rec.rack().reo_wnd_steps, 1u);
}

}  // namespace
