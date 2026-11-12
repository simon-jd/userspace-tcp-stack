#include "core/tcp/recovery.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <utility>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/cc_newreno.hpp"
#include "core/tcp/rate.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::AckInput;
using utcp::AckOutcome;
using utcp::CaState;
using utcp::Range;
using utcp::Time;
using utcp::TxKind;
using utcp::TxSeg;
using utcp::XmitTimer;

constexpr std::uint32_t seg_len = 1000;

// A connection's send side driven by scripted ACKs. The ACK steps are those
// of process_ack (SACK tagging, cumulative cleanup, then on_ack), written out
// here so that recovery is tested on its own.
struct Rig {
  explicit Rig(bool sack_ok) : sack(sack_ok) {
    q.set_sack_ok(sack_ok);
    cc.cwnd = 10;
    cc.ssthresh = utcp::cwnd_infinite;
    cc.mss = seg_len;
  }

  utcp::RecoveryCtx ctx() {
    return utcp::RecoveryCtx{q,   cc,      algo,  rtt,  cfg,      now,
                             wnd, stats, sack, backoff, rto_count};
  }

  // Writes and sends n new segments.
  void send(int n) {
    const std::vector<std::byte> data(static_cast<std::size_t>(n) * seg_len);
    ASSERT_EQ(q.write(data), data.size());
    for (int i = 0; i < n; ++i) {
      utcp::rate_on_send(rate, q.counters().packets_out, now);
      const TxSeg& s = q.on_transmit(q.nxt(), seg_len, false, now, rate);
      auto c = ctx();
      rec.on_transmit(c, s, TxKind::data);
    }
  }

  void resend(std::uint64_t off, TxKind kind) {
    const TxSeg& s = q.on_transmit(off, seg_len, false, now, rate);
    auto c = ctx();
    rec.on_transmit(c, s, kind);
  }

  AckOutcome ack(std::uint64_t una, std::initializer_list<Range> blocks = {}, bool dupack = false) {
    AckOutcome out;
    const std::uint64_t prior_una = q.una();
    const std::vector<Range> sacks(blocks);
    out.prior_in_flight = utcp::packets_in_flight(q.counters());
    const auto none = [](const TxSeg&, bool) {};
    out.newly_sacked = q.on_sack(sacks, now, none).newly_sacked;
    const utcp::AckedSummary a = q.on_cumulative_ack(una, now, none);
    out.acked_pkts = a.pkts;
    if (una > prior_una) {
      out.flags |= utcp::ack_una_advanced;
      rto_count = 0;
    }
    if (a.stopped_at_sacked) {
      out.flags |= utcp::ack_sack_reneging;
    }
    AckInput in;
    in.now = now;
    in.prior_una = prior_una;
    in.new_una = una;
    in.sack = sacks;
    in.dupack = dupack;
    auto c = ctx();
    rec.on_ack(c, in, out);
    return out;
  }

  void dupack() { ack(q.una(), {}, true); }

  void rto() {
    auto c = ctx();
    rec.on_rto(c);
    ++backoff;  // the engine's part of an expiry (§4.8)
    ++rto_count;
  }

  const TxSeg& at(std::uint64_t off) const {
    const TxSeg* s = q.find(off);
    EXPECT_NE(s, nullptr) << off;
    return *s;
  }

  std::pair<XmitTimer, Time> timer() {
    auto c = ctx();
    return rec.xmit_timer(c);
  }

  bool sack;
  utcp::TcpConfig cfg = utcp::tcp_config(utcp::ProfileId::rfc);  // rto 1 s, dupthresh 3
  utcp::ChunkPool pool{64};
  utcp::SendQueue q{pool, 1 << 20};
  utcp::RttEstimator rtt{cfg};
  utcp::NewReno algo;
  utcp::CcConn cc;
  utcp::StackStats stats;
  utcp::RateState rate;
  utcp::LossRecovery rec;
  Time now{1'000'000'000};
  std::uint32_t wnd = 1 << 20;
  std::uint8_t backoff = 0, rto_count = 0;
};

TEST(Recovery, RenoThreeDupacksPartialAndFullAck) {
  Rig r(false);
  r.send(10);
  r.dupack();
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  r.dupack();
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  EXPECT_FALSE(r.at(0).lost);
  r.dupack();
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.rec.recover(), 10'000u);  // SND.NXT
  EXPECT_TRUE(r.at(0).lost);
  EXPECT_TRUE(r.rec.fast_rexmit_pending());
  EXPECT_EQ(r.cc.ssthresh, 5u);  // FlightSize 10 / 2
  EXPECT_EQ(r.cc.cwnd, 5u);
  EXPECT_EQ(r.cc.prior_cwnd, 10u);
  EXPECT_EQ(r.stats.TcpExtTCPRenoRecovery, 1u);
  EXPECT_EQ(r.q.counters().sacked_out, 3u);
  // in_flight = 10 - (3 + 1) = 6 > cwnd: the fast retransmit skips the gate.
  EXPECT_EQ(r.cc.in_flight, 6u);
  r.resend(0, TxKind::fast_rexmit);
  EXPECT_FALSE(r.rec.fast_rexmit_pending());
  EXPECT_EQ(r.stats.TcpExtTCPFastRetrans, 1u);
  // More dupacks drain the pipe; sacked_out stops at packets_out - 1.
  for (int i = 0; i < 10; ++i) {
    r.dupack();
  }
  EXPECT_EQ(r.q.counters().sacked_out, 9u);
  // Partial ACK: the next segment is lost.
  const AckOutcome p = r.ack(3000);
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_TRUE(r.at(3000).lost);
  EXPECT_FALSE(r.at(4000).lost);
  EXPECT_EQ(p.acked_pkts, 3u);
  // An ACK of exactly recover holds Recovery without SACK (RFC 6582).
  r.send(2);
  r.ack(10'000);
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  // Above recover: Open, cwnd = ssthresh.
  r.cc.cwnd = 9;
  r.ack(11'000);
  EXPECT_EQ(r.rec.state(), CaState::open);
  EXPECT_EQ(r.cc.cwnd, 5u);
  EXPECT_FALSE(r.rec.recover().has_value());
  r.q.check_invariants();
}

TEST(Recovery, SackThreeSackedSegmentsEnterRecovery) {
  Rig r(true);
  r.send(10);
  r.ack(0, {{1000, 2000}}, true);
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  r.ack(0, {{1000, 3000}}, true);
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  EXPECT_FALSE(r.at(0).lost);
  r.ack(0, {{1000, 4000}}, true);
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.rec.recover(), 10'000u);
  EXPECT_TRUE(r.at(0).lost);
  EXPECT_TRUE(r.rec.fast_rexmit_pending());
  EXPECT_EQ(r.cc.cwnd, 5u);
  EXPECT_EQ(r.stats.TcpExtTCPSackRecovery, 1u);
  EXPECT_EQ(r.stats.TcpExtTCPRenoRecovery, 0u);
  // The SND.UNA segment resent while the RTO runs re-arms it (Linux
  // tcp_xmit_retransmit_queue), so a late fast retransmit is not followed
  // by an RTO at the first deadline.
  const Time first_deadline = r.timer().second;
  r.now += 500ms;
  r.resend(0, TxKind::fast_rexmit);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + r.rtt.rto_backed_off(r.backoff)));
  EXPECT_NE(r.timer().second, first_deadline);
  // Partial ACK up to the SACKed run: SND.UNA = 4000 is marked lost.
  r.ack(4000);
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_TRUE(r.at(4000).lost);
  EXPECT_EQ(r.q.counters().lost_out, 1u);
  // Full ACK: Open, cwnd = ssthresh.
  r.cc.cwnd = 8;
  r.ack(10'000);
  EXPECT_EQ(r.rec.state(), CaState::open);
  EXPECT_EQ(r.cc.cwnd, 5u);
  // Two SACKed segments are not enough.
  Rig s(true);
  s.send(10);
  s.ack(0, {{1000, 3000}}, true);
  EXPECT_EQ(s.rec.state(), CaState::disorder);
  EXPECT_EQ(s.q.counters().lost_out, 0u);
  // Only a retransmission of the SND.UNA segment re-arms the running RTO.
  Rig t(true);
  t.send(4);
  const Time deadline = t.timer().second;
  t.now += 300ms;
  t.resend(2000, TxKind::rexmit);
  EXPECT_EQ(t.timer(), std::make_pair(XmitTimer::rto, deadline));
  t.resend(0, TxKind::rexmit);
  EXPECT_EQ(t.timer(), std::make_pair(XmitTimer::rto, t.now + 1s));
}

TEST(Recovery, RtoMarksEveryNonSackedSegmentLost) {
  Rig r(true);
  r.send(10);
  r.ack(0, {{5000, 6000}}, true);
  ASSERT_EQ(r.rec.state(), CaState::disorder);
  r.rto();
  EXPECT_EQ(r.rec.state(), CaState::loss);
  EXPECT_EQ(r.cc.cwnd, 1u);
  EXPECT_EQ(r.cc.ssthresh, 5u);
  EXPECT_EQ(r.rec.recover(), 10'000u);
  EXPECT_EQ(r.q.counters().lost_out, 9u);
  EXPECT_EQ(r.q.counters().sacked_out, 1u);
  EXPECT_TRUE(r.at(5000).sacked);
  EXPECT_FALSE(r.at(5000).lost);
  EXPECT_EQ(r.stats.TcpExtTCPTimeouts, 1u);
  EXPECT_EQ(r.stats.TcpExtTCPSACKReneging, 0u);
  EXPECT_FALSE(r.rec.sack_reneg());
  EXPECT_EQ(r.timer().first, XmitTimer::none);  // until the rto_rexmit
  r.resend(0, TxKind::rto_rexmit);
  EXPECT_EQ(r.stats.TcpExtTCPSlowStartRetrans, 0u);  // the RTO's own resend
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 2s));  // backoff 1
  r.resend(1000, TxKind::rexmit);
  EXPECT_EQ(r.stats.TcpExtTCPSlowStartRetrans, 1u);
  // Without SACK the dupack count goes too.
  Rig n(false);
  n.send(4);
  n.dupack();
  n.dupack();
  ASSERT_EQ(n.q.counters().sacked_out, 2u);
  n.rto();
  EXPECT_EQ(n.q.counters().sacked_out, 0u);
  EXPECT_EQ(n.q.counters().lost_out, 4u);
  EXPECT_EQ(n.cc.cwnd, 1u);
}

TEST(Recovery, RepeatedRtoKeepsSsthresh) {
  Rig r(true);
  r.send(10);
  r.rto();
  ASSERT_EQ(r.cc.ssthresh, 5u);
  r.send(10);  // FlightSize 20 now
  r.rto();     // rto_count 1: the same episode
  EXPECT_EQ(r.cc.ssthresh, 5u);
  EXPECT_EQ(r.rec.recover(), 20'000u);
  EXPECT_EQ(r.cc.cwnd, 1u);
  // SND.UNA advanced (rto_count 0) but stays below recover: a new RTO in
  // Loss recomputes it (Linux tcp_enter_loss, !icsk_retransmits).
  r.ack(1000);
  r.rto();
  EXPECT_EQ(r.cc.ssthresh, 9u);  // 19 / 2
}

TEST(Recovery, RtoDuringRecoveryKeepsSsthresh) {
  Rig r(true);
  r.send(10);
  r.ack(0, {{1000, 4000}}, true);
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  ASSERT_EQ(r.cc.ssthresh, 5u);
  r.send(10);
  r.rto();
  EXPECT_EQ(r.rec.state(), CaState::loss);
  EXPECT_EQ(r.cc.ssthresh, 5u);  // 10 if recomputed
  EXPECT_EQ(r.rec.recover(), 20'000u);
  EXPECT_FALSE(r.rec.fast_rexmit_pending());
}

TEST(Recovery, RtoWithSackedHeadClearsEverySackMark) {
  Rig r(true);
  r.cfg = utcp::tcp_config(utcp::ProfileId::linux_compat);
  r.rtt = utcp::RttEstimator(r.cfg);
  r.rtt.on_srtt_sample(100ms, 0, 1);
  r.send(10);
  r.ack(0, {{1000, 3000}, {6000, 7000}}, true);
  // The receiver acknowledges 1000 but not the SACKed 1000-3000 above it.
  const AckOutcome a = r.ack(1000);
  EXPECT_NE(a.flags & utcp::ack_sack_reneging, 0u);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 50ms));  // srtt / 2
  r.rto();
  EXPECT_EQ(r.stats.TcpExtTCPSACKReneging, 1u);
  EXPECT_TRUE(r.rec.sack_reneg());  // rate samples invalid
  EXPECT_EQ(r.q.counters().sacked_out, 0u);
  EXPECT_EQ(r.q.counters().lost_out, 9u);
  EXPECT_TRUE(r.at(1000).lost);
  EXPECT_FALSE(r.at(6000).sacked);
  EXPECT_EQ(r.cc.cwnd, 1u);
  // Still reneged in Loss; cleared once recovery ends.
  r.ack(5000);
  EXPECT_TRUE(r.rec.sack_reneg());
  r.ack(10'000);
  EXPECT_EQ(r.rec.state(), CaState::open);
  EXPECT_FALSE(r.rec.sack_reneg());
  // A short srtt gives the 10 ms floor.
  Rig s(true);
  s.rtt.on_srtt_sample(4ms, 0, 1);
  s.send(4);
  s.ack(0, {{1000, 2000}}, true);
  s.ack(1000);
  EXPECT_EQ(s.timer(), std::make_pair(XmitTimer::rto, s.now + 10ms));
}

TEST(Recovery, PmtuDropEntersLossWithoutCwndCut) {
  Rig r(true);
  r.send(5);
  r.cc.cwnd = 10;
  r.cc.ssthresh = 4;
  r.cc.mss = 600;
  auto c = r.ctx();
  r.rec.on_pmtu_drop(c);
  EXPECT_EQ(r.rec.state(), CaState::loss);
  EXPECT_EQ(r.cc.cwnd, 10u);
  EXPECT_EQ(r.cc.ssthresh, 7u);  // max(4, 3/4 * 10)
  EXPECT_EQ(r.rec.recover(), 5000u);
  EXPECT_EQ(r.q.counters().packets_out, 10u);  // split 600 + 400
  EXPECT_EQ(r.q.counters().lost_out, 10u);
  for (const TxSeg& s : r.q.segs()) {
    EXPECT_LE(s.len, 600u);
  }
  // In Recovery with the fast retransmit not yet sent: Loss drops it, the
  // head is resent under cwnd as an ordinary lost segment (§4.9, §4.13).
  Rig f(true);
  f.send(10);
  f.ack(0, {{1000, 4000}}, true);
  ASSERT_EQ(f.rec.state(), CaState::recovery);
  ASSERT_TRUE(f.rec.fast_rexmit_pending());
  f.cc.mss = 600;
  auto e = f.ctx();
  f.rec.on_pmtu_drop(e);
  EXPECT_EQ(f.rec.state(), CaState::loss);
  EXPECT_FALSE(f.rec.fast_rexmit_pending());
  EXPECT_TRUE(f.at(0).lost);
  // Nothing longer than the MSS: no state change.
  Rig n(true);
  n.send(3);
  n.cc.mss = 1200;
  auto d = n.ctx();
  n.rec.on_pmtu_drop(d);
  EXPECT_EQ(n.rec.state(), CaState::open);
  EXPECT_EQ(n.q.counters().lost_out, 0u);
}

TEST(Recovery, XmitTimerRtoAndPersist) {
  Rig r(true);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::none, Time::never()));
  r.send(2);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 1s));
  // Later sends do not restart it (RFC 6298 §5.1); an ACK of new data does.
  r.now += 300ms;
  r.send(1);
  EXPECT_EQ(r.timer().second, r.now - 300ms + 1s);
  r.now += 100ms;
  r.ack(1000);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 1s));
  // All acknowledged, data queued, zero window: persist at the backed-off RTO.
  const std::vector<std::byte> more(500);
  ASSERT_EQ(r.q.write(more), 500u);
  r.wnd = 0;
  r.backoff = 1;
  r.ack(3000);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::persist, r.now + 2s));
  // After the probe the engine raises backoff; transmit's end re-arms.
  r.now += 2s;
  r.backoff = 2;
  auto c = r.ctx();
  r.rec.on_burst_end(c);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::persist, r.now + 4s));
  // A window below min(unsent, mss) is the SWS override.
  r.wnd = 400;
  r.ack(3000);
  EXPECT_EQ(r.timer().first, XmitTimer::persist);
  // A usable window: no timer until something is sent.
  r.wnd = 500;
  r.ack(3000);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::none, Time::never()));
  // Nothing queued at a zero window: none.
  Rig e(true);
  e.send(1);
  e.wnd = 0;
  e.ack(1000);
  EXPECT_EQ(e.timer().first, XmitTimer::none);
}

}  // namespace
