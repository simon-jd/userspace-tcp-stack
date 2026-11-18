#include "core/tcp/recovery.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/cc_newreno.hpp"
#include "core/tcp/rate.hpp"
#include "recovery_rig.hpp"

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
    cc.flavor = cfg.cc_flavor;
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
  // Partial ACK up to the SACKed run: with SACK it marks nothing by itself
  // (RFC 6675 IsLost only, M2-DESIGN §1.2); nothing is SACKed above 4000.
  r.ack(4000);
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_FALSE(r.at(4000).lost);
  EXPECT_EQ(r.q.counters().lost_out, 0u);
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

// ---- m2a-recovery acceptance tests 5 and 6 and the test faults (M2-DESIGN
// §1.7, §1.9; the rig drives process_ack, recovery_rig.hpp). Packet k is
// stream bytes [(k - 1) * 1000, k * 1000); "N<k>" new data, "R<k>" a
// retransmission, "P<k>" a probe resending k.

namespace rg = utcp::test::rig;
using Sent = std::vector<std::string>;

// srtt 20 ms from one sample: Linux rttvar = max(2 * 20 ms, rto_min) = 200 ms,
// RTO 220 ms.
void rtt20(rg::Rig& r) {
  r.set_rtt({20ms});
  ASSERT_EQ(r.rtt.rto(), 220ms);
}

// tcp_schedule_loss_probe after new data (transmit's on_burst_end).
TEST(RecoveryTlpSchedule, ProbeTimeouts) {
  {
    SCOPED_TRACE("3 packets: 2 * srtt + 2 ms = 42 ms");
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.write(3);
    EXPECT_EQ(r.transmit(), (Sent{"N1", "N2", "N3"}));
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, r.now + 42ms));
  }
  {
    SCOPED_TRACE("1 packet: min(2 * srtt + rto_min, RTO) = min(240, 220) = 220 ms");
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.write(1);
    EXPECT_EQ(r.transmit(), Sent{"N1"});
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, r.now + 220ms));
  }
  {
    SCOPED_TRACE("1 packet, RTO above 240 ms: 240 ms");
    // A first sample of 400 ms sets rttvar 800 ms, which no later sample
    // lowers without the end of a round (SND.UNA never passes rtt_seq here);
    // 400 samples of 20 ms bring srtt to 20 ms exactly, the RTO stays above
    // 800 ms.
    rg::Rig r(rg::linux_cfg());
    r.set_rtt({400ms});
    for (int i = 0; i < 400; ++i) {
      r.rtt.on_srtt_sample(20ms, 0, 0);
    }
    ASSERT_EQ(r.rtt.srtt(), 20ms);
    ASSERT_GT(r.rtt.rto(), 800ms);
    r.write(1);
    EXPECT_EQ(r.transmit(), Sent{"N1"});
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, r.now + 240ms));
  }
  {
    SCOPED_TRACE("srtt 300 ms: capped at the head's RTO expiry");
    // RTO = 300 + 600 = 900 ms. Packet 1 at t0: one packet, min(800, 900) =
    // 800 ms. Packets 2-3 at t0 + 500: min(602, time left to the head's RTO
    // 900 - 500 = 400) = 400 ms, i.e. t0 + 900.
    rg::Rig r(rg::linux_cfg());
    r.set_rtt({300ms});
    ASSERT_EQ(r.rtt.rto(), 900ms);
    const Time t0 = r.now;
    r.write(1);
    EXPECT_EQ(r.transmit(), Sent{"N1"});
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, t0 + 800ms));
    r.now = t0 + 500ms;
    r.write(2);
    EXPECT_EQ(r.transmit(), (Sent{"N2", "N3"}));
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, t0 + 900ms));
  }
  {
    SCOPED_TRACE("no RTT sample: 1 s (TCP_TIMEOUT_INIT)");
    rg::Rig r(rg::linux_cfg());
    r.rtt = utcp::RttEstimator(r.cfg);
    ASSERT_EQ(r.rtt.rto(), 1s);
    r.write(3);
    r.transmit();
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, r.now + 1s));
  }
  {
    SCOPED_TRACE("no RTT sample, RTO backed off to 2 s: 1 s, below the cap");
    rg::Rig r(rg::linux_cfg());
    r.rtt = utcp::RttEstimator(r.cfg);
    r.backoff = 1;
    ASSERT_EQ(r.rtt.rto_backed_off(1), 2s);
    r.write(3);
    r.transmit();
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, r.now + 1s));
  }
}

// No PTO without SACK, in Recovery or in Loss, or in the rfc profile.
TEST(RecoveryTlpSchedule, OnlyOpenOrCwrWithSack) {
  {
    SCOPED_TRACE("no SACK");
    rg::Rig r(rg::linux_cfg(), 14, false);
    rtt20(r);
    r.write(3);
    r.transmit();
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 220ms));
  }
  {
    SCOPED_TRACE("Recovery");
    rg::Rig r(rg::linux_cfg());
    r.send_new(10);
    r.now += 100ms;
    r.ack(1, {{2, 4}});
    ASSERT_EQ(r.rec.state(), CaState::recovery);
    auto c = r.rctx();
    r.rec.on_burst_end(c, true);
    EXPECT_EQ(r.timer().first, XmitTimer::rto);
  }
  {
    SCOPED_TRACE("Loss");
    rg::Rig r(rg::linux_cfg());
    r.send_new(2);
    r.now += 400ms;
    r.fire_rto();
    ASSERT_EQ(r.rec.state(), CaState::loss);
    auto c = r.rctx();
    r.rec.on_burst_end(c, true);
    EXPECT_EQ(r.timer().first, XmitTimer::rto);
  }
  {
    SCOPED_TRACE("rfc");
    rg::Rig r(rg::rfc_cfg());
    r.write(3);
    r.transmit();
    EXPECT_EQ(r.timer().first, XmitTimer::rto);
  }
}

// tcp_send_loss_probe: new data if the window takes it (past cwnd by one),
// else the last segment; tlp_high_seq = SND.NXT; at most one outstanding;
// the RTO a full RTO from now after a sent probe, the head's remaining time
// after a PTO that sends nothing.
TEST(RecoveryTlpProbe, NewDataOrLastSegmentAndOneOutstanding) {
  {
    SCOPED_TRACE("new data");
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.cc.cwnd = 3;
    const Time t0 = r.now;
    r.write(5);
    EXPECT_EQ(r.transmit(), (Sent{"N1", "N2", "N3"}));
    r.now = t0 + 42ms;
    EXPECT_EQ(r.fire_pto(), Sent{"N4"});
    EXPECT_EQ(r.in_flight(), 4u);  // cwnd 3 + 1
    EXPECT_EQ(r.rec.tlp_high_seq(), rg::off_of(5));
    EXPECT_EQ(r.stats.TcpExtTCPLossProbes, 1u);
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 220ms));
    // A second PTO (say from an ACK below tlp_high_seq) sends nothing; the
    // RTO gets the head's time left: sent at t0, t0 + 220 ms.
    r.now = t0 + 52ms;
    EXPECT_EQ(r.fire_pto(), Sent{});
    EXPECT_EQ(r.stats.TcpExtTCPLossProbes, 1u);
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 220ms));
  }
  {
    SCOPED_TRACE("last segment");
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.write(3);
    r.transmit();
    r.now += 42ms;
    EXPECT_EQ(r.fire_pto(), Sent{"P3"});
    EXPECT_EQ(r.rec.tlp_high_seq(), rg::off_of(4));
    EXPECT_EQ(r.pkt(3).tx_count, 2u);
    EXPECT_FALSE(r.pkt(3).retrans_inflight);  // __tcp_retransmit_skb alone
    EXPECT_EQ(r.in_flight(), 3u);
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 220ms));
  }
  {
    SCOPED_TRACE("last segment beyond a shrunk window");
    // __tcp_retransmit_skb resends nothing starting at or past SND.UNA +
    // SND.WND but the head.
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.write(3);
    r.transmit();
    r.now += 42ms;
    r.wnd = 1500;  // packet 3 starts at 2000
    EXPECT_EQ(r.fire_pto(), Sent{});
    EXPECT_EQ(r.rec.tlp_high_seq(), std::nullopt);
  }
}

// A PTO left pending into Recovery or Loss sends nothing (on_pto's own
// Open/CWR guard; RFC 8985 §7.2 and the simulator's TLP rule): no probe, no
// TcpExtTCPLossProbes, no tlp_high_seq.
TEST(RecoveryTlpProbe, NoProbeInRecoveryOrLoss) {
  {
    SCOPED_TRACE("Recovery");
    rg::Rig r(rg::linux_cfg());
    r.send_new(10);
    r.now += 100ms;
    r.ack(1, {{2, 4}});
    ASSERT_EQ(r.rec.state(), CaState::recovery);
    EXPECT_EQ(r.fire_pto(), Sent{});
    EXPECT_EQ(r.stats.TcpExtTCPLossProbes, 0u);
    EXPECT_EQ(r.rec.tlp_high_seq(), std::nullopt);
  }
  {
    SCOPED_TRACE("Loss");
    rg::Rig r(rg::linux_cfg());
    r.send_new(2);
    r.now += 400ms;
    r.fire_rto();
    ASSERT_EQ(r.rec.state(), CaState::loss);
    EXPECT_EQ(r.fire_pto(), Sent{});
    EXPECT_EQ(r.stats.TcpExtTCPLossProbes, 0u);
    EXPECT_EQ(r.rec.tlp_high_seq(), std::nullopt);
  }
}

// tcp_process_tlp_ack, once SND.UNA reaches tlp_high_seq.
TEST(RecoveryTlpAck, FourOutcomes) {
  {
    SCOPED_TRACE("new-data probe acknowledged");
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.cc.cwnd = 3;
    r.write(4);
    r.transmit();
    r.now += 42ms;
    ASSERT_EQ(r.fire_pto(), Sent{"N4"});
    r.now += 20ms;
    r.ack(5);
    EXPECT_EQ(r.rec.tlp_high_seq(), std::nullopt);
    EXPECT_EQ(r.cc.cwnd, 3u);
    EXPECT_EQ(r.stats.TcpExtTCPLossProbeRecovery, 0u);
  }
  {
    SCOPED_TRACE("D-SACK of the probe: no loss");
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.write(3);
    r.transmit();
    r.now += 42ms;
    ASSERT_EQ(r.fire_pto(), Sent{"P3"});
    r.now += 20ms;
    r.ack(4, {}, Range{rg::off_of(3), rg::off_of(4)});
    EXPECT_EQ(r.rec.tlp_high_seq(), std::nullopt);
    EXPECT_EQ(r.cc.cwnd, 20u);
    EXPECT_EQ(r.rec.state(), CaState::open);
    EXPECT_EQ(r.stats.TcpExtTCPLossProbeRecovery, 0u);
  }
  {
    SCOPED_TRACE("ACK above tlp_high_seq after a resent probe: a loss repaired");
    // init_cwnd_reduction (ssthresh 14), CWR, end_cwnd_reduction (cwnd =
    // ssthresh), back to Open.
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.write(3);
    r.transmit();
    r.now += 42ms;
    ASSERT_EQ(r.fire_pto(), Sent{"P3"});
    r.write(1);
    EXPECT_EQ(r.transmit(), Sent{"N4"});
    r.now += 20ms;
    r.ack(5);
    EXPECT_EQ(r.rec.tlp_high_seq(), std::nullopt);
    EXPECT_EQ(r.cc.ssthresh, 14u);
    EXPECT_EQ(r.cc.cwnd, 14u);
    EXPECT_EQ(r.rec.state(), CaState::open);
    EXPECT_EQ(r.stats.TcpExtTCPLossProbeRecovery, 1u);
    EXPECT_EQ(r.stats.TcpExtTCPLossProbes, 1u);
  }
  {
    SCOPED_TRACE("pure duplicate ACK: the original and the probe arrived");
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.write(3);
    r.transmit();
    r.now += 42ms;
    ASSERT_EQ(r.fire_pto(), Sent{"P3"});
    r.write(1);
    ASSERT_EQ(r.transmit(), Sent{"N4"});
    r.now += 20ms;
    r.ack(4);  // SND.UNA = tlp_high_seq, not a duplicate: kept
    EXPECT_EQ(r.rec.tlp_high_seq(), rg::off_of(4));
    r.ack(4);  // a pure duplicate (4 still out): cleared
    EXPECT_EQ(r.rec.tlp_high_seq(), std::nullopt);
    EXPECT_EQ(r.cc.cwnd, 20u);
    EXPECT_EQ(r.stats.TcpExtTCPLossProbeRecovery, 0u);
  }
}

// FLAG_SET_XMIT_TIMER for an ACK without cumulative progress: only when its
// SACK RTT sample is older than the head's last transmission (rfc, so no
// PTO or RACK timer: RTO 1 s).
TEST(RecoveryTlpTimers, SackOnlyAckRearmsOnlyUnderSetXmitTimer) {
  {
    SCOPED_TRACE("head not resent: SACK RTT 100 ms = the head's age, no re-arm");
    rg::Rig r(rg::rfc_cfg());
    const Time t0 = r.now;
    r.write(5);
    r.transmit();
    ASSERT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 1s));
    r.now = t0 + 100ms;
    r.ack(1, {{3, 3}});
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 1s));
  }
  {
    SCOPED_TRACE("head resent at +50: SACK RTT 100 ms > 50 ms, re-armed");
    rg::Rig r(rg::rfc_cfg());
    const Time t0 = r.now;
    r.write(5);
    r.transmit();
    r.now = t0 + 50ms;
    r.send_at(0, TxKind::rexmit);
    ASSERT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 1050ms));
    r.now = t0 + 100ms;
    r.ack(1, {{3, 3}});
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 1100ms));
  }
}

// on_burst_end schedules the PTO only when the transmit call sent new data.
TEST(RecoveryTlpTimers, BurstEndSchedulesOnlyAfterNewData) {
  rg::Rig r(rg::linux_cfg());
  rtt20(r);
  r.send_new(3);  // no burst end: the first transmission armed the RTO
  ASSERT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 220ms));
  auto c = r.rctx();
  r.rec.on_burst_end(c, false);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + 220ms));
  r.rec.on_burst_end(c, true);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, r.now + 42ms));
}

// tcp_pacing_delay with pacing_next 3.5 ms ahead: 3 ms (whole jiffies,
// truncated) on the PTO and on the RTO armed by tcp_rearm_rto's paths, not
// on the REO timer.
TEST(RecoveryTlpTimers, PacingDelay) {
  {
    rg::Rig r(rg::linux_cfg());
    rtt20(r);
    r.pacing_delay = 3500us;
    const Time t0 = r.now;
    r.write(3);
    r.transmit();
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::pto, t0 + 45ms));
    r.now = t0 + 45ms;
    ASSERT_EQ(r.fire_pto(), Sent{"P3"});
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 45ms + 223ms));
    // A PTO that sends nothing: the head's time left (t0 + 220) + 3 ms.
    r.now = t0 + 50ms;
    ASSERT_EQ(r.fire_pto(), Sent{});
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 223ms));
  }
  {
    SCOPED_TRACE("tcp_rearm_rto after an ACK (no SACK, so no PTO)");
    rg::Rig r(rg::linux_cfg(), 14, false);
    r.pacing_delay = 3500us;
    r.send_new(3);
    r.now += 20ms;
    r.ack(2);
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + r.rtt.rto_backed_off(0) + 3ms));
  }
  {
    SCOPED_TRACE("REO: no pacing delay");
    rg::Rig r(rg::linux_cfg());
    r.pacing_delay = 3500us;
    const Time t0 = r.now;
    r.send_new(10);
    r.now = t0 + 100ms;
    r.ack(1, {{2, 2}});
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::reo, t0 + 112ms));
  }
  {
    SCOPED_TRACE("head retransmission: + 3 ms; the RTO timer's own re-arm: none");
    // At t0 + 100 ms 2-4 are SACKed (reo_wnd 0 at 3 SACKed): 1 is lost and
    // no REO timer is armed. The head's retransmission 1 ms later re-arms a
    // full RTO plus the delay (tcp_xmit_retransmit_queue); the RTO expiry's
    // re-arm (tcp_retransmit_timer) gets the backed-off RTO without it.
    rg::Rig r(rg::linux_cfg());
    r.pacing_delay = 3500us;
    const Time t0 = r.now;
    r.send_new(10);
    r.now = t0 + 100ms;
    r.ack(1, {{2, 4}});
    ASSERT_EQ(r.rec.state(), CaState::recovery);
    ASSERT_EQ(r.timer().first, XmitTimer::rto);
    r.now = t0 + 101ms;
    EXPECT_EQ(r.transmit(), Sent{"R1"});
    const utcp::Duration rto = r.rtt.rto_backed_off(0);
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, t0 + 101ms + rto + 3ms));
    r.now = r.timer().second;
    ASSERT_EQ(r.fire_rto().front(), "R1");
    EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + r.rtt.rto_backed_off(1)));
  }
}

// TestFault::double_tlp: on_pto ignores tlp_high_seq.
TEST(RecoveryTestFaults, DoubleTlpSendsASecondProbe) {
  for (const bool fault : {false, true}) {
    SCOPED_TRACE(fault);
    utcp::TcpConfig cfg = rg::linux_cfg();
    cfg.test_fault = fault ? utcp::TestFault::double_tlp : utcp::TestFault::none;
    rg::Rig r(cfg);
    rtt20(r);
    r.write(3);
    r.transmit();
    r.now += 42ms;
    EXPECT_EQ(r.fire_pto(), Sent{"P3"});
    r.now += 10ms;
    EXPECT_EQ(r.fire_pto(), fault ? Sent{"P3"} : Sent{});
    EXPECT_EQ(r.stats.TcpExtTCPLossProbes, fault ? 2u : 1u);
  }
}

// TestFault::prr_skip_force: PRR gives the first retransmission no room and
// it bypasses the cwnd gate. The PRR script's entry (prr_test.cpp): in_flight
// 16, delta -2; with the fault sndcnt = (14 * 1 + 19) / 20 - 1 = 0, cwnd 16,
// and R1 goes out exempt: in_flight 17 > cwnd. Without it cwnd 17.
TEST(RecoveryTestFaults, PrrSkipForceBypassesTheCwndGate) {
  for (const bool fault : {false, true}) {
    SCOPED_TRACE(fault);
    utcp::TcpConfig cfg = rg::linux_cfg();
    cfg.test_fault = fault ? utcp::TestFault::prr_skip_force : utcp::TestFault::none;
    rg::Rig r(cfg);
    const Time t0 = r.now;
    r.send_new(20);
    r.now = t0 + 100ms;
    r.ack(1, {{2, 2}});
    r.now = t0 + 101ms;
    r.ack(1, {{2, 3}});
    r.now = t0 + 102ms;
    r.ack(1, {{2, 4}});
    ASSERT_EQ(r.rec.state(), CaState::recovery);
    EXPECT_EQ(r.cc.cwnd, fault ? 16u : 17u);
    auto c = r.rctx();
    EXPECT_EQ(r.rec.exempt_from_cwnd(c, r.pkt(1)), fault);
    EXPECT_EQ(r.transmit(), Sent{"R1"});
    EXPECT_EQ(r.in_flight(), 17u);
    // Only the first retransmission of the recovery.
    auto d = r.rctx();
    EXPECT_FALSE(r.rec.exempt_from_cwnd(d, r.pkt(1)));
  }
}

// ---- Acceptance test 6: adaptive reordering (M2-DESIGN §1.9).

// Packets 1-10 at t0; at +100 1-2 are ACKed and 7 SACKed (fack = end of 7);
// at +101 the hole 3-6 is filled by a cumulative ACK: never-retransmitted
// packets delivered below the prior fack, low = start of 3, fack = SND.UNA =
// end of 7 (nothing SACKed is left): 5 packets > reordering 3, so
// reordering = ceil(5000 / 1000) = 5 (tcp_check_sack_reordering), capped at
// max_reordering; rfc (no adaptive reordering) keeps DupThresh 3.
TEST(RecoveryAdaptiveReordering, HoleFilledFivePacketsBelowFack) {
  struct Case {
    const char* name;
    utcp::TcpConfig cfg;
    std::uint32_t want;
  };
  utcp::TcpConfig capped = rg::linux_cfg();
  capped.max_reordering = 4;
  for (const Case& k : {Case{"linux_compat", rg::linux_cfg(), 5}, Case{"max 4", capped, 4},
                        Case{"rfc", rg::rfc_cfg(), 3}}) {
    SCOPED_TRACE(k.name);
    rg::Rig r(k.cfg);
    const Time t0 = r.now;
    r.send_new(10);
    r.now = t0 + 100ms;
    r.ack(3, {{7, 7}});
    EXPECT_EQ(r.rec.reord_seen(), 0u);
    r.now = t0 + 101ms;
    r.ack(8);
    EXPECT_EQ(r.rec.reordering(r.cfg), k.want);
    EXPECT_EQ(r.rec.reord_seen(), 1u);
    EXPECT_EQ(r.stats.TcpExtTCPSACKReorder, 1u);
  }
}

// The degree is rounded up to whole packets (tcp_check_sack_reordering:
// DIV_ROUND_UP(fack - low, mss)). Packets 1-10 at t0, packet 7 cut into
// [6000, 6500) and [6500, 7000); at +100 1-2 are ACKed and [6000, 6500)
// SACKed (fack 6500); at +101 the hole 3-6 is filled: fack - low = 6500 -
// 2000 = 4500 > 3 * 1000, so reordering = ceil(4.5) = 5, not 4.
TEST(RecoveryAdaptiveReordering, DegreeRoundsUpToWholePackets) {
  rg::Rig r(rg::linux_cfg());
  const Time t0 = r.now;
  r.send_new(10);
  r.q.split(rg::off_of(7), 500);
  r.now = t0 + 100ms;
  r.ack_bytes(rg::off_of(3), {Range{6000, 6500}});
  ASSERT_TRUE(r.q.find(6000)->sacked);
  ASSERT_FALSE(r.q.find(6500)->sacked);
  EXPECT_EQ(r.rec.reord_seen(), 0u);
  r.now = t0 + 101ms;
  r.ack(7);
  EXPECT_EQ(r.rec.reordering(r.cfg), 5u);
  EXPECT_EQ(r.rec.reord_seen(), 1u);
}

// tcp_may_raise_cwnd: with reordering above DupThresh any forward progress
// (here a SACK-only ACK) lets cong_avoid run; at DupThresh only cumulative
// progress does. An RTO in Disorder with sacked_out >= DupThresh sets
// reordering back to min(reordering, DupThresh) (tcp_enter_loss).
TEST(RecoveryAdaptiveReordering, ForwardProgressAndRtoReset) {
  rg::Rig r(rg::linux_cfg());
  const Time t0 = r.now;
  r.send_new(12);
  r.now = t0 + 100ms;
  r.ack(3, {{7, 7}});
  r.now = t0 + 101ms;
  r.ack(8);
  ASSERT_EQ(r.rec.reordering(r.cfg), 5u);
  // +150: 9-11 SACKed, 8 the hole (3 SACKed < reordering 5, and reo_wnd is
  // min_rtt / 4 = 10 ms with reordering seen: not lost yet).
  const int before = r.algo.cong_avoids;
  r.now = t0 + 150ms;
  r.ack(8, {{9, 11}});
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  EXPECT_EQ(r.q.counters().sacked_out, 3u);
  EXPECT_EQ(r.algo.cong_avoids, before + 1);
  r.now = t0 + 151ms;
  r.fire_rto();
  EXPECT_EQ(r.rec.reordering(r.cfg), 3u);

  // No reordering seen: the same kind of SACK-only ACK does not raise cwnd.
  rg::Rig f(rg::linux_cfg());
  f.send_new(12);
  f.now += 100ms;
  f.ack(1, {{2, 3}});
  ASSERT_EQ(f.rec.state(), CaState::disorder);
  EXPECT_EQ(f.algo.cong_avoids, 0);
}

// Without SACK (tcp_check_reno_reordering): 4 packets out, 3 duplicate ACKs
// enter Recovery (head lost); a 4th would make sacked_out 4 + 1 hole > 4
// packets out: capped at 3 (tcp_limit_reno_sacked), and reordering =
// packets_out + 0 = 4.
TEST(RecoveryAdaptiveReordering, RenoMoreDupacksThanPacketsOut) {
  rg::Rig r(rg::linux_cfg(), 14, false);
  r.send_new(4);
  r.now += 100ms;
  for (int i = 0; i < 3; ++i) {
    r.ack(1);
  }
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.rec.reord_seen(), 0u);
  r.ack(1);
  EXPECT_EQ(r.q.counters().sacked_out, 3u);
  EXPECT_EQ(r.rec.reordering(r.cfg), 4u);
  EXPECT_EQ(r.rec.reord_seen(), 1u);
  EXPECT_EQ(r.stats.TcpExtTCPRenoReorder, 1u);
}

}  // namespace
