#include "core/tcp/ack_pipeline.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/cc_newreno.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::AckInput;
using utcp::AckOutcome;
using utcp::CaState;
using utcp::Duration;
using utcp::Range;
using utcp::Time;
using utcp::TxKind;
using utcp::TxSeg;

constexpr std::uint32_t mss = 1000;

const char* state_name(CaState s) {
  switch (s) {
    case CaState::open: return "open";
    case CaState::disorder: return "disorder";
    case CaState::cwr: return "cwr";
    case CaState::recovery: return "recovery";
    case CaState::loss: return "loss";
  }
  return "?";
}

// NewReno doing the work, with its hook calls logged in order.
class Probe final : public utcp::CongestionControl {
public:
  [[nodiscard]] std::string_view name() const override { return reno.name(); }
  std::uint32_t ssthresh(const utcp::CcConn& c) override { return reno.ssthresh(c); }
  void cong_avoid(utcp::CcConn& c, const AckOutcome& out) override {
    log.push_back("cong_avoid " + std::to_string(out.delivered));
    reno.cong_avoid(c, out);
  }
  void pkts_acked(utcp::CcConn& c, const utcp::AckSample& s) override {
    log.push_back("pkts_acked " + std::to_string(s.pkts_acked) + " " + state_name(c.ca_state));
  }
  void set_state(utcp::CcConn&, CaState s) override {
    log.push_back(std::string("set_state ") + state_name(s));
  }

  utcp::NewReno reno;
  std::vector<std::string> log;
};

struct Rig {
  explicit Rig(bool sack_ok) : sack(sack_ok) {
    q.set_sack_ok(sack_ok);
    cc.cwnd = 10;
    cc.ssthresh = utcp::cwnd_infinite;
    cc.mss = mss;
    cc.cwnd_limited = true;
  }

  utcp::RecoveryCtx rctx() {
    return utcp::RecoveryCtx{q, cc, algo, rtt, cfg, now, wnd, stats, sack, backoff, 0};
  }

  // Sends one segment of `len` bytes at `now` (new data or a retransmission).
  void send(std::uint64_t off, std::uint32_t len, TxKind kind, bool fin = false) {
    if (off == q.end()) {
      const std::vector<std::byte> data(len);
      ASSERT_EQ(q.write(data), len);
    }
    utcp::rate_on_send(rate, q.counters().packets_out, now);
    const TxSeg& s = q.on_transmit(off, len, fin, now, rate);
    auto c = rctx();
    rec.on_transmit(c, s, kind);
  }

  // n full segments, 1 ms apart.
  void send_spaced(int n) {
    for (int i = 0; i < n; ++i) {
      send(q.nxt(), mss, TxKind::data);
      now += 1ms;
    }
  }

  AckInput input(std::uint64_t una) const {
    AckInput in;
    in.now = now;
    in.prior_una = q.una();
    in.new_una = una;
    return in;
  }

  AckOutcome run(const AckInput& in) {
    utcp::AckContext c{q, rec, rtt, cc, algo, rate, cfg, stats, ctr, wnd, sack, backoff, 0};
    const AckOutcome out = utcp::process_ack(c, in, [this](const TxSeg& s, bool via_sack) {
      delivered_log.emplace_back(s.off, via_sack);
    });
    if (out.seq_rtt >= Duration::zero()) {
      backoff = 0;
    }
    return out;
  }

  AckOutcome ack(std::uint64_t una, const std::vector<Range>& blocks = {}, bool dupack = false) {
    AckInput in = input(una);
    in.sack = blocks;
    in.dupack = dupack;
    return run(in);
  }

  bool sack;
  utcp::TcpConfig cfg = utcp::tcp_config(utcp::ProfileId::linux_compat);
  utcp::ChunkPool pool{64};
  utcp::SendQueue q{pool, 1 << 20};
  utcp::RttEstimator rtt{cfg};
  Probe algo;
  utcp::CcConn cc;
  utcp::RateState rate;
  utcp::StackStats stats;
  utcp::TcpCounters ctr;
  utcp::LossRecovery rec;
  Time now{1'000'000'000};
  std::uint32_t wnd = 1 << 20;
  std::uint8_t backoff = 0;
  std::vector<std::pair<std::uint64_t, bool>> delivered_log;  // (off, via_sack) per delivery
};

TEST(AckPipeline, ScriptedSackSequence) {
  Rig r(true);
  const Time t0 = r.now;
  r.send_spaced(10);  // segment i sent at t0 + i ms

  // 1. Cumulative ACK of one segment: seq_rtt = ca_rtt from it; slow start.
  r.now = t0 + 100ms;
  AckOutcome o = r.ack(1000);
  EXPECT_EQ(o.seq_rtt, 100ms);
  EXPECT_EQ(o.ca_rtt, 100ms);
  EXPECT_EQ(o.delivered, 1u);
  EXPECT_EQ(o.acked_pkts, 1u);
  EXPECT_NE(o.flags & utcp::ack_una_advanced, 0u);
  EXPECT_EQ(r.cc.cwnd, 11u);
  EXPECT_EQ(r.rtt.srtt(), 100ms);
  EXPECT_EQ(r.algo.log, (std::vector<std::string>{"pkts_acked 1 open", "cong_avoid 1"}));
  r.algo.log.clear();

  // 2. Cumulative + SACK in one ACK: the SACKed segments count as delivered
  // once, seq_rtt is from the first cumulatively acked segment (sent at 1
  // ms), ca_rtt from the last SACKed one (4 ms).
  r.now = t0 + 110ms;
  const std::vector<Range> b2{{3000, 5000}};
  o = r.ack(2000, b2);
  EXPECT_EQ(o.newly_sacked, 2u);
  EXPECT_EQ(o.acked_pkts, 1u);
  EXPECT_EQ(o.delivered, 3u);
  EXPECT_EQ(o.seq_rtt, 109ms);
  EXPECT_EQ(o.ca_rtt, 106ms);
  EXPECT_NE(o.flags & utcp::ack_orig_sack_acked, 0u);
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  EXPECT_EQ(r.cc.cwnd, 14u);
  EXPECT_EQ(r.algo.log, (std::vector<std::string>{"pkts_acked 1 open", "set_state disorder",
                                                  "cong_avoid 3"}));
  r.algo.log.clear();

  // 3. A third SACKed segment: pkts_acked sees the state before on_ack
  // enters Recovery; seq_rtt falls back to the first newly SACKed segment.
  r.now = t0 + 120ms;
  const std::vector<Range> b3{{3000, 6000}};
  o = r.ack(2000, b3, true);
  EXPECT_EQ(o.newly_sacked, 1u);
  EXPECT_EQ(o.seq_rtt, 115ms);  // segment 5 sent at 5 ms
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_TRUE(r.q.find(2000)->lost);
  EXPECT_EQ(r.cc.ssthresh, 4u);  // FlightSize 8 / 2
  EXPECT_EQ(r.cc.cwnd, 4u);
  EXPECT_EQ(r.algo.log,
            (std::vector<std::string>{"pkts_acked 0 disorder", "set_state recovery"}));
  r.algo.log.clear();

  // 4. The retransmitted segment is acknowledged: no seq_rtt (Karn), and no
  // TSecr on this ACK. A partial ACK: the new head is lost.
  r.send(2000, mss, TxKind::fast_rexmit);
  r.now = t0 + 200ms;
  r.backoff = 2;
  o = r.ack(6000);
  EXPECT_EQ(o.seq_rtt, Duration{-1});
  EXPECT_EQ(o.ca_rtt, Duration{-1});
  EXPECT_NE(o.flags & utcp::ack_retrans_data_acked, 0u);
  EXPECT_EQ(o.acked_pkts, 4u);
  EXPECT_EQ(o.delivered, 1u);  // 3000-6000 were delivered by SACK before
  EXPECT_EQ(r.backoff, 2u);
  EXPECT_TRUE(r.q.find(6000)->lost);
  EXPECT_EQ(r.algo.log, (std::vector<std::string>{"pkts_acked 4 recovery"}));  // no growth
  r.algo.log.clear();

  // 5. Full ACK: Open with cwnd = ssthresh, then congestion avoidance on
  // the delivered packets of the same ACK.
  r.now = t0 + 300ms;
  o = r.ack(10'000);
  EXPECT_EQ(r.rec.state(), CaState::open);
  EXPECT_EQ(o.delivered, 4u);
  EXPECT_EQ(r.cc.cwnd, 5u);  // 4, then cwnd_cnt 4 >= 4
  EXPECT_EQ(r.algo.log, (std::vector<std::string>{"pkts_acked 4 recovery", "set_state open",
                                                  "cong_avoid 4"}));
  EXPECT_EQ(r.rate.delivered, 10u);
  EXPECT_EQ(r.stats.TcpExtTCPDelivered, 10u);
  r.q.check_invariants();
}

TEST(AckPipeline, TsecrFallbackOnlyForAValidTsecr) {
  struct Row {
    std::optional<std::uint32_t> tsecr;
    std::uint32_t now_ts;
    Duration expect;
  };
  const Row rows[] = {
      {std::nullopt, 5000, Duration{-1}},  // no timestamp
      {0u, 5000, Duration{-1}},            // TSecr 0 is not an echo
      {4950u, 5000, 50ms},
      {5000u, 5000, 1ms},                  // delta 0 counts as 1 tick
      {5000u - 2'147'483u, 5000, Duration{-1}},  // too old (Linux bound)
      {5000u - 2'147'482u, 5000, Duration{2'147'482ms}},
      {5001u, 5000, Duration{-1}},         // from the future: wraps huge
  };
  for (const Row& row : rows) {
    Rig r(false);
    r.send(0, mss, TxKind::data);
    r.send(0, mss, TxKind::rto_rexmit);
    r.now += 300ms;
    AckInput in = r.input(1000);
    in.tsecr = row.tsecr;
    in.now_ts = row.now_ts;
    const AckOutcome o = r.run(in);
    EXPECT_EQ(o.seq_rtt, row.expect) << row.now_ts - row.tsecr.value_or(0);
    EXPECT_EQ(o.ca_rtt, row.expect);
  }
  // An ACK that acknowledges nothing new takes no TSecr sample, and an
  // ACK-timed sample is preferred over it.
  Rig r(false);
  r.send(0, mss, TxKind::data);
  r.now += 40ms;
  AckInput dup = r.input(0);
  dup.tsecr = 1;
  dup.now_ts = 100;
  dup.dupack = true;
  EXPECT_EQ(r.run(dup).seq_rtt, Duration{-1});
  AckInput in = r.input(1000);
  in.tsecr = 1;
  in.now_ts = 100;
  EXPECT_EQ(r.run(in).seq_rtt, 40ms);
}

TEST(AckPipeline, MaybeDelayedFollowsCleanRtxQueue) {
  // A lone runt, nothing SACKed, nothing else delivered since it was sent.
  Rig r(true);
  r.send(0, 500, TxKind::data);
  r.now += 50ms;
  AckOutcome o = r.ack(500);
  EXPECT_NE(o.flags & utcp::ack_maybe_delayed, 0u);
  // The delayed sample above min_rtt does not raise it.
  r.send(500, 500, TxKind::data);
  r.now += 200ms;
  o = r.ack(1000);
  EXPECT_NE(o.flags & utcp::ack_maybe_delayed, 0u);
  EXPECT_EQ(r.rtt.min_rtt(), 50ms);
  // A full-sized segment: no.
  r.send(1000, mss, TxKind::data);
  r.now += 10ms;
  EXPECT_EQ(r.ack(2000).flags & utcp::ack_maybe_delayed, 0u);
  // Two runts acknowledged together: no.
  r.send(2000, 300, TxKind::data);
  r.send(2300, 300, TxKind::data);
  r.now += 10ms;
  EXPECT_EQ(r.ack(2600).flags & utcp::ack_maybe_delayed, 0u);
  // A runt acknowledged while something above it is SACKed: no.
  r.send(2600, 300, TxKind::data);
  r.send(2900, 300, TxKind::data);
  r.now += 10ms;
  const std::vector<Range> b{{2900, 3200}};
  r.ack(2600, b, true);
  EXPECT_EQ(r.ack(2900).flags & utcp::ack_maybe_delayed, 0u);
  // A retransmitted runt: no RTT sample at all.
  Rig s(true);
  s.send(0, 500, TxKind::data);
  s.send(0, 500, TxKind::rto_rexmit);
  s.now += 10ms;
  o = s.ack(500);
  EXPECT_EQ(o.flags & utcp::ack_maybe_delayed, 0u);
  EXPECT_EQ(o.seq_rtt, Duration{-1});
  // A runt acknowledged by an ACK that carries a D-SACK: a sample, but not
  // maybe-delayed (FLAG_CA_ALERT includes FLAG_DSACKING_ACK).
  Rig d(true);
  d.send(0, 500, TxKind::data);
  d.now += 50ms;
  d.ack(500);
  d.send(500, 500, TxKind::data);
  d.now += 40ms;
  AckInput in = d.input(1000);
  in.dsack = Range{0, 500};  // a second copy of the first runt arrived
  o = d.run(in);
  EXPECT_EQ(o.seq_rtt, 40ms);
  EXPECT_EQ(o.flags & utcp::ack_maybe_delayed, 0u);
  EXPECT_EQ(d.rtt.min_rtt(), 40ms);
}

TEST(AckPipeline, NoRttSampleWhenRetransmittedDataIsAcked) {
  // Karn (RFC 6298 §3), Linux FLAG_RETRANS_DATA_ACKED: an ACK that covers a
  // retransmitted segment gives no seq_rtt or ca_rtt, even from the
  // never-retransmitted segments it also covers.
  Rig r(true);
  r.send(0, mss, TxKind::data);
  r.now += 100ms;
  r.ack(1000);
  ASSERT_EQ(r.rtt.srtt(), 100ms);
  ASSERT_EQ(r.rtt.min_rtt(), 100ms);
  const Duration rttvar = r.rtt.rttvar();
  r.send(1000, mss, TxKind::data);  // A
  r.now += 1ms;
  r.send(2000, mss, TxKind::data);  // B
  r.now += 300ms;
  r.send(1000, mss, TxKind::rto_rexmit);
  r.now += 30ms;  // 331 ms after A, 330 ms after B, 30 ms after A's resend
  const AckOutcome o = r.ack(3000);
  EXPECT_EQ(o.acked_pkts, 2u);
  EXPECT_NE(o.flags & utcp::ack_retrans_data_acked, 0u);
  EXPECT_EQ(o.seq_rtt, Duration{-1});
  EXPECT_EQ(o.ca_rtt, Duration{-1});
  EXPECT_EQ(r.rtt.srtt(), 100ms);
  EXPECT_EQ(r.rtt.rttvar(), rttvar);
  EXPECT_EQ(r.rtt.min_rtt(), 100ms);
  // The next never-retransmitted segment is timed again.
  r.send(3000, mss, TxKind::data);
  r.now += 80ms;
  EXPECT_EQ(r.ack(4000).seq_rtt, 80ms);
  EXPECT_EQ(r.rtt.min_rtt(), 80ms);
}

TEST(AckPipeline, SackTaggingRunsBeforeTheCumulativeCleanup) {
  // Linux tcp_ack: tcp_sacktag_write_queue, then tcp_clean_rtx_queue. The
  // newly SACKed segment above is delivered before the cumulatively acked
  // one below it.
  Rig r(true);
  r.send_spaced(4);
  const std::vector<Range> b{{2000, 3000}};
  r.ack(1000, b);
  EXPECT_EQ(r.delivered_log,
            (std::vector<std::pair<std::uint64_t, bool>>{{2000, true}, {0, false}}));
  r.delivered_log.clear();
  // Blocks newest first (RFC 2018 §4): SACK deliveries in sequence order.
  Rig s(true);
  s.send_spaced(8);
  const std::vector<Range> b2{{5000, 6000}, {3000, 4000}};
  s.ack(2000, b2);
  EXPECT_EQ(s.delivered_log, (std::vector<std::pair<std::uint64_t, bool>>{
                                 {3000, true}, {5000, true}, {0, false}, {1000, false}}));
}

TEST(AckPipeline, SackBlocksMustStartAboveTheNewSndUna) {
  // Linux tcp_is_sackblock_valid runs after tcp_ack_update_window moved
  // SND.UNA: a block between the old and the new SND.UNA, or starting at the
  // new one, is not valid. Accepting either would SACK a segment that the
  // cumulative ACK pops (newly_sacked) or the new head, which looks like
  // reneging and re-arms the RTO at max(srtt/2, 10 ms).
  Rig r(true);
  r.rtt.on_srtt_sample(100ms, 0, 1);
  r.send_spaced(4);
  const std::vector<Range> b{{1000, 2000}, {2000, 3000}};
  const AckOutcome o = r.ack(2000, b);
  EXPECT_EQ(o.newly_sacked, 0u);
  EXPECT_EQ(o.acked_pkts, 2u);
  EXPECT_EQ(o.flags & utcp::ack_sack_reneging, 0u);
  EXPECT_FALSE(r.q.find(2000)->sacked);
  EXPECT_EQ(r.q.counters().sacked_out, 0u);
  EXPECT_EQ(r.rec.state(), CaState::open);
  const auto timer = r.rec.xmit_timer(r.rctx());
  EXPECT_EQ(timer.first, utcp::XmitTimer::rto);
  EXPECT_EQ(timer.second, r.now + r.rtt.rto_backed_off(0));  // not the srtt/2 reneging timer
  // A block just above the new SND.UNA is valid.
  const std::vector<Range> ok{{3000, 4000}};
  EXPECT_EQ(r.ack(2000, ok, true).newly_sacked, 1u);
}

TEST(AckPipeline, DsackRunsTheStateMachine) {
  // Linux tcp_ack_is_dubious: FLAG_CA_ALERT includes FLAG_DSACKING_ACK, so a
  // D-SACK runs tcp_fastretrans_alert even on an ACK that is not a
  // duplicate (here a window update); with a retransmission outstanding,
  // Open becomes Disorder (tcp_try_keep_open).
  Rig r(true);
  r.send_spaced(4);
  r.ack(1000);
  r.send(1000, mss, TxKind::rexmit);
  ASSERT_EQ(r.rec.state(), CaState::open);
  AckInput in = r.input(1000);
  in.dsack = Range{0, 1000};
  in.window_update = true;
  const AckOutcome o = r.run(in);
  EXPECT_NE(o.flags & utcp::ack_dsack, 0u);
  EXPECT_EQ(r.rec.state(), CaState::disorder);
}

TEST(AckPipeline, RangesPastEndAreClippedAndTheFinAckIsReported) {
  Rig r(true);
  r.send(0, mss, TxKind::data);
  r.send(1000, mss, TxKind::data);
  r.send(2000, 500, TxKind::data, true);  // FIN rides on the last segment
  ASSERT_TRUE(r.q.fin_sent());
  ASSERT_EQ(r.q.nxt_with_fin(), 2501u);
  // The receiver SACKs the last segment and its FIN: [2000, end() + 1).
  const std::vector<Range> b{{2000, 2501}};
  AckOutcome o = r.ack(0, b, true);
  EXPECT_EQ(o.newly_sacked, 1u);
  EXPECT_TRUE(r.q.find(2000)->sacked);
  // A block starting at the new SND.UNA or below is not valid (Linux).
  const std::vector<Range> low{{0, 1000}};
  o = r.ack(1000, low);
  EXPECT_EQ(o.newly_sacked, 0u);
  EXPECT_EQ(o.acked_pkts, 1u);
  // SEG.ACK = end() + 1 covers the FIN.
  o = r.ack(2501);
  EXPECT_NE(o.flags & utcp::ack_fin_acked, 0u);
  EXPECT_NE(o.flags & utcp::ack_una_advanced, 0u);
  EXPECT_EQ(o.acked_pkts, 2u);
  EXPECT_TRUE(r.q.fin_acked());
  EXPECT_EQ(r.q.counters().packets_out, 0u);
  EXPECT_EQ(r.q.una_with_fin(), 2501u);
  EXPECT_EQ(r.rec.xmit_timer(r.rctx()).first, utcp::XmitTimer::none);
  // A repeated ACK of end() + 1 acknowledges nothing new: no FIN ACK again.
  o = r.ack(2501);
  EXPECT_EQ(o.flags & utcp::ack_fin_acked, 0u);
  EXPECT_EQ(o.flags & utcp::ack_una_advanced, 0u);
  EXPECT_EQ(o.acked_pkts, 0u);
  EXPECT_TRUE(r.q.fin_acked());

  // A bare FIN: its payload-free slot is never SACKed; an ACK of the data
  // alone keeps it, the next ACK covers it.
  Rig f(true);
  f.send(0, mss, TxKind::data);
  f.send(1000, 0, TxKind::fin, true);
  const std::vector<Range> fin_only{{1000, 1001}};
  o = f.ack(0, fin_only, true);
  EXPECT_EQ(o.newly_sacked, 0u);
  o = f.ack(1000);
  EXPECT_EQ(o.flags & utcp::ack_fin_acked, 0u);
  EXPECT_EQ(f.q.counters().packets_out, 1u);
  o = f.ack(1001);
  EXPECT_NE(o.flags & utcp::ack_fin_acked, 0u);
  EXPECT_NE(o.flags & utcp::ack_una_advanced, 0u);
  EXPECT_EQ(o.acked_pkts, 1u);
  EXPECT_EQ(f.q.counters().packets_out, 0u);
  o = f.ack(1001);
  EXPECT_EQ(o.flags & utcp::ack_fin_acked, 0u);
  EXPECT_EQ(o.acked_pkts, 0u);
}

TEST(AckPipeline, DsackIsCountedAndIsNotADupack) {
  Rig r(false);
  r.send_spaced(4);
  r.ack(1000);
  AckInput in = r.input(1000);
  in.dsack = Range{0, 1000};
  in.dupack = true;
  const AckOutcome o = r.run(in);
  EXPECT_NE(o.flags & utcp::ack_dsack, 0u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKRecv, 1u);
  EXPECT_EQ(r.ctr.dsack_dups, 1u);
  EXPECT_EQ(r.q.counters().sacked_out, 0u);  // no reno dupack counted
  EXPECT_EQ(r.rec.state(), CaState::open);
}

TEST(AckPipeline, RenoDeliveredCountsDupacksOnce) {
  Rig r(false);
  r.send_spaced(6);
  for (int i = 0; i < 2; ++i) {
    EXPECT_EQ(r.ack(0, {}, true).delivered, 1u);  // tcp_add_reno_sack
  }
  // Three packets acked, two already counted by the dupacks: one more.
  const AckOutcome o = r.ack(3000);
  EXPECT_EQ(o.delivered, 1u);
  EXPECT_EQ(r.rate.delivered, 3u);
  EXPECT_EQ(r.q.counters().sacked_out, 0u);
  // Pacing rate follows the CC each ACK (tcp_update_pacing_rate).
  EXPECT_GT(r.cc.pacing_rate, 0u);
}

}  // namespace
