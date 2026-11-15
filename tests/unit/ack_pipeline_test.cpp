#include "core/tcp/ack_pipeline.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/cc_newreno.hpp"
#include "support/recovery_script.hpp"

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

// A CC that owns cwnd (has_cong_control, as BBR): records its hook calls and
// the sample it got, and can write CcConn::app_limited (BBR entering
// PROBE_RTT, tcp_bbr.c bbr_update_min_rtt).
class OwnCc final : public utcp::CongestionControl {
public:
  [[nodiscard]] std::string_view name() const override { return "own"; }
  std::uint32_t ssthresh(const utcp::CcConn& c) override { return std::max(c.cwnd / 2, 2u); }
  void cong_avoid(utcp::CcConn&, const AckOutcome&) override { log.emplace_back("cong_avoid"); }
  [[nodiscard]] bool has_cong_control() const override { return true; }
  void cong_control(utcp::CcConn& c, const AckOutcome& out, const utcp::RateSample& rs) override {
    log.push_back("cong_control " + std::to_string(out.delivered));
    last_rs = &rs;
    last_out_rs = out.rs;
    if (write_app_limited) {
      c.app_limited = c.delivered + c.in_flight > 0 ? c.delivered + c.in_flight : 1;
      write_app_limited = false;
    }
  }

  std::vector<std::string> log;
  const utcp::RateSample* last_rs = nullptr;
  const utcp::RateSample* last_out_rs = nullptr;
  bool write_app_limited = false;
};

struct Rig {
  explicit Rig(bool sack_ok) : sack(sack_ok) {
    q.set_sack_ok(sack_ok);
    cc.cwnd = 10;
    cc.ssthresh = utcp::cwnd_infinite;
    cc.mss = mss;
    cc.cwnd_limited = true;
  }

  utcp::CongestionControl& a() { return own != nullptr ? *own : static_cast<utcp::CongestionControl&>(algo); }

  utcp::RecoveryCtx rctx() {
    return utcp::RecoveryCtx{q, cc, a(), rtt, cfg, now, wnd, stats, sack, backoff, 0};
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

  // The AckContext of the last run stays alive (AckOutcome::rs points into it).
  AckOutcome run(const AckInput& in) {
    ctx = std::make_unique<utcp::AckContext>(
        utcp::AckContext{q, rec, rtt, cc, a(), rate, cfg, stats, ctr, wnd, sack, backoff, 0,
                         max_snd_wnd, ts_offset, pacing_delay});
    utcp::AckContext& c = *ctx;
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
  std::uint32_t max_snd_wnd = 1 << 20;
  std::uint32_t ts_offset = 0;
  Duration pacing_delay{0};
  OwnCc* own = nullptr;  // replaces `algo` when set
  std::unique_ptr<utcp::AckContext> ctx;
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
  // A runt acknowledged by an ACK that carries a valid D-SACK: a sample, but
  // not maybe-delayed (FLAG_CA_ALERT includes FLAG_DSACKING_ACK, which
  // tcp_dsack_seen sets only for a D-SACK within total_retrans).
  Rig d(true);
  d.send(0, 500, TxKind::data);
  d.now += 50ms;
  d.ack(500);
  d.send(500, 500, TxKind::data);
  d.now += 40ms;
  d.ctr.total_retrans = 1;  // the first runt was also retransmitted
  AckInput in = d.input(1000);
  in.dsack = Range{0, 500};  // its second copy arrived
  o = d.run(in);
  EXPECT_NE(o.flags & utcp::ack_dsack, 0u);
  EXPECT_EQ(o.seq_rtt, 40ms);
  EXPECT_EQ(o.flags & utcp::ack_maybe_delayed, 0u);
  EXPECT_EQ(d.rtt.min_rtt(), 40ms);
  // The same with nothing retransmitted (a duplicate made by the network):
  // the D-SACK is dubious, so the ACK is not FLAG_DSACKING_ACK, and the lone
  // runt is maybe-delayed as without a D-SACK.
  Rig e(true);
  e.send(0, 500, TxKind::data);
  e.now += 50ms;
  e.ack(500);
  e.send(500, 500, TxKind::data);
  e.now += 40ms;
  in = e.input(1000);
  in.dsack = Range{0, 500};
  o = e.run(in);
  EXPECT_EQ(o.flags & utcp::ack_dsack, 0u);
  EXPECT_NE(o.flags & utcp::ack_maybe_delayed, 0u);
  EXPECT_EQ(e.ctr.dsack_dups, 1u);
  EXPECT_EQ(e.stats.TcpExtTCPDSACKIgnoredDubious, 1u);
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
  r.ctr.total_retrans = 1;  // the engine counts it
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
  r.ctr.total_retrans = 1;  // segment 0 was also retransmitted
  AckInput in = r.input(1000);
  in.dsack = Range{0, 1000};
  in.dupack = true;
  const AckOutcome o = r.run(in);
  EXPECT_NE(o.flags & utcp::ack_dsack, 0u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKRecv, 1u);
  EXPECT_EQ(r.ctr.dsack_dups, 1u);
  EXPECT_EQ(o.delivered, 1u);  // the spurious retransmission is delivered
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

// M2-DESIGN §1.6 (tcp_dsack_seen): a D-SACK counts ceil(len / mss) segments
// in dsack_dups unless it is longer than the max window; it is valid if
// dsack_dups then stays within total_retrans, and only then are its segments
// delivered (out.delivered, RateState::delivered, TcpExtTCPDelivered) and the
// ACK flagged ack_dsack.
TEST(AckPipeline, DsackSegmentsAreCountedAndDelivered) {
  Rig r(true);
  r.send_spaced(8);
  r.ack(4000);
  r.ctr.total_retrans = 4;  // segments 0-3 were resent too

  // A 3-segment D-SACK on a duplicate ACK: 3 more dups, 3 delivered.
  AckInput in = r.input(4000);
  in.dsack = Range{0, 3000};
  in.dupack = true;
  AckOutcome o = r.run(in);
  EXPECT_EQ(r.ctr.dsack_dups, 3u);
  EXPECT_EQ(o.delivered, 3u);
  EXPECT_EQ(o.acked_pkts, 0u);
  EXPECT_EQ(r.rate.delivered, 7u);  // 4 acked + 3
  EXPECT_EQ(r.stats.TcpExtTCPDelivered, 7u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKRecv, 1u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKRecvSegs, 3u);
  EXPECT_NE(o.flags & utcp::ack_dsack, 0u);
  ASSERT_NE(o.rs, nullptr);
  EXPECT_EQ(o.rs->acked_sacked, 3u);

  // Longer than the largest window the peer offered: ignored entirely.
  r.max_snd_wnd = 2999;
  in.dsack = Range{0, 3000};
  o = r.run(in);
  EXPECT_EQ(r.ctr.dsack_dups, 3u);
  EXPECT_EQ(o.delivered, 0u);
  EXPECT_EQ(o.flags & utcp::ack_dsack, 0u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKRecv, 2u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKIgnoredDubious, 1u);
  r.max_snd_wnd = 1 << 20;

  // 1001 bytes are 2 segments (rounded up); dsack_dups 5 would pass
  // total_retrans 4: counted, but nothing delivered.
  in.dsack = Range{1000, 2001};
  o = r.run(in);
  EXPECT_EQ(r.ctr.dsack_dups, 5u);
  EXPECT_EQ(o.delivered, 0u);
  EXPECT_EQ(o.flags & utcp::ack_dsack, 0u);
  EXPECT_EQ(r.rate.delivered, 7u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKIgnoredDubious, 2u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKRecvSegs, 3u);

  // Below one MSS: one segment. With the stub recovery no TLP is
  // outstanding, so it is never ack_dsack_tlp.
  r.ctr.total_retrans = 6;
  in.dsack = Range{0, 10};
  o = r.run(in);
  EXPECT_EQ(r.ctr.dsack_dups, 6u);
  EXPECT_EQ(o.delivered, 1u);
  EXPECT_EQ(o.flags & utcp::ack_dsack_tlp, 0u);
}

// M2-DESIGN §1.8, Linux tcp_cong_control: a CC with cong_control gets the
// ACK's rate sample (the one AckOutcome::rs points to) instead of cong_avoid,
// PRR and the engine's pacing-rate update.
TEST(AckPipeline, CongControlReplacesCongAvoidAndGetsTheSample) {
  Rig r(true);
  OwnCc own;
  r.own = &own;
  r.send_spaced(4);
  r.now += 30ms;
  r.cc.pacing_rate = 12345;
  const AckOutcome o = r.ack(2000);
  EXPECT_EQ(own.log, (std::vector<std::string>{"cong_control 2"}));
  ASSERT_NE(o.rs, nullptr);
  EXPECT_EQ(o.rs, &r.ctx->sample);
  EXPECT_EQ(own.last_rs, o.rs);
  EXPECT_EQ(own.last_out_rs, o.rs);
  EXPECT_EQ(o.rs->acked_sacked, 2u);
  EXPECT_EQ(o.rs->rtt, o.ca_rtt);
  EXPECT_EQ(r.cc.pacing_rate, 12345u);  // left to the CC
  EXPECT_EQ(r.cc.cwnd, 10u);
}

// M2-DESIGN §2.6: rs.rtt is the ACK's ca_rtt (tcp_ack_update_rtt) and
// rs.is_ack_delayed its ack_maybe_delayed flag (tcp_ack), set on every
// sample; an old ACK has no sample.
TEST(AckPipeline, RateSampleCarriesCaRttAndMaybeDelayed) {
  Rig r(true);
  r.send(0, 500, TxKind::data);
  r.now += 50ms;
  AckOutcome o = r.ack(500);
  ASSERT_NE(o.rs, nullptr);
  EXPECT_NE(o.flags & utcp::ack_maybe_delayed, 0u);
  EXPECT_TRUE(o.rs->is_ack_delayed);
  EXPECT_EQ(o.rs->rtt, 50ms);
  EXPECT_EQ(o.rs->rtt, o.ca_rtt);
  r.send_spaced(3);
  r.now += 20ms;
  const std::vector<Range> b{{1500, 2500}};
  o = r.ack(500, b, true);  // SACK only: ca_rtt from the SACKed segment
  EXPECT_FALSE(o.rs->is_ack_delayed);
  EXPECT_EQ(o.rs->rtt, o.ca_rtt);
  EXPECT_EQ(o.rs->rtt, 22ms);  // segment 2 left 1 ms after segment 1
  o = r.ack(500, {}, true);  // nothing new: no RTT
  EXPECT_EQ(o.rs->rtt, Duration{-1});
  AckInput old = r.input(500);
  old.new_una = 500;
  old.old_ack = true;
  old.prior_una = 500;
  const std::vector<Range> b2{{2500, 3500}};
  old.sack = b2;
  o = r.run(old);
  EXPECT_EQ(o.rs, nullptr);
}

// The tcp_cong_control step with the stub recovery's hooks driven through
// the test seam: cong_avoid runs exactly when may_raise_cwnd says so outside
// CWR and Recovery; in Recovery cwnd_reduction runs with (delivered,
// rs.losses, flags) instead, and cong_avoid and may_raise_cwnd do not.
TEST(AckPipeline, CongControlStepAsksRecovery) {
  Rig r(true);
  utcp::test::ScriptedRecovery script;
  r.rec.set_script(&script);
  r.send_spaced(10);
  r.now += 50ms;
  const auto grew = [&r] {
    for (const std::string& l : r.algo.log) {
      if (l.rfind("cong_avoid", 0) == 0) {
        return true;
      }
    }
    return false;
  };

  // The stub's may_raise_cwnd (M1): data cumulatively acked.
  r.ack(1000);
  EXPECT_EQ(script.calls_of("may_raise_cwnd").size(), 1u);
  EXPECT_TRUE(grew());
  // A cumulative ACK the script refuses: no cong_avoid.
  script.may_raise = [](const utcp::RecoveryCtx&, const AckOutcome&) { return false; };
  r.algo.log.clear();
  const std::uint32_t cwnd = r.cc.cwnd;
  r.ack(2000);
  EXPECT_FALSE(grew());
  EXPECT_EQ(r.cc.cwnd, cwnd);
  // A SACK-only ACK: the stub says no ...
  script.may_raise = nullptr;
  r.algo.log.clear();
  std::vector<Range> b{{3000, 4000}};
  r.ack(2000, b, true);
  EXPECT_FALSE(grew());
  // ... a script that says yes gets cong_avoid.
  script.may_raise = [](const utcp::RecoveryCtx&, const AckOutcome&) { return true; };
  b = {{3000, 5000}};
  r.ack(2000, b, true);
  EXPECT_TRUE(grew());
  script.may_raise = nullptr;
  EXPECT_TRUE(script.calls_of("cwnd_reduction").empty());
  EXPECT_EQ(script.calls_of("may_raise_cwnd").size(), 4u);

  // A third SACKed segment above the hole at 2000 enters Recovery; from
  // then on cwnd_reduction gets (delivered, rs.losses, flags) and neither
  // may_raise_cwnd nor cong_avoid runs.
  r.algo.log.clear();
  b = {{3000, 6000}};
  AckOutcome o = r.ack(2000, b, true);
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  ASSERT_NE(o.rs, nullptr);
  ASSERT_EQ(script.calls_of("cwnd_reduction").size(), 1u);
  EXPECT_EQ(script.calls_of("cwnd_reduction").back(),
            "cwnd_reduction " + std::to_string(o.delivered) + " " +
                std::to_string(o.rs->losses) + " " + std::to_string(o.flags));
  EXPECT_EQ(o.delivered, 1u);
  b = {{3000, 7000}};
  o = r.ack(2000, b, true);
  EXPECT_EQ(script.calls_of("cwnd_reduction").back(),
            "cwnd_reduction 1 " + std::to_string(o.rs->losses) + " " + std::to_string(o.flags));
  EXPECT_EQ(script.calls_of("cwnd_reduction").size(), 2u);
  EXPECT_EQ(script.calls_of("may_raise_cwnd").size(), 4u);
  EXPECT_FALSE(grew());
  // A script that handles the reduction writes cwnd itself.
  script.reduce = [](utcp::RecoveryCtx& c, std::uint32_t, std::uint32_t, std::uint32_t) {
    c.cc.cwnd = 77;
    return true;
  };
  b = {{3000, 8000}};
  r.ack(2000, b, true);
  EXPECT_EQ(r.cc.cwnd, 77u);
  r.rec.set_script(nullptr);
}

// tcp_in_cwnd_reduction is CWR or Recovery (Linux tcp_input.c:3866-3872):
// in Loss (after an RTO) cwnd grows through may_raise_cwnd and cong_avoid; in
// CWR (ECE, or the TLP-repaired loss of M2-DESIGN §1.7; the stub never enters
// it, so the test seam reports it) cwnd_reduction gets (delivered, rs.losses,
// flags) and neither may_raise_cwnd nor cong_avoid runs.
TEST(AckPipeline, CongControlStepInLossAndCwr) {
  {
    SCOPED_TRACE("loss");
    Rig r(true);
    utcp::test::ScriptedRecovery script;
    r.rec.set_script(&script);
    r.send_spaced(10);
    r.now += 300ms;
    utcp::RecoveryCtx c = r.rctx();
    r.rec.on_rto(c);
    ASSERT_EQ(r.rec.state(), CaState::loss);
    ASSERT_EQ(r.cc.cwnd, 1u);
    r.algo.log.clear();
    r.ack(1000);
    ASSERT_EQ(r.rec.state(), CaState::loss);
    EXPECT_TRUE(script.calls_of("cwnd_reduction").empty());
    EXPECT_EQ(script.calls_of("may_raise_cwnd").size(), 1u);
    EXPECT_EQ(r.algo.log.back(), "cong_avoid 1");
    EXPECT_EQ(r.cc.cwnd, 2u);  // slow start
    r.rec.set_script(nullptr);
  }
  {
    SCOPED_TRACE("cwr");
    Rig r(true);
    utcp::test::ScriptedRecovery script;
    r.rec.set_script(&script);
    script.state = CaState::cwr;
    r.send_spaced(4);
    r.now += 30ms;
    r.algo.log.clear();
    const AckOutcome o = r.ack(2000);
    ASSERT_NE(o.rs, nullptr);
    EXPECT_EQ(script.calls_of("cwnd_reduction"),
              (std::vector<std::string>{"cwnd_reduction 2 " + std::to_string(o.rs->losses) + " " +
                                        std::to_string(o.flags)}));
    EXPECT_TRUE(script.calls_of("may_raise_cwnd").empty());
    for (const std::string& l : r.algo.log) {
      EXPECT_FALSE(l.starts_with("cong_avoid")) << l;
    }
    r.rec.set_script(nullptr);
  }
}

// Linux tcp_ack with nothing outstanding (prior_packets 0, no_queue,
// tcp_input.c:4357-4358, 4413-4433): a D-SACK is still delivered, but there
// is no rate sample and no tcp_cong_control (no PRR, no cong_avoid, no
// pacing-rate update), even in a cwnd-reduction state.
TEST(AckPipeline, AckWithNothingOutstandingSkipsTheCcStep) {
  Rig r(true);
  utcp::test::ScriptedRecovery script;
  r.rec.set_script(&script);
  r.send_spaced(4);
  r.now += 30ms;
  r.ack(4000);
  ASSERT_EQ(r.q.counters().packets_out, 0u);
  script.state = CaState::cwr;
  script.calls.clear();
  r.algo.log.clear();
  r.cc.pacing_rate = 12345;
  const std::uint32_t cwnd = r.cc.cwnd;
  r.ctr.total_retrans = 1;  // segment 0 was also retransmitted
  AckInput in = r.input(4000);
  in.dsack = Range{0, 1000};
  in.dupack = true;
  const AckOutcome o = r.run(in);
  EXPECT_NE(o.flags & utcp::ack_dsack, 0u);
  EXPECT_EQ(o.delivered, 1u);
  EXPECT_EQ(r.rate.delivered, 5u);
  EXPECT_EQ(o.rs, nullptr);
  EXPECT_TRUE(script.calls_of("cwnd_reduction").empty());
  EXPECT_TRUE(script.calls_of("may_raise_cwnd").empty());
  for (const std::string& l : r.algo.log) {
    EXPECT_FALSE(l.starts_with("cong_avoid")) << l;
  }
  EXPECT_EQ(r.cc.pacing_rate, 12345u);
  EXPECT_EQ(r.cc.cwnd, cwnd);
  r.rec.set_script(nullptr);
}

// tcp_dsack_seen ignores a D-SACK only when it is longer than max_window
// (`seq_len > tp->max_window`): one exactly max_snd_wnd long counts.
TEST(AckPipeline, DsackOfExactlyTheMaxWindowCounts) {
  Rig r(true);
  r.send_spaced(8);
  r.ack(4000);
  r.ctr.total_retrans = 4;
  r.max_snd_wnd = 3000;
  AckInput in = r.input(4000);
  in.dsack = Range{0, 3000};
  in.dupack = true;
  const AckOutcome o = r.run(in);
  EXPECT_EQ(r.ctr.dsack_dups, 3u);
  EXPECT_EQ(o.delivered, 3u);
  EXPECT_NE(o.flags & utcp::ack_dsack, 0u);
  EXPECT_EQ(r.stats.TcpExtTCPDSACKIgnoredDubious, 0u);
}

// Every M2 input of RecoveryCtx is filled for the hooks of one ACK
// (M2-DESIGN §1.6 "Inputs", §1.7).
TEST(AckPipeline, RecoveryCtxCarriesTheM2Inputs) {
  Rig r(true);
  utcp::test::ScriptedRecovery script;
  r.rec.set_script(&script);
  r.max_snd_wnd = 65535;
  r.ts_offset = 777;
  r.pacing_delay = 3500us;
  r.send_spaced(4);
  r.now += 40ms;
  r.ctr.total_retrans = 5;
  r.ctr.dsack_dups = 1;
  struct Seen {
    const AckInput* in = nullptr;
    std::uint64_t new_una = 0;
    std::optional<std::uint32_t> tsecr;
    std::uint32_t ts_now = 0, ts_of_now = 0, max_snd_wnd = 0;
    std::uint64_t total_retrans = 0, dsack_dups = 0, prior_delivered = 0, delivered = 0;
    bool has_prior = false;
    Duration pacing_delay{0};
  } seen;
  script.may_raise = [&seen](const utcp::RecoveryCtx& c, const AckOutcome&) {
    seen.in = c.in;
    if (c.in != nullptr) {
      seen.new_una = c.in->new_una;
      seen.tsecr = c.in->tsecr;
      seen.ts_now = c.in->now_ts;
    }
    seen.ts_of_now = c.ts_of(c.now);
    seen.max_snd_wnd = c.max_snd_wnd;
    seen.total_retrans = c.total_retrans;
    seen.dsack_dups = c.dsack_dups;
    seen.has_prior = c.has_prior;
    seen.prior_delivered = c.prior_delivered;
    seen.delivered = c.delivered;
    seen.pacing_delay = c.pacing_delay;
    return std::nullopt;
  };
  AckInput in = r.input(2000);
  in.tsecr = 4242;
  const std::uint32_t ts_now =
      static_cast<std::uint32_t>(static_cast<std::uint64_t>(r.now.ns) / 1'000'000u) + 777u;
  in.now_ts = ts_now;  // ms of `now` plus the offset
  in.dsack = Range{0, 500};  // valid: dsack_dups 2 <= 5
  r.run(in);
  EXPECT_NE(seen.in, nullptr);
  EXPECT_EQ(seen.new_una, 2000u);
  EXPECT_EQ(seen.tsecr, std::optional<std::uint32_t>{4242});
  EXPECT_EQ(seen.ts_now, ts_now);
  EXPECT_EQ(seen.ts_of_now, ts_now);
  EXPECT_EQ(seen.max_snd_wnd, 65535u);
  EXPECT_EQ(seen.total_retrans, 5u);
  EXPECT_EQ(seen.dsack_dups, 2u);
  EXPECT_TRUE(seen.has_prior);
  EXPECT_EQ(seen.prior_delivered, 0u);  // segment 1 was sent with delivered 0
  EXPECT_EQ(seen.delivered, 3u);        // 2 acked + 1 D-SACKed
  EXPECT_EQ(seen.delivered, r.rate.delivered);
  EXPECT_EQ(seen.pacing_delay, 3500us);
  r.rec.set_script(nullptr);
}

// M2-DESIGN §2.1 item 7: tp->app_limited is one value. A CC that writes
// CcConn::app_limited in cong_control (BBR entering PROBE_RTT) sets
// RateState::app_limited, so the next segment sent carries the mark and
// the sample of its ACK is app-limited.
TEST(AckPipeline, CongControlAppLimitedWriteReachesTheNextSample) {
  for (const bool write : {false, true}) {
    SCOPED_TRACE(write);
    Rig r(true);
    OwnCc own;
    r.own = &own;
    r.send_spaced(2);
    r.now += 30ms;
    own.write_app_limited = write;
    r.ack(1000);
    EXPECT_EQ(r.rate.app_limited, write ? 2u : 0u);  // delivered 1 + in flight 1
    EXPECT_EQ(r.cc.app_limited, r.rate.app_limited);
    r.send(r.q.nxt(), mss, TxKind::data);
    r.now += 30ms;
    const AckOutcome o = r.ack(3000);
    ASSERT_NE(o.rs, nullptr);
    EXPECT_EQ(o.rs->is_app_limited, write);
  }
}

}  // namespace
