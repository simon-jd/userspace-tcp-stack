// m2a-recovery acceptance test 2: the RFC 6675 scoreboard of the rfc profile
// (M2-DESIGN §1.4): IsLost, DupAcks, entry, partial ACKs, NextSeg rules 1-4
// with HighRxt and RescueRxt, and the RTO during recovery (RFC 6675 §5.1).
#include "core/tcp/sack_scoreboard.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include "recovery_rig.hpp"
#include "tcp_test_util.hpp"
#include "utcp/trace.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::CaState;
using utcp::Range;
using utcp::Rfc6675Scoreboard;
using utcp::SendQueue;
using utcp::Time;
using utcp::TxSeg;
using utcp::test::rig::off_of;
using utcp::test::rig::Rig;
using Sent = std::vector<std::string>;

// A send queue of `n` segments of `len` bytes, all sent at t.
struct Queue {
  Queue(std::uint32_t n, std::uint32_t len) {
    const std::vector<std::byte> data(std::size_t{n} * len);
    EXPECT_EQ(q.write(data), data.size());
    for (std::uint32_t i = 0; i < n; ++i) {
      q.on_transmit(q.nxt(), len, false, t, rate);
    }
  }
  void sack(std::initializer_list<Range> blocks) {
    const std::vector<Range> b(blocks);
    q.on_sack(b, t, [](const TxSeg&, bool) {});
  }
  utcp::ChunkPool pool{64};
  SendQueue q{pool, 1 << 20};
  utcp::RateState rate;
  Time t{1'000'000'000};
};

// IsLost by DupThresh (3) SACKed segments above, and the incremental marking.
TEST(SackScoreboard, IsLostByCount) {
  Queue s(10, 1000);
  s.sack({{2000, 3000}, {4000, 5000}, {6000, 7000}});  // segments 3, 5, 7
  // Segments 1 and 2 have 3 SACKed above; 4 has 2 (5, 7); 6 has 1.
  EXPECT_TRUE(Rfc6675Scoreboard::is_lost(s.q, 0, 3, 1000));
  EXPECT_TRUE(Rfc6675Scoreboard::is_lost(s.q, 1000, 3, 1000));
  EXPECT_FALSE(Rfc6675Scoreboard::is_lost(s.q, 3000, 3, 1000));
  EXPECT_FALSE(Rfc6675Scoreboard::is_lost(s.q, 5000, 3, 1000));
  Rfc6675Scoreboard sb;
  EXPECT_EQ(sb.mark_lost(s.q, 3, 1000), 2u);
  EXPECT_TRUE(s.q.find(0)->lost);
  EXPECT_TRUE(s.q.find(1000)->lost);
  EXPECT_FALSE(s.q.find(3000)->lost);
  EXPECT_EQ(sb.lost_below(), 2000u);  // the third SACKed segment from the top
  EXPECT_EQ(sb.mark_lost(s.q, 3, 1000), 0u);  // nothing new
  // SACK 9: now 5, 7, 9 lie above 4, which becomes lost; 6 has 2 above.
  s.sack({{8000, 9000}});
  EXPECT_EQ(sb.mark_lost(s.q, 3, 1000), 1u);
  EXPECT_TRUE(s.q.find(3000)->lost);
  EXPECT_FALSE(s.q.find(5000)->lost);
  EXPECT_EQ(sb.lost_below(), 4000u);
  EXPECT_EQ(s.q.counters().lost_out, 3u);
  s.q.check_invariants();
}

// Short segments (400 bytes, SMSS 1000): 3 SACKed segments are 1200 bytes,
// not more than (3 - 1) * 1000, yet the count makes the ones below lost.
TEST(SackScoreboard, IsLostByCountOfShortSegments) {
  Queue s(6, 400);
  s.sack({{800, 2000}});  // segments 3, 4, 5
  EXPECT_TRUE(Rfc6675Scoreboard::is_lost(s.q, 0, 3, 1000));
  EXPECT_TRUE(Rfc6675Scoreboard::is_lost(s.q, 400, 3, 1000));
  Rfc6675Scoreboard sb;
  EXPECT_EQ(sb.mark_lost(s.q, 3, 1000), 2u);
}

// IsLost by bytes: more than (DupThresh - 1) * SMSS SACKed bytes above with
// fewer than 3 SACKed segments. With SMSS 600 below the 1000-byte segments
// (a PMTU decrease since they were sent), 2 SACKed segments are 2000 > 1200
// bytes; one is 1000, not more than 1200.
TEST(SackScoreboard, IsLostByBytes) {
  Queue s(6, 1000);
  s.sack({{2000, 3000}, {4000, 5000}});  // segments 3 and 5
  EXPECT_TRUE(Rfc6675Scoreboard::is_lost(s.q, 0, 3, 600));
  EXPECT_TRUE(Rfc6675Scoreboard::is_lost(s.q, 1000, 3, 600));
  EXPECT_FALSE(Rfc6675Scoreboard::is_lost(s.q, 3000, 3, 600));
  EXPECT_FALSE(Rfc6675Scoreboard::is_lost(s.q, 0, 3, 1000));  // 2000 = 2 * 1000: not more
  Rfc6675Scoreboard sb;
  EXPECT_EQ(sb.mark_lost(s.q, 3, 600), 2u);
  EXPECT_FALSE(s.q.find(3000)->lost);
}

// DupAcks (RFC 6675 §2, §5): an ACK that SACKs new data counts, even if it
// also moves SND.UNA (the reset comes first); a cumulative ACK alone resets;
// nothing is counted in loss recovery.
TEST(SackScoreboard, DupAcks) {
  Rfc6675Scoreboard sb;
  sb.on_ack(false, 1, true);
  sb.on_ack(false, 2, true);
  EXPECT_EQ(sb.dupacks(), 2u);
  sb.on_ack(true, 1, true);  // reset, then this ACK
  EXPECT_EQ(sb.dupacks(), 1u);
  sb.on_ack(true, 0, true);
  EXPECT_EQ(sb.dupacks(), 0u);
  sb.on_ack(false, 0, true);  // no new SACK information
  EXPECT_EQ(sb.dupacks(), 0u);
  sb.on_ack(false, 1, false);  // in recovery
  EXPECT_EQ(sb.dupacks(), 0u);
}

// Entry by IsLost: one ACK SACKs 3 segments (DupAcks 1).
TEST(SackScoreboard, EntryByIsLost) {
  Rig r(utcp::test::rig::rfc_cfg());
  r.send_new(10);
  r.now += 100ms;
  r.ack(1, {{2, 4}});
  EXPECT_EQ(r.rec.scoreboard().dupacks(), 1u);
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_TRUE(r.pkt(1).lost);
  EXPECT_EQ(r.rec.scoreboard().high_rxt(), 1000u);  // (4.3): the head's end
  EXPECT_EQ(r.rec.scoreboard().rescue_rxt(), 1000u);
}

// Entry by DupAcks counted on ACKs that also move SND.UNA: SACK 3 (DupAcks
// 1); an ACK of 1-3 that SACKs 5 resets DupAcks and counts itself (1); two
// more SACKs (7, 9) make 3, and IsLost(4) holds at the same ACK (5, 7, 9
// above it).
TEST(SackScoreboard, EntryByDupAcksCountedOnCumulativeAcks) {
  Rig r(utcp::test::rig::rfc_cfg());
  r.send_new(10);
  r.now += 100ms;
  r.ack(1, {{3, 3}});
  EXPECT_EQ(r.rec.scoreboard().dupacks(), 1u);
  r.ack(4, {{5, 5}});  // SND.UNA moves: reset, then counted
  EXPECT_EQ(r.rec.scoreboard().dupacks(), 1u);
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  r.ack(4, {{5, 5}, {7, 7}});
  EXPECT_EQ(r.rec.scoreboard().dupacks(), 2u);
  EXPECT_FALSE(r.pkt(4).lost);
  r.ack(4, {{5, 5}, {7, 7}, {9, 9}});
  EXPECT_EQ(r.rec.scoreboard().dupacks(), 3u);
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_TRUE(r.pkt(4).lost);
  EXPECT_FALSE(r.pkt(6).lost);  // 7, 9 above
  EXPECT_EQ(r.stats.TcpExtTCPSackRecovery, 1u);
}

// A partial ACK with SACK marks nothing by itself (the RFC 6582 head rule is
// for connections without SACK, M2-DESIGN §1.2); IsLost marks the new head
// once 3 SACKed segments lie above it.
TEST(SackScoreboard, PartialAckMarksOnlyByIsLost) {
  Rig r(utcp::test::rig::rfc_cfg());
  r.send_new(10);
  r.now += 100ms;
  r.ack(1, {{2, 4}});
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.transmit(), Sent{"R1"});
  r.now += 100ms;
  r.ack(5, {{7, 7}});  // partial ACK: 5 is the head, one SACKed above
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_FALSE(r.pkt(5).lost);
  r.ack(5, {{7, 8}});
  EXPECT_FALSE(r.pkt(5).lost);
  r.ack(5, {{7, 9}});  // 7, 8, 9 above 5 and 6
  EXPECT_TRUE(r.pkt(5).lost);
  EXPECT_TRUE(r.pkt(6).lost);
  EXPECT_EQ(r.q.counters().lost_out, 2u);
  // Without SACK a partial ACK marks the new head (RFC 6582 §3.2 step 5).
  Rig n(utcp::test::rig::rfc_cfg(), 14, false);
  n.send_new(10);
  n.now += 100ms;
  for (int i = 0; i < 3; ++i) {
    n.ack(1);
  }
  ASSERT_EQ(n.rec.state(), CaState::recovery);
  n.ack(4);
  EXPECT_TRUE(n.pkt(4).lost);
}

// NextSeg (RFC 6675 §4): rule 1 (lost segments above HighRxt, the engine's
// lost loop), rule 2 (new data), rule 3 (unSACKed below the highest SACK,
// above HighRxt), with HighRxt after each. ssthresh 5: cwnd 5 in Recovery.
TEST(SackScoreboard, NextSegRulesOneToThree) {
  Rig r(utcp::test::rig::rfc_cfg(), 5);
  r.cc.cwnd = 10;
  r.send_new(10);
  r.now += 100ms;
  r.ack(1, {{2, 4}});
  ASSERT_EQ(r.cc.cwnd, 5u);
  // pipe 10 - 3 - 1 = 6: only the exempt fast retransmission (rule 1).
  EXPECT_EQ(r.transmit(), Sent{"R1"});
  EXPECT_EQ(r.rec.scoreboard().high_rxt(), 1000u);
  r.ack(1, {{2, 4}, {6, 6}});  // pipe 6
  EXPECT_EQ(r.transmit(), Sent{});
  r.ack(1, {{2, 4}, {6, 6}, {8, 8}});  // pipe 5
  EXPECT_EQ(r.transmit(), Sent{});
  // SACK 10: 6, 8, 10 above 5, which is lost; 7 has 2 above, 9 one. pipe
  // 10 - 6 - 2 + 1 = 3. Rule 1 resends 5 (pipe 4, HighRxt 5000); no new data
  // (rule 2); rule 3: the lowest unSACKed segment at or above HighRxt below
  // the highest SACK, without a retransmission in flight, is 7 (pipe 5).
  r.ack(1, {{2, 4}, {6, 6}, {8, 8}, {10, 10}});
  EXPECT_TRUE(r.pkt(5).lost);
  EXPECT_FALSE(r.pkt(7).lost);
  EXPECT_EQ(r.transmit(), (Sent{"R5", "R7"}));
  EXPECT_EQ(r.rec.scoreboard().high_rxt(), 7000u);
  EXPECT_EQ(r.in_flight(), 5u);
  // Partial ACK of 1: SND.UNA 4000, pipe 6 - 3 - 1 + 2 = 4. Rule 3: 9.
  r.now += 100ms;
  r.ack(5, {{6, 6}, {8, 8}, {10, 10}});
  EXPECT_EQ(r.transmit(), Sent{"R9"});
  EXPECT_EQ(r.rec.scoreboard().high_rxt(), 9000u);
  EXPECT_EQ(r.rec.scoreboard().rescue_rxt(), 1000u);
}

// Rule 4, the rescue retransmission: a tail whose last segments are lost
// with nothing SACKed above them. Not before SND.UNA passes RescueRxt
// (4.a), then the highest unSACKed segment once; RescueRxt = RecoveryPoint,
// HighRxt unchanged (C.4).
TEST(SackScoreboard, RescueRetransmissionOncePerRecovery) {
  Rig r(utcp::test::rig::rfc_cfg(), 5);
  r.cc.cwnd = 10;
  r.send_new(10);  // 1, 9 and 10 are lost
  r.now += 100ms;
  r.ack(1, {{2, 8}});
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  // pipe 10 - 7 - 1 = 2. R1 (pipe 3); no rule 3 segment (2-8 SACKed); no
  // rescue while SND.UNA 0 <= RescueRxt 1000.
  EXPECT_EQ(r.transmit(), Sent{"R1"});
  EXPECT_EQ(r.rec.scoreboard().rescue_rxt(), 1000u);
  // Partial ACK of 1-8: SND.UNA 8000 > 1000, pipe 2. Rule 4: segment 10.
  r.now += 100ms;
  r.ack(9);
  EXPECT_EQ(r.transmit(), Sent{"R10"});
  EXPECT_EQ(r.rec.scoreboard().rescue_rxt(), 10'000u);  // recover
  EXPECT_EQ(r.rec.scoreboard().high_rxt(), 1000u);
  EXPECT_EQ(r.in_flight(), 3u);  // 9, and 10 counted twice (not lost)
  // A duplicate ACK: pipe 3 < 5, but SND.UNA 8000 <= RescueRxt: no rescue.
  r.ack(9);
  EXPECT_EQ(r.transmit(), Sent{});
  // The rescue arrives (SACK 10): 9 is unSACKed below the highest SACK and
  // above HighRxt, so rule 3 sends it.
  r.ack(9, {{10, 10}});
  EXPECT_EQ(r.transmit(), Sent{"R9"});
  EXPECT_EQ(r.rec.scoreboard().high_rxt(), 9000u);
}

// The rescue guard alone: after a rescue, rule 4 names nothing while SND.UNA
// <= RescueRxt, even when the highest unSACKed segment has nothing in flight.
TEST(SackScoreboard, RescueGuard) {
  Queue s(4, 1000);
  Rfc6675Scoreboard sb;
  sb.on_enter_recovery(1000);
  EXPECT_EQ(sb.next_seg(s.q, 0, 1 << 20), std::nullopt);  // SND.UNA 0 <= 1000
  EXPECT_EQ(sb.next_seg(s.q, 2000, 1 << 20), 3000u);      // the highest unSACKed
  sb.on_retransmit(*s.q.find(3000), 4000);                  // sent: RescueRxt = recover
  EXPECT_EQ(sb.rescue_rxt(), 4000u);
  EXPECT_EQ(sb.high_rxt(), 1000u);
  EXPECT_EQ(sb.next_seg(s.q, 3000, 1 << 20), std::nullopt);
  // A segment beyond the receive window is not named (only the head is).
  Rfc6675Scoreboard w;
  w.on_enter_recovery(1000);
  EXPECT_EQ(w.next_seg(s.q, 2000, 3000), std::nullopt);
}

// RTO during recovery (RFC 6675 §5.1): RecoveryPoint = HighData, Loss, and no
// new recovery before SND.UNA reaches it, however many DupAcks arrive.
TEST(SackScoreboard, RtoDuringRecovery) {
  Rig r(utcp::test::rig::rfc_cfg());
  r.send_new(10);
  r.now += 100ms;
  r.ack(1, {{2, 4}});
  ASSERT_EQ(r.rec.state(), CaState::recovery);
  r.send_new(5);  // HighData: 15 packets
  r.now += 2s;
  r.fire_rto();
  EXPECT_EQ(r.rec.state(), CaState::loss);
  EXPECT_EQ(r.rec.recover(), off_of(16));
  EXPECT_EQ(r.rec.scoreboard().dupacks(), 0u);
  // SACKs in Loss are not DupAcks for a new recovery.
  r.now += 100ms;
  r.ack(1, {{2, 4}, {6, 6}});
  r.ack(1, {{2, 4}, {6, 8}});
  r.ack(1, {{2, 4}, {6, 10}});
  EXPECT_EQ(r.rec.state(), CaState::loss);
  EXPECT_EQ(r.rec.scoreboard().dupacks(), 0u);
  EXPECT_EQ(r.stats.TcpExtTCPSackRecovery, 1u);
  // SND.UNA reaches RecoveryPoint: Open; a later loss is a new recovery.
  r.ack(16);
  EXPECT_EQ(r.rec.state(), CaState::open);
  r.send_new(10);
  r.now += 100ms;
  r.ack(16, {{17, 19}});
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.stats.TcpExtTCPSackRecovery, 2u);
}

// The engine's NextSeg step (tcp_output.cpp step 4): retransmit_seg cuts a
// segment longer than the current MSS, and the tail of a segment not marked
// lost then counts in flight too, so a rule 3 segment that will be cut needs
// room for two packets. Here the stack's ACKs carry a SACK block (the peer's
// data has a hole), so the current MSS is 12 bytes below the segment size.
// Every rexmit leaves in_flight <= cwnd (sweep seeds 661, 1325, 1480, 1676,
// 1983 found the overrun).
TEST(SackScoreboard, EngineRuleThreeLeavesRoomForTheCut) {
  namespace t = utcp::test;
  namespace w = utcp::wire;
  using namespace utcp::test::tcpt;
  struct Sink final : utcp::TraceSink {
    void on_event(const utcp::TraceEvent& e) override {
      if (e.kind == utcp::TraceKind::tx && (e.tx == utcp::TxKind::rexmit)) {
        rexmit.push_back(e);
      }
    }
    std::vector<utcp::TraceEvent> rexmit;
  };
  utcp::StackConfig cfg = config(t::Side::b, utcp::ProfileId::rfc);
  cfg.tcp.initial_cwnd = 10;
  cfg.trace_mask = utcp::trace_bit(utcp::TraceKind::tx);
  Scripted c(cfg);
  ASSERT_TRUE(c.accept());
  Sink sink;
  c.stack().set_trace_sink(&sink);
  const std::uint32_t mss = c.stack().tcp_info(c.h)->snd_mss;
  ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(10 * std::size_t{mss})));
  const auto segs = c.out();
  ASSERT_EQ(segs.size(), 10u);
  const auto seg = [&](std::uint32_t k) { return segs[0].v.h.seq + (k - 1) * mss; };  // 1-based
  // A hole in the peer's data: every later ACK of the stack carries a SACK block.
  c.nxt = c.nxt + 100;
  c.send_data(100);
  static_cast<void>(c.out());
  const auto ack = [&](utcp::Seq32 cum, std::initializer_list<std::pair<std::uint32_t, std::uint32_t>> sacked) {
    t::TcpSpec a = c.spec(w::tcp_ack);
    a.ack = cum;
    for (const auto& [first, last] : sacked) {
      a.opt.sack[a.opt.sack_count++] = {seg(first), seg(last + 1)};
    }
    c.send(a);
    return c.out();
  };
  // SACK 2-4, 6, 8: IsLost(1) (5 above); 5 and 7 have 2 and 1 above. cwnd =
  // ssthresh = 5, pipe 4: the exempt fast retransmission of 1, cut in two.
  ack(seg(1), {{2, 4}, {6, 6}, {8, 8}});
  ASSERT_EQ(c.stack().tcp_info(c.h)->ca_state, CaState::recovery);
  // 1's head arrives, then its tail: SND.UNA reaches 5, pipe 6 - 2 = 4 < 5.
  // Rule 3 names 5, a full segment that would be cut: 4 + 2 > 5, so it waits.
  ack(seg(1) + (mss - 12), {{2, 4}, {6, 6}, {8, 8}});
  const auto o = ack(seg(5), {{6, 6}, {8, 8}});
  for (const Parsed& p : o) {
    EXPECT_FALSE(is_data(p.v) && p.v.h.seq == seg(5));
  }
  // SACK 10: 5 is IsLost now (6, 8, 10 above) and the lost loop resends it
  // (its cut tail stays lost: no extra packet in flight).
  const auto o2 = ack(seg(5), {{6, 6}, {8, 8}, {10, 10}});
  ASSERT_FALSE(o2.empty());
  EXPECT_TRUE(std::any_of(o2.begin(), o2.end(),
                          [&](const Parsed& p) { return is_data(p.v) && p.v.h.seq == seg(5); }));
  ASSERT_FALSE(sink.rexmit.empty());
  for (const utcp::TraceEvent& e : sink.rexmit) {
    EXPECT_LE(e.in_flight, e.cwnd) << e.seq;
  }
  c.stack().set_trace_sink(nullptr);
  c.stack().debug_check();
}

}  // namespace
