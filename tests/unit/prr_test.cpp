// m2a-recovery acceptance test 1: PRR, Linux variant (M2-DESIGN §1.8, §4.1;
// RFC 9937; Linux 7.0 tcp_cwnd_reduction, tcp_input.c:2984). Every expected
// value is derived by hand in the comments.
#include "core/tcp/prr.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include "recovery_rig.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::CaState;
using utcp::PrrState;
using utcp::Range;
using utcp::Time;
using utcp::XmitTimer;
using utcp::test::rig::Rig;
using Sent = std::vector<std::string>;

// The formula alone.
TEST(Prr, FormulaBranches) {
  PrrState p;
  // Nothing delivered, or no reduction started: no answer (Linux returns).
  EXPECT_EQ(utcp::prr_cwnd(p, 14, 16, 1, 0, false), std::nullopt);
  utcp::prr_init(p, 20);
  EXPECT_EQ(utcp::prr_cwnd(p, 14, 16, 0, 0, false), std::nullopt);
  EXPECT_EQ(p.delivered, 0u);
  // delta = 14 - 16 < 0: ceil(14 * 1 / 20) - 0 = 1, cwnd 16 + 1.
  EXPECT_EQ(utcp::prr_cwnd(p, 14, 16, 1, 1, false), 17u);
  EXPECT_EQ(p.delivered, 1u);
  p.out = 1;
  // delta = 14 - 10 = 4: max(prr.delivered 1 + 2 - out 1, 2) = 2, +1 SafeACK
  // (SND.UNA advanced, nothing lost) = 3, min(4, 3) = 3: cwnd 13.
  EXPECT_EQ(utcp::prr_cwnd(p, 14, 10, 2, 0, true), 13u);
  // With a new loss: no +1. in_flight 8, delta 6: max(5 - 1, 2) = 4, min(6,
  // 4) = 4, cwnd 12 (13 with the +1).
  EXPECT_EQ(utcp::prr_cwnd(p, 14, 8, 2, 1, true), 12u);
  // prr.out 0 forces sndcnt >= 1 even where the formula gives 0: delta 0,
  // min(0, 1) = 0, then max(0, 1).
  PrrState q;
  utcp::prr_init(q, 10);
  EXPECT_EQ(utcp::prr_cwnd(q, 5, 5, 1, 0, false), 6u);
  q.out = 1;
  EXPECT_EQ(utcp::prr_cwnd(q, 5, 5, 1, 0, false), 5u);
  // More sent than the proportional share: delta = 5 - 9 < 0, ceil(5 * 3 /
  // 10) - 4 = 2 - 4 = -2, raised to 0 by the max with (prr.out ? 0 : 1):
  // cwnd = in_flight, nothing more goes out.
  PrrState r;
  utcp::prr_init(r, 10);
  r.out = 4;
  EXPECT_EQ(utcp::prr_cwnd(r, 5, 9, 3, 0, false), 9u);
}

// The M2-DESIGN §4.1 script in linux_compat (RACK marks, PRR reduces): cwnd
// 20, a fixed ssthresh of 14 (CUBIC's value for cwnd 20), packets 1-20 sent
// back to back at t0, srtt 100 ms, min_rtt 40 ms, no reordering seen. Packet
// 1 is late (its original arrives at +110 ms), 15-19 are lost, 15's original
// arrives late too. The application writes packets 21-40 when recovery
// starts. Per ACK: cwnd, prr.out and what transmit() sends.
TEST(PrrScript, LinuxCompatPerAck) {
  Rig r(utcp::test::rig::linux_cfg());
  const Time t0 = r.now;
  r.send_new(20);

  // +100: SACK 2. reo_wnd = min(min_rtt / 4, srtt) = 10 ms (sacked_out 1 <
  // reordering 3); packet 1 has 100 + 10 - 100 = 10 ms left: REO at +100 +
  // ceil(10 + 2) = +112. Disorder, cwnd unchanged, nothing to send.
  r.now = t0 + 100ms;
  r.ack(1, {{2, 2}});
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::reo, t0 + 112ms));
  EXPECT_EQ(r.cc.cwnd, 20u);
  EXPECT_EQ(r.transmit(), Sent{});
  // +101: SACK 2-3, the same at rack.rtt 101: REO at +113.
  r.now = t0 + 101ms;
  r.ack(1, {{2, 3}});
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::reo, t0 + 113ms));
  EXPECT_FALSE(r.pkt(1).lost);

  // +102: SACK 2-4. sacked_out 3 = reordering: reo_wnd 0, packet 1 has 102 +
  // 0 - 102 = 0 left: lost. Recovery, prior_cwnd 20, ssthresh 14. in_flight
  // 20 - 3 - 1 = 16, delta -2: sndcnt = (14 * 1 + 19) / 20 - 0 = 1, cwnd 17.
  r.now = t0 + 102ms;
  r.ack(1, {{2, 4}});
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_TRUE(r.pkt(1).lost);
  EXPECT_EQ(r.rec.prr().prior_cwnd, 20u);
  EXPECT_EQ(r.cc.ssthresh, 14u);
  EXPECT_EQ(r.cc.cwnd, 17u);
  r.write(20);
  EXPECT_EQ(r.transmit(), Sent{"R1"});  // through the cwnd gate: 16 < 17
  EXPECT_EQ(r.rec.prr().out, 1u);
  EXPECT_EQ(r.stats.TcpExtTCPFastRetrans, 1u);

  // +103: SACK 2-5. in_flight 20 - 4 - 1 + 1 = 16: (14 * 2 + 19) / 20 - 1 = 1,
  // cwnd 17, one new packet.
  r.now = t0 + 103ms;
  r.ack(1, {{2, 5}});
  EXPECT_EQ(r.cc.cwnd, 17u);
  EXPECT_EQ(r.transmit(), Sent{"N21"});
  EXPECT_EQ(r.rec.prr().out, 2u);
  // +104: SACK 2-6. in_flight 21 - 5 = 16: (42 + 19) / 20 - 2 = 1, cwnd 17.
  r.now = t0 + 104ms;
  r.ack(1, {{2, 6}});
  EXPECT_EQ(r.cc.cwnd, 17u);
  EXPECT_EQ(r.transmit(), Sent{"N22"});
  EXPECT_EQ(r.rec.prr().out, 3u);
  // +105: SACK 2-7. in_flight 22 - 6 = 16: (56 + 19) / 20 - 3 = 0, cwnd =
  // in_flight + 0 = 16.
  r.now = t0 + 105ms;
  r.ack(1, {{2, 7}});
  EXPECT_EQ(r.cc.cwnd, 16u);
  EXPECT_EQ(r.transmit(), Sent{});
  EXPECT_EQ(r.rec.prr().out, 3u);

  // +105: a D-SACK-only ACK (packet 2 arrived twice). dsack_dups 1 <=
  // total_retrans 1: valid, one packet delivered (M2-DESIGN §1.6), so PRR
  // runs: in_flight 16, (14 * 5 + 19) / 20 - 3 = 1, cwnd 17.
  const auto d = r.ack(1, {{2, 7}}, Range{utcp::test::rig::off_of(2), utcp::test::rig::off_of(3)});
  EXPECT_EQ(d.delivered, 1u);
  EXPECT_EQ(r.rec.prr().delivered, 5u);
  EXPECT_EQ(r.cc.cwnd, 17u);
  EXPECT_EQ(r.transmit(), Sent{"N23"});
  EXPECT_EQ(r.rec.prr().out, 4u);

  // +106: SACK 2-14, 7 newly. in_flight 23 - 13 = 10, delta 4 >= 0:
  // max(prr.delivered 12 - out 4, 7) = 8, no SND.UNA advance, min(delta 4, 8)
  // = 4 caps it: cwnd 14.
  r.now = t0 + 106ms;
  r.ack(1, {{2, 14}});
  EXPECT_EQ(r.cc.cwnd, 14u);
  EXPECT_EQ(r.transmit(), (Sent{"N24", "N25", "N26", "N27"}));
  EXPECT_EQ(r.rec.prr().out, 8u);

  // +110: packet 1's original arrives (cumulative ACK to 15) and 20 is
  // SACKed. RACK skips packet 1 (retransmitted 8 ms ago < min_rtt 40 ms:
  // ambiguous) and advances on 20 (t0, rtt 110): 15-19, sent at t0 with
  // lower ends, have 110 + 0 - 110 = 0 left: lost. delivered 1 + 1 = 2,
  // newly lost 5. in_flight 13 - 1 - 5 = 7, delta 7: max(14 - 8, 2) = 6;
  // SND.UNA advanced but with a new loss, so no +1: min(7, 6) = 6, cwnd 13.
  r.now = t0 + 110ms;
  const auto b = r.ack(15, {{20, 20}});
  EXPECT_EQ(b.delivered, 2u);
  EXPECT_EQ(b.newly_lost, 5u);
  EXPECT_EQ(r.q.counters().lost_out, 5u);
  EXPECT_EQ(r.cc.cwnd, 13u);
  EXPECT_EQ(r.transmit(), (Sent{"R15", "R16", "R17", "R18", "R19", "N28"}));
  EXPECT_EQ(r.rec.prr().out, 14u);

  // +149: packet 15's original arrives: cumulative ACK to 16. Ambiguous for
  // RACK (39 ms < 40 ms), nothing marked. in_flight 13 - 1 - 4 + 4 = 12,
  // delta 2: max(15 - 14, 1) = 1, +1 (SND.UNA advanced, no new loss: the
  // SafeACK rule) = 2, min(2, 2): cwnd 14.
  r.now = t0 + 149ms;
  const auto a = r.ack(16, {{20, 20}});
  EXPECT_EQ(a.newly_lost, 0u);
  EXPECT_EQ(r.cc.cwnd, 14u);
  EXPECT_EQ(r.transmit(), (Sent{"N29", "N30"}));
  EXPECT_EQ(r.rec.prr().out, 16u);

  // +150: SACK 21 (sent at +103). RACK moves to it; 22 was sent later:
  // nothing lost. in_flight 13, delta 1: max(16 - 16, 1) = 1, min(1, 1):
  // cwnd 14.
  r.now = t0 + 150ms;
  r.ack(16, {{20, 21}});
  EXPECT_EQ(r.cc.cwnd, 14u);
  EXPECT_EQ(r.transmit(), Sent{"N31"});
  EXPECT_EQ(r.rec.prr().out, 17u);
  EXPECT_EQ(r.stats.TcpExtTCPSackRecovery, 1u);

  // Everything up to 31 acknowledged, above recover (20 packets): Open with
  // cwnd = ssthresh (tcp_end_cwnd_reduction).
  r.now = t0 + 300ms;
  r.ack(32);
  EXPECT_EQ(r.rec.state(), CaState::open);
  EXPECT_EQ(r.cc.cwnd, 14u);
  r.q.check_invariants();
}

// The same script with recovery_reduction rfc6675 (the rfc profile: RFC 6675
// marking, no RACK): cwnd = ssthresh = 14 at entry, the fast retransmission
// exempt from the cwnd gate, and no new data until pipe < 14.
TEST(PrrScript, Rfc6675SameScript) {
  Rig r(utcp::test::rig::rfc_cfg());
  const Time t0 = r.now;
  r.send_new(20);
  r.now = t0 + 100ms;
  r.ack(1, {{2, 2}});
  r.now = t0 + 101ms;
  r.ack(1, {{2, 3}});
  EXPECT_EQ(r.rec.state(), CaState::disorder);
  EXPECT_EQ(r.rec.scoreboard().dupacks(), 2u);
  EXPECT_EQ(r.timer().first, XmitTimer::rto);  // no RACK, no REO timer
  // +102: the third DupAck, and 3 SACKed segments above packet 1 (IsLost):
  // Recovery with cwnd = ssthresh = 14.
  r.now = t0 + 102ms;
  r.ack(1, {{2, 4}});
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.cc.cwnd, 14u);
  EXPECT_TRUE(r.rec.fast_rexmit_pending());
  r.write(20);
  // pipe 20 - 3 - 1 = 16 >= 14: only the exempt fast retransmission.
  EXPECT_EQ(r.transmit(), Sent{"R1"});
  EXPECT_EQ(r.in_flight(), 17u);
  // pipe 16, 15, 14: nothing.
  for (std::uint32_t k = 5; k <= 7; ++k) {
    r.now += 1ms;
    r.ack(1, {{2, k}});
    EXPECT_EQ(r.cc.cwnd, 14u);
    EXPECT_EQ(r.transmit(), Sent{}) << k;
  }
  EXPECT_EQ(r.in_flight(), 14u);
  // The D-SACK-only ACK changes nothing under RFC 6675.
  r.ack(1, {{2, 7}}, Range{utcp::test::rig::off_of(2), utcp::test::rig::off_of(3)});
  EXPECT_EQ(r.cc.cwnd, 14u);
  EXPECT_EQ(r.transmit(), Sent{});
  // SACK 2-14: pipe 20 - 13 - 1 + 1 = 7 < 14: the first new data, 7 packets.
  r.now = t0 + 106ms;
  r.ack(1, {{2, 14}});
  EXPECT_EQ(r.transmit(), (Sent{"N21", "N22", "N23", "N24", "N25", "N26", "N27"}));
  // Exit: cwnd = ssthresh.
  r.now = t0 + 300ms;
  r.ack(28);
  EXPECT_EQ(r.rec.state(), CaState::open);
  EXPECT_EQ(r.cc.cwnd, 14u);
}

// tcp_rack_reo_timeout: the REO timer enters Recovery and runs
// cwnd_reduction(1, newly_lost, 0).
TEST(PrrScript, ReoTimerEntry) {
  Rig r(utcp::test::rig::linux_cfg());
  const Time t0 = r.now;
  r.send_new(20);
  r.now = t0 + 100ms;
  r.ack(1, {{2, 2}});
  r.now = t0 + 101ms;
  r.ack(1, {{2, 3}});
  ASSERT_EQ(r.timer(), std::make_pair(XmitTimer::reo, t0 + 113ms));
  // At +113 packet 1 has rack.rtt 101 + reo_wnd 10 - 113 = -2: lost. in_flight
  // 20 - 2 - 1 = 17, delta 14 - 17 < 0: sndcnt = (14 * 1 + 19) / 20 - 0 = 1,
  // cwnd 18; the retransmission goes through the gate.
  r.now = t0 + 113ms;
  EXPECT_EQ(r.fire_reo(), Sent{"R1"});
  EXPECT_EQ(r.rec.state(), CaState::recovery);
  EXPECT_EQ(r.rec.prr().delivered, 1u);
  EXPECT_EQ(r.rec.prr().out, 1u);
  EXPECT_EQ(r.cc.cwnd, 18u);
  EXPECT_EQ(r.stats.rack_reo_timeouts, 1u);
  EXPECT_EQ(r.stats.TcpExtTCPSackRecovery, 1u);
  // The head's retransmission re-armed a full RTO.
  EXPECT_EQ(r.timer(), std::make_pair(XmitTimer::rto, r.now + r.rtt.rto_backed_off(0)));
}

}  // namespace
