// m2a-recovery acceptance test 7 and M2-DESIGN §4.3's directed cases: loss
// recovery end to end in the simulator. A tail loss of the last two packets
// is repaired by a tail loss probe without an RTO in linux_compat and by the
// RTO in rfc; a lost retransmission is repaired by RACK without an RTO in
// linux_compat; the REO timer enters Recovery; RFC 6675's rescue
// retransmission repairs a tail loss in rfc; a D-SACK widens RACK's reorder
// window; a receiver reneges under RACK; a PMTU drop arrives in Recovery;
// 100 MB under 1 % Bernoulli loss and under 5 % burst loss, per profile, with
// SACK on and off, arrive intact (the StreamChecker compares every byte) with
// no checker violation. Every run is repeated and must give the same digest.
#include <cstdint>
#include <functional>
#include <memory>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <ostream>
#include <utility>
#include <vector>

#include "support/packet_builder.hpp"
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

constexpr std::uint32_t seg = 1448;  // MSS 1460 less the timestamp option

std::string profile_name(ProfileId p) { return p == ProfileId::rfc ? "rfc" : "linux_compat"; }

// Drops data segments node 0 sends, chosen by stream offset, length and copy
// number (`drop(off, len, copy)`, copy 1 = the first transmission), as
// M2-DESIGN §4.2's scripted drops do. `hold(off, copy)` instead delays a
// segment past the next one: node 0's copy is withheld, and when node 1
// receives the first data segment above it, the withheld one is delivered
// `extra` later (0: right after that segment, before anything else).
struct OffsetDropper {
  std::function<bool(std::uint64_t off, std::uint32_t len, std::uint32_t copy)> drop;
  std::function<std::optional<Duration>(std::uint64_t off, std::uint32_t copy)> hold;
  std::optional<Seq32> isn;
  std::map<std::uint64_t, std::uint32_t> copies;
  std::set<std::uint64_t> dropped;
  struct Held {
    std::uint64_t off;
    Duration extra;
    std::vector<std::byte> bytes;
  };
  std::vector<Held> held;

  void install(Tap& sender, Tap& receiver) {
    sender.egress = [this](Tap&, Time t, std::span<const std::byte> d) {
      const auto s = parse_seg(0, true, t, d);
      if (!s) {
        return true;
      }
      if (s->has(wire::tcp_syn)) {
        isn = s->h.seq;
        return true;
      }
      if (!isn || s->len == 0) {
        return true;
      }
      const std::uint64_t off = s->h.seq - (*isn + 1);
      const std::uint32_t copy = ++copies[off];
      if (drop && drop(off, s->len, copy)) {
        dropped.insert(off);
        return false;
      }
      if (hold) {
        if (const std::optional<Duration> extra = hold(off, copy)) {
          held.push_back(Held{off, *extra, std::vector<std::byte>(d.begin(), d.end())});
          return false;
        }
      }
      return true;
    };
    receiver.ingress = [this](Tap& tap, Time t, std::span<const std::byte> d) {
      const auto s = parse_seg(1, false, t, d);
      if (held.empty() || !s || !isn || s->len == 0 || s->has(wire::tcp_syn)) {
        return true;
      }
      const std::uint64_t off = s->h.seq - (*isn + 1);
      bool deliver_here = true;
      for (auto it = held.begin(); it != held.end();) {
        if (off <= it->off) {
          ++it;
          continue;
        }
        if (it->extra == Duration::zero()) {
          // This segment first, then the withheld one, synchronously.
          if (deliver_here) {
            tap.inner().receive(t, d);
            deliver_here = false;
          }
          tap.inner().receive(t, it->bytes);
        } else {
          (void)tap.inject_at(t + it->extra, std::move(it->bytes));
        }
        it = held.erase(it);
      }
      return deliver_here;
    };
  }
};

// One bulk transfer from node 0 to node 1 over 10 ms each way, run twice.
struct TwoRuns {
  Outcome first;
  std::uint64_t second_digest = 0;
  std::map<std::uint64_t, std::uint32_t> copies;  // first run: transmissions per offset
  Seq32 isn;                                      // node 0's ISN in the first run
};

// `more` installs further hooks on the taps of each run (after the dropper's).
TwoRuns run_twice(const Scenario& s, const std::function<void(OffsetDropper&)>& set_drops,
                  const std::function<void(std::vector<Tap*>&, OffsetDropper&)>& more = {}) {
  TwoRuns r;
  for (int i = 0; i < 2; ++i) {
    auto dropper = std::make_shared<OffsetDropper>();
    set_drops(*dropper);
    RunSpec spec;
    spec.keep_wire = i == 0;
    spec.setup = [dropper, &more](std::vector<Tap*>& taps) {
      dropper->install(*taps[0], *taps[1]);
      if (more) {
        more(taps, *dropper);
      }
    };
    Outcome o = run_sim(s, spec);
    if (i == 0) {
      r.first = std::move(o);
      r.copies = dropper->copies;
      r.isn = dropper->isn.value_or(Seq32{});
    } else {
      r.second_digest = o.result.digest;
    }
  }
  return r;
}

// Node 0's tx events of data at stream offset `off` (any kind).
std::vector<TraceEvent> tx_at(const TwoRuns& r, std::uint64_t off) {
  const std::uint32_t seq = (r.isn + 1 + static_cast<std::uint32_t>(off)).raw();
  return r.first.events(0, [seq](const TraceEvent& e) {
    return e.kind == TraceKind::tx && e.len > 0 && e.seq == seq;
  });
}

// Node 0's xmit timer expiries of kind `k`.
std::vector<TraceEvent> fired(const Outcome& o, TraceTimer k) {
  return o.events(0, [k](const TraceEvent& e) {
    return e.kind == TraceKind::timer && e.timer == k && e.timer_op == TimerOp::fired;
  });
}

Scenario directed(std::uint64_t seed, ProfileId profile, std::uint64_t bytes) {
  Scenario s = two_node_scenario(seed, clean_link(10ms), clean_link(10ms));
  for (NodeSpec& n : s.node) {
    n.profile = profile;
  }
  s.conn.push_back(bulk(bytes, 0));
  return s;
}

// The first transmissions of the last two packets of a 30-packet transfer
// are lost. linux_compat: the PTO resends the last packet (TLP), whose SACK
// lets RACK mark the other one lost; no RTO. rfc (no TLP): the RTO repairs
// them.
TEST(TcpRecoverySim, TailLossOfTheLastTwoPackets) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(profile_name(profile));
    constexpr std::uint64_t total = 30 * std::uint64_t{seg};
    const Scenario s = directed(7100 + static_cast<std::uint64_t>(profile), profile, total);
    const TwoRuns r = run_twice(s, [](OffsetDropper& d) {
      d.drop = [](std::uint64_t off, std::uint32_t, std::uint32_t copy) {
        return copy == 1 && off >= total - 2 * seg;
      };
    });
    const Outcome& o = r.first;
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
    EXPECT_EQ(r.second_digest, o.result.digest);
    const StackStats& st = o.stats[0];
    if (profile == ProfileId::linux_compat) {
      EXPECT_EQ(st.TcpExtTCPTimeouts, 0u);
      EXPECT_EQ(st.TcpExtTCPLossProbes, 1u);
      EXPECT_EQ(st.TcpExtTCPSackRecovery, 1u);
    } else {
      EXPECT_GE(st.TcpExtTCPTimeouts, 1u);
      EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);
    }
    // Both lost packets were sent again (the application's writes leave a
    // short segment here and there, so the last two start where they start).
    ASSERT_GE(r.copies.size(), 2u);
    const auto last = r.copies.rbegin();
    EXPECT_GE(last->second, 2u);
    EXPECT_GE(std::next(last)->second, 2u);
    EXPECT_GE(std::next(last)->first, total - 2 * seg);
  }
}

// The original and the first retransmission of the first packet starting at
// or after byte 100 * 1448 are lost. RACK finds the
// retransmission lost once packets sent after it are SACKed (Linux
// FLAG_LOST_RETRANS) and sends it a third time; no RTO.
TEST(TcpRecoverySim, LostRetransmissionRepairedByRack) {
  constexpr std::uint64_t total = 300 * std::uint64_t{seg};
  constexpr std::uint64_t victim = 100 * std::uint64_t{seg};
  const Scenario s = directed(7200, ProfileId::linux_compat, total);
  const TwoRuns r = run_twice(s, [](OffsetDropper& d) {
    d.drop = [chosen = std::optional<std::uint64_t>{}](std::uint64_t off, std::uint32_t,
                                                       std::uint32_t copy) mutable {
      if (!chosen && off >= victim) {
        chosen = off;
      }
      return off == chosen && copy <= 2;
    };
  });
  const Outcome& o = r.first;
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
  EXPECT_EQ(r.second_digest, o.result.digest);
  const StackStats& st = o.stats[0];
  EXPECT_EQ(st.TcpExtTCPTimeouts, 0u);
  EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);
  EXPECT_GE(st.TcpRetransSegs, 2u);
  // Three transmissions of the victim, the third one delivered.
  const auto v = r.copies.lower_bound(victim);
  ASSERT_NE(v, r.copies.end());
  EXPECT_EQ(v->second, 3u);
}

// M2-DESIGN §1.6 "REO timer": the first transmission of the segment before
// the last two full ones is lost. Its two successors are SACKed, fewer than
// reordering (3), so the reorder window is min_rtt / 4 and RACK arms the REO
// timer instead of marking it; the expiry marks it lost, enters Recovery and
// retransmits it. No PTO (the REO timer replaced it), no RTO.
TEST(TcpRecoverySim, ReoTimerEntersRecovery) {
  constexpr std::uint64_t total = 30 * std::uint64_t{seg};
  constexpr std::uint64_t cut = total - 2 * seg;
  const Scenario s = directed(7400, ProfileId::linux_compat, total);
  const TwoRuns r = run_twice(s, [](OffsetDropper& d) {
    d.drop = [](std::uint64_t off, std::uint32_t len, std::uint32_t copy) {
      return copy == 1 && off < cut && off + len >= cut;
    };
  });
  const Outcome& o = r.first;
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
  EXPECT_EQ(r.second_digest, o.result.digest);
  // The victim and the segments above it: two, so two SACKs at most.
  const auto victim = std::prev(r.copies.lower_bound(cut));
  ASSERT_EQ(std::distance(std::next(victim), r.copies.end()), 2);
  EXPECT_EQ(victim->second, 2u);
  const StackStats& st = o.stats[0];
  EXPECT_EQ(st.rack_reo_timeouts, 1u);
  EXPECT_EQ(st.TcpExtTCPSackRecovery, 1u);
  EXPECT_EQ(st.TcpExtTCPTimeouts, 0u);
  EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);
  // The retransmission goes out in Recovery at the REO expiry.
  const auto tx = tx_at(r, victim->first);
  ASSERT_EQ(tx.size(), 2u);
  EXPECT_EQ(tx[1].tx, TxKind::rexmit);
  EXPECT_EQ(tx[1].ca, CaState::recovery);
  const auto reo = fired(o, TraceTimer::reo);
  ASSERT_EQ(reo.size(), 1u);
  EXPECT_EQ(reo[0].t, tx[1].t);
}

// RFC 6675 NextSeg rule 4 (§4, the rescue retransmission; M2-DESIGN §1.4):
// rfc profile, the first transmissions of the segment covering byte
// total - 6 * 1448 and of the last segment are lost. The SACKs of the
// segments between enter Recovery (DupThresh) and the first is fast
// retransmitted; nothing is SACKed above the last segment, so neither IsLost
// nor rule 3 names it. Once the retransmission is acknowledged (SND.UNA >
// RescueRxt), rule 4 resends the highest unSACKed segment, the last one, in
// Recovery: no RTO, which without rule 4 would repair it (RTO 1 s).
TEST(TcpRecoverySim, RescueRetransmissionRepairsTheTail) {
  constexpr std::uint64_t total = 30 * std::uint64_t{seg};
  constexpr std::uint64_t mid = total - 6 * seg;
  const Scenario s = directed(7500, ProfileId::rfc, total);
  const TwoRuns r = run_twice(s, [](OffsetDropper& d) {
    d.drop = [](std::uint64_t off, std::uint32_t len, std::uint32_t copy) {
      return copy == 1 && ((off <= mid && off + len > mid) || off + len == total);
    };
  });
  const Outcome& o = r.first;
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
  EXPECT_EQ(r.second_digest, o.result.digest);
  const StackStats& st = o.stats[0];
  EXPECT_EQ(st.TcpExtTCPTimeouts, 0u);
  EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);
  EXPECT_EQ(st.TcpExtTCPSackRecovery, 1u);
  const auto last = std::prev(r.copies.end());
  const auto first = std::prev(r.copies.upper_bound(mid));
  ASSERT_LT(std::distance(first, last), 6);
  ASSERT_GE(std::distance(first, last), 4);  // three SACKed segments at least
  EXPECT_EQ(first->second, 2u);
  EXPECT_EQ(last->second, 2u);
  const auto fast = tx_at(r, first->first);
  const auto rescue = tx_at(r, last->first);
  ASSERT_EQ(fast.size(), 2u);
  ASSERT_EQ(rescue.size(), 2u);
  EXPECT_EQ(rescue[1].tx, TxKind::rexmit);
  EXPECT_EQ(rescue[1].ca, CaState::recovery);
  // After the fast retransmission's ACK: one round trip (20 ms) later.
  EXPECT_GE(rescue[1].t - fast[1].t, 20ms);
}

// D-SACK growth of RACK's reorder window (M2-DESIGN §1.6, Linux
// tcp_rack_update_reo_wnd). linux_compat, 6000 segments, three of them
// arrive late (each delay is counted from the arrival of the next segment):
// P (at 40 * 1448) right after its successor, so one SACK precedes it and it
// is not retransmitted, but reordering is seen (reord_seen 1, the degree
// stays 3); Q (at 120 * 1448) 20 ms late, so the REO timer (min_rtt / 4 =
// 5 ms, + 2 ms) resends it spuriously and the receiver D-SACKs one of the
// two copies: reo_wnd_steps 2 at the next ACK that delivers data; R (at
// 1000 * 1448, sent after Q's D-SACK came back) 10 ms late. With steps 2 the
// window is 10 ms and the REO timer 12 ms after the first SACK above R: R's
// own ACK comes first and R is not resent. Without Q (steps 1, the timer
// 7 ms after that SACK) R is resent and D-SACKed.
TEST(TcpRecoverySim, DsackWidensTheReorderWindow) {
  constexpr std::uint64_t total = 6000 * std::uint64_t{seg};
  for (const bool with_q : {true, false}) {
    SCOPED_TRACE(with_q ? "P, Q, R late" : "P, R late");
    const Scenario s = directed(7600, ProfileId::linux_compat, total);
    const TwoRuns r = run_twice(s, [with_q](OffsetDropper& d) {
      d.hold = [with_q, chosen = std::map<std::uint64_t, std::uint64_t>{}](
                   std::uint64_t off, std::uint32_t copy) mutable -> std::optional<Duration> {
        const std::pair<std::uint64_t, Duration> late[] = {
            {40 * std::uint64_t{seg}, Duration::zero()},
            {120 * std::uint64_t{seg}, Duration{20ms}},
            {1000 * std::uint64_t{seg}, Duration{10ms}}};
        for (const auto& [at, extra] : late) {
          if (!with_q && at == 120 * std::uint64_t{seg}) {
            continue;
          }
          if (copy == 1 && off >= at && !chosen.contains(at)) {
            chosen[at] = off;
            return extra;
          }
        }
        return std::nullopt;
      };
    });
    const Outcome& o = r.first;
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
    EXPECT_EQ(r.second_digest, o.result.digest);
    const StackStats& st = o.stats[0];
    const auto copies_at_or_above = [&](std::uint64_t at) {
      return r.copies.lower_bound(at)->second;
    };
    EXPECT_EQ(copies_at_or_above(40 * std::uint64_t{seg}), 1u);
    EXPECT_GE(st.TcpExtTCPSACKReorder, 1u);
    EXPECT_EQ(st.TcpExtTCPTimeouts, 0u);
    if (with_q) {
      EXPECT_EQ(copies_at_or_above(120 * std::uint64_t{seg}), 2u);
      EXPECT_EQ(st.TcpExtTCPDSACKRecv, 1u);  // Q's spurious retransmission
      EXPECT_EQ(copies_at_or_above(1000 * std::uint64_t{seg}), 1u);
    } else {
      EXPECT_EQ(st.TcpExtTCPDSACKRecv, 1u);  // R's spurious retransmission
      EXPECT_EQ(copies_at_or_above(1000 * std::uint64_t{seg}), 2u);
    }
  }
}

// A receiver reneges under RACK (RFC 2018 §8; M2-DESIGN §1.6 "RTO", Linux
// tcp_check_sack_reneging, tcp_timeout_mark_lost). The first transmissions
// of V (the segment at 100 * 1448) and of W (the one after it) are lost.
// While SEG.ACK is V's start, the ACKs node 0 receives that SACK from W's
// end are changed to SACK from W's start, as if W had arrived, been SACKed
// and been dropped again. RACK marks V lost and Recovery resends it; the ACK
// of V brings SND.UNA to W, which is marked SACKed, so the RTO is re-armed
// at max(srtt / 2, 10 ms) (the reneging timer); the RTO finds the head
// SACKed, counts the reneging, clears the SACK marks and resends W.
TEST(TcpRecoverySim, RenegingUnderRack) {
  constexpr std::uint64_t total = 200 * std::uint64_t{seg};
  constexpr std::uint64_t at = 100 * std::uint64_t{seg};
  const Scenario s = directed(7700, ProfileId::linux_compat, total);
  std::uint32_t forged = 0;
  const TwoRuns r = run_twice(
      s,
      [](OffsetDropper& d) {
        d.drop = [n = 0](std::uint64_t off, std::uint32_t, std::uint32_t copy) mutable {
          // The first two segments at or above `at`, first copies only.
          if (copy == 1 && off >= at && n < 2) {
            ++n;
            return true;
          }
          return false;
        };
      },
      [&forged](std::vector<Tap*>& taps, OffsetDropper& d) {
        forged = 0;
        taps[0]->ingress = [&d, &forged](Tap& tap, Time t, std::span<const std::byte> bytes) {
          if (d.dropped.size() < 2 || !d.isn) {
            return true;
          }
          const auto g = parse_seg(0, false, t, bytes);
          if (!g || g->opt.sack_count == 0) {
            return true;
          }
          const std::uint64_t v = *d.dropped.begin();
          const std::uint64_t w = *std::next(d.dropped.begin());
          const auto after_w = d.copies.upper_bound(w);
          if (after_w == d.copies.end()) {
            return true;
          }
          const Seq32 v_start = *d.isn + 1 + static_cast<std::uint32_t>(v);
          const Seq32 w_start = *d.isn + 1 + static_cast<std::uint32_t>(w);
          const Seq32 w_end = *d.isn + 1 + static_cast<std::uint32_t>(after_w->first);
          if (g->h.ack != v_start) {
            return true;
          }
          test::TcpSpec spec(g->src, g->dst);
          spec.seq = g->h.seq;
          spec.ack = g->h.ack;
          spec.flags = g->h.flags;
          spec.window = g->h.window;
          spec.opt = g->opt;
          bool changed = false;
          for (std::uint8_t i = 0; i < spec.opt.sack_count; ++i) {
            if (spec.opt.sack[i].first == w_end) {
              spec.opt.sack[i].first = w_start;
              changed = true;
            }
          }
          if (!changed) {
            return true;
          }
          // The checkers saw the ACK as sent; node 0's stack gets the
          // changed copy instead.
          ++forged;
          tap.inner().receive(t, test::tcp_datagram(spec));
          return false;
        };
      });
  const Outcome& o = r.first;
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
  EXPECT_EQ(r.second_digest, o.result.digest);
  EXPECT_GT(forged, 0u);
  const StackStats& st = o.stats[0];
  EXPECT_EQ(st.TcpExtTCPSACKReneging, 1u);
  EXPECT_EQ(st.TcpExtTCPTimeouts, 1u);
  EXPECT_EQ(st.TcpExtTCPSackRecovery, 1u);
  const auto v = r.copies.lower_bound(at);
  ASSERT_NE(v, r.copies.end());
  const auto w = std::next(v);
  ASSERT_NE(w, r.copies.end());
  const auto tv = tx_at(r, v->first);
  const auto tw = tx_at(r, w->first);
  ASSERT_GE(tv.size(), 2u);
  ASSERT_GE(tw.size(), 2u);
  EXPECT_EQ(tv[1].ca, CaState::recovery);  // RACK's retransmission of V
  EXPECT_EQ(tw[1].tx, TxKind::rto_rexmit);
  // The reneging timer: W goes out again well before a full RTO (rto_min
  // 200 ms) after V's retransmission.
  const auto rto = fired(o, TraceTimer::rto);
  ASSERT_EQ(rto.size(), 1u);
  EXPECT_EQ(rto[0].t, tw[1].t);
  EXPECT_LT(tw[1].t - tv[1].t, 100ms);
}

// A PMTU drop in Recovery (M2-DESIGN §4.3; DESIGN §4.13, Linux
// tcp_simple_retransmit): the first transmission of the segment at
// 100 * 1448 is lost; 1 ms after its retransmission (in Recovery) an ICMP
// frag-needed for MTU 1400 quoting that retransmission arrives. The MSS
// drops to 1348, the longer segments are marked lost and split, the state
// goes from Recovery to Loss, and they are resent as pmtu_rexmit under cwnd;
// no RTO.
TEST(TcpRecoverySim, PmtuDropDuringRecovery) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(profile_name(profile));
    constexpr std::uint64_t total = 300 * std::uint64_t{seg};
    constexpr std::uint64_t at = 100 * std::uint64_t{seg};
    const Scenario s = directed(7800 + static_cast<std::uint64_t>(profile), profile, total);
    const TwoRuns r = run_twice(
        s,
        [](OffsetDropper& d) {
          d.drop = [chosen = std::optional<std::uint64_t>{}](std::uint64_t off, std::uint32_t,
                                                             std::uint32_t copy) mutable {
            if (!chosen && off >= at) {
              chosen = off;
            }
            return off == chosen && copy == 1;
          };
        },
        [](std::vector<Tap*>& taps, OffsetDropper& d) {
          auto inner = taps[0]->egress;
          taps[0]->egress = [inner, &d, sent = false](Tap& tap, Time t,
                                                      std::span<const std::byte> bytes) mutable {
            const bool pass = inner(tap, t, bytes);
            const auto g = parse_seg(0, true, t, bytes);
            if (!sent && pass && g && g->len > 0 && d.isn && !d.dropped.empty() &&
                g->h.seq == *d.isn + 1 + static_cast<std::uint32_t>(*d.dropped.begin())) {
              sent = true;
              (void)tap.inject_at(
                  t + 1ms, test::icmp_error(LinkParams{}.router_addr, node_addr(0), 3, 4, 1400,
                                            std::vector<std::byte>(bytes.begin(), bytes.end())));
            }
            return pass;
          };
        });
    const Outcome& o = r.first;
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
    EXPECT_EQ(r.second_digest, o.result.digest);
    const StackStats& st = o.stats[0];
    EXPECT_EQ(st.TcpExtTCPTimeouts, 0u);
    EXPECT_EQ(st.TcpExtTCPSackRecovery, 1u);
    const auto v = r.copies.lower_bound(at);
    ASSERT_NE(v, r.copies.end());
    const auto tx = tx_at(r, v->first);
    ASSERT_GE(tx.size(), 2u);
    EXPECT_EQ(tx[1].ca, CaState::recovery);
    const auto pmtu = o.events(0, [](const TraceEvent& e) {
      return e.kind == TraceKind::tx && e.tx == TxKind::pmtu_rexmit;
    });
    ASSERT_FALSE(pmtu.empty());
    EXPECT_EQ(pmtu.front().t, tx[1].t + 1ms);
    EXPECT_EQ(pmtu.front().ca, CaState::loss);
    for (const TraceEvent& e : pmtu) {
      EXPECT_LE(e.len, 1348u);
      EXPECT_EQ(e.mss, 1348);
    }
  }
}

// 100 MB from node 0 to node 1 over 10 ms each way, the data direction lossy:
// 1 % Bernoulli, or 5 % in bursts (Gilbert-Elliott: p = 26316 ppm, r =
// 500000 ppm, everything lost in the bad state: p / (p + r) = 5 %, bursts of
// 2 packets on average). The model's state moves per packet, so a burst that
// catches an RTO retransmission tends to catch the next one too (each stays
// lost with probability 1 - r); the applications' idle limit is raised to
// 20 minutes so that a long backoff chain is not taken for a hang. Per
// profile, SACK on and off.
enum class LossKind : std::uint8_t { bernoulli_1pct, burst_5pct };

struct BulkCase {
  ProfileId profile;
  LossKind loss;
  bool sack;
};

std::string bulk_case_name(const BulkCase& c) {
  return profile_name(c.profile) + (c.loss == LossKind::bernoulli_1pct ? "_loss1" : "_burst5") +
         (c.sack ? "_sack" : "_nosack");
}

// The case's name in gtest output (and so in the ctest name).
void PrintTo(const BulkCase& c, std::ostream* os) { *os << bulk_case_name(c); }

class TcpRecoveryBulkSim : public ::testing::TestWithParam<BulkCase> {};

TEST_P(TcpRecoveryBulkSim, HundredMegabytesArriveIntact) {
  const auto [profile, loss, sack] = GetParam();
  constexpr std::uint64_t total = 100'000'000;
  LinkParams ab = clean_link(10ms);
  if (loss == LossKind::bernoulli_1pct) {
    ab.loss_ppm = 10'000;
  } else {
    ab.burst = GilbertElliott{26'316, 500'000, 1'000'000};
  }
  Scenario s = two_node_scenario(7300 + static_cast<std::uint64_t>(profile) * 4 +
                                     static_cast<std::uint64_t>(loss) * 2 + (sack ? 1 : 0),
                                 ab, clean_link(10ms));
  for (NodeSpec& n : s.node) {
    n.profile = profile;
    n.sack = sack;
  }
  s.app_idle_timeout = 1200s;
  s.conn.push_back(bulk(total, 0));
  RunSpec spec;
  spec.keep_trace = false;
  spec.keep_wire = false;
  const Outcome o = run_sim(s, spec);
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
  const StackStats& st = o.stats[0];
  EXPECT_GT(st.TcpRetransSegs, 0u);
  EXPECT_EQ(st.TcpExtTCPSACKDiscard, 0u);
  if (sack) {
    EXPECT_GT(st.TcpExtTCPSackRecovery, 0u);
  } else {
    EXPECT_GT(st.TcpExtTCPRenoRecovery, 0u);
    EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);  // no TLP without SACK
  }
  if (profile == ProfileId::rfc) {
    EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);
  }
  EXPECT_EQ(run_sim(s, spec).result.digest, o.result.digest);
}

std::string bulk_param_name(const ::testing::TestParamInfo<BulkCase>& p) {
  return bulk_case_name(p.param);
}

INSTANTIATE_TEST_SUITE_P(
    Profiles, TcpRecoveryBulkSim,
    ::testing::Values(BulkCase{ProfileId::linux_compat, LossKind::bernoulli_1pct, true},
                      BulkCase{ProfileId::linux_compat, LossKind::bernoulli_1pct, false},
                      BulkCase{ProfileId::linux_compat, LossKind::burst_5pct, true},
                      BulkCase{ProfileId::linux_compat, LossKind::burst_5pct, false},
                      BulkCase{ProfileId::rfc, LossKind::bernoulli_1pct, true},
                      BulkCase{ProfileId::rfc, LossKind::bernoulli_1pct, false},
                      BulkCase{ProfileId::rfc, LossKind::burst_5pct, true},
                      BulkCase{ProfileId::rfc, LossKind::burst_5pct, false}),
    bulk_param_name);

}  // namespace
}  // namespace utcp::sim
