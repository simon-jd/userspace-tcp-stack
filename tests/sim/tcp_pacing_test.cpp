// m2b-rate-pacing acceptance test 3 (M2-DESIGN §2.5, §4.4): paced bulk
// transfers over a 100 Mbit/s, 20 ms simulated path. Every paced burst is
// checked against a replay of the earliest-departure-time recurrence (Linux
// tcp_update_skb_after_send) computed from the trace alone, and a fixed
// pacing rate gives its payload rate.
#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

__extension__ using U128 = unsigned __int128;

// 100 Mbit/s, 10 ms one way, a drop-tail queue of 2 x BDP (BDP = 12.5 MB/s x
// 20 ms = 250 000 bytes): no loss at the rates below.
LinkParams bottleneck() {
  LinkParams p;
  p.delay = 10ms;
  p.rate_bps = 100'000'000;
  p.queue_bytes = 500'000;
  return p;
}

// A BulkClient on node 0 (StackConfig changed by `tweak`) sends `total`
// bytes to a StackNode on node 1 over bottleneck() in both directions.
Outcome paced_bulk(std::uint64_t seed, std::uint64_t total,
                   const std::function<void(StackConfig&)>& tweak, bool keep_trace,
                   bool keep_wire) {
  Scenario s = two_node_scenario(seed, bottleneck(), bottleneck());
  s.conn.push_back(bulk(total, 0));
  BulkClient cl;
  cl.total = total;
  cl.start = s.start + 1ms;
  RunSpec spec;
  spec.keep_trace = keep_trace;
  spec.keep_wire = keep_wire;
  spec.make = [&](const Scenario& sc, std::uint32_t i) -> std::unique_ptr<Node> {
    if (i != 0) {
      return nullptr;
    }
    auto n = std::make_unique<AppNode>(sc, i, tweak);
    n->script = [&](AppNode& node, Time now) { cl.step(node, now); };
    return n;
  };
  Outcome o = run_sim(s, spec);
  EXPECT_EQ(cl.sent, total);
  return o;
}

// One paced burst as the trace shows it: the tx events with gate_rate != 0
// from a burst_start up to the next one, all at one instant and one rate.
struct Burst {
  Time t;
  std::uint64_t rate = 0;   // bytes/s, the gate's
  std::uint64_t bytes = 0;  // payload
  std::uint32_t cwnd = 0, ssthresh = 0;
  std::uint32_t segments = 1;
};

std::vector<Burst> bursts(const Outcome& o, std::uint32_t node) {
  std::vector<Burst> v;
  for (const Rec& r : o.trace) {
    const TraceEvent& e = r.e;
    if (r.node != node || e.kind != TraceKind::tx || e.len == 0) {
      continue;
    }
    if (e.gate_rate == 0) {
      ADD_FAILURE() << "missing pacing rate on sender payload";
      continue;
    }
    if (e.burst_start || v.empty()) {
      EXPECT_TRUE(e.burst_start) << "a paced send before any burst start";
      v.push_back(Burst{e.t, e.gate_rate, e.len, e.cwnd, e.ssthresh});
      continue;
    }
    EXPECT_EQ(e.t, v.back().t) << "a burst spread over time";
    EXPECT_EQ(e.gate_rate, v.back().rate);
    v.back().bytes += e.len;
    ++v.back().segments;
  }
  return v;
}

TEST(TcpPacingSim, ReplayRejectsUntaggedEligiblePayload) {
  Outcome o;
  TraceEvent e;
  e.kind = TraceKind::tx;
  e.tx = TxKind::data;
  e.len = 1000;
  e.gate_rate = 1'000'000;
  e.burst_start = true;
  for (int i = 0; i < 10; ++i) {
    o.trace.push_back({0, e});
  }
  e.t = Time{5'000'000};
  o.trace.push_back({0, e});
  e.t += 1ns;
  e.gate_rate = 0;
  o.trace.push_back({0, e});
  EXPECT_NONFATAL_FAILURE((void)bursts(o, 0), "missing pacing rate");
}

// The EDT replay of M2-DESIGN §4.4, independent of the engine's code: with
// `next` the modelled earliest departure after the previous burst, a burst
// sent at t must have t >= next (1 us of rounding slack); then
// next = max(next, t) + len_ns - min(len_ns / 2, max(0, t - next)), len_ns =
// bytes * 10^9 / rate. Before the first paced burst there is no bound, and
// its lateness is taken as unbounded (pacing_next starts at 0).
struct Replay {
  std::size_t checked = 0;
  std::size_t early = 0;  // sent before the modelled departure: violations
  // Per burst: sent within 1 us of the modelled departure, i.e. held by the
  // gate until then.
  std::vector<bool> on_time;
  std::string first_early;
};

Replay replay(const std::vector<Burst>& bs) {
  constexpr std::int64_t slack_ns = 1000;
  Replay r;
  std::optional<std::int64_t> next;
  std::uint64_t segments = 0;
  for (const Burst& b : bs) {
    segments += b.segments;
    const std::int64_t t = b.t.ns;
    std::uint64_t late = std::numeric_limits<std::uint64_t>::max();
    bool held = false;
    if (next) {
      ++r.checked;
      if (t + slack_ns < *next) {
        if (r.early++ == 0) {
          r.first_early = "burst at " + std::to_string(t) + " ns, modelled departure " +
                          std::to_string(*next) + " ns";
        }
      } else {
        held = t <= *next + slack_ns;
      }
      late = t > *next ? static_cast<std::uint64_t>(t - *next) : 0;
    }
    r.on_time.push_back(held);
    const std::int64_t base = next ? std::max(*next, t) : t;
    if (segments < 10) {
      next = base;
      continue;
    }
    auto len_ns = static_cast<std::uint64_t>(U128{b.bytes} * 1'000'000'000 / b.rate);
    len_ns -= std::min(len_ns / 2, late);
    next = base + static_cast<std::int64_t>(len_ns);
  }
  return r;
}

// Pacing::always with NewReno (CUBIC is m2b-cc's; m2-integrate adds it to
// this test once it is merged), initial ssthresh 100: the gate rate is
// 200 % of mss * cwnd / srtt while cwnd < 50 = ssthresh / 2 and 120 % from
// there on (tcp_update_pacing_rate), so the transfer crosses the ratio
// change in slow start. Every paced burst satisfies the replay, many were
// held by the gate until exactly the modelled departure in both regimes, and
// the gate rate falls where cwnd reaches ssthresh / 2.
TEST(TcpPacingSim, PacedBurstsFollowTheEdtReplay) {
  const auto tweak = [](StackConfig& c) {
    c.tcp.cc = CcAlgo::newreno;
    c.tcp.pacing = Pacing::always;
    c.tcp.initial_ssthresh = 100;
  };
  const Outcome o = paced_bulk(9100, 8'000'000, tweak, true, false);
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.stats[0].TcpRetransSegs, 0u);
  const std::vector<Burst> bs = bursts(o, 0);
  ASSERT_GT(bs.size(), 500u);
  const Replay r = replay(bs);
  EXPECT_EQ(r.early, 0u) << r.first_early;
  EXPECT_EQ(r.checked, bs.size() - 1);
  std::size_t held_ss = 0, held_ca = 0;
  std::optional<std::size_t> cross;
  for (std::size_t i = 0; i < bs.size(); ++i) {
    const bool ss = bs[i].cwnd < bs[i].ssthresh / 2;
    if (i > 0 && !cross && !ss && bs[i - 1].cwnd < bs[i - 1].ssthresh / 2) {
      cross = i;
    }
    if (r.on_time[i]) {
      ++(ss ? held_ss : held_ca);
    }
  }
  EXPECT_GT(held_ss, 20u);
  EXPECT_GT(held_ca, 100u);
  ASSERT_TRUE(cross.has_value());
  // 200 % -> 120 % at about the same cwnd and srtt: the rate drops by about
  // 40 %.
  const Burst& before = bs[*cross - 1];
  const Burst& after = bs[*cross];
  EXPECT_EQ(before.ssthresh, 100u);
  EXPECT_LT(after.rate * 10, before.rate * 7) << before.rate << " -> " << after.rate;
}

// The replay is not vacuous: with TestFault::ignore_pacing_gate (the gate
// always open, pacing_next still advanced) bursts leave before the modelled
// departure.
TEST(TcpPacingSim, ReplayCatchesAnIgnoredGate) {
  const auto tweak = [](StackConfig& c) {
    c.tcp.cc = CcAlgo::newreno;
    c.tcp.pacing = Pacing::always;
    c.tcp.initial_ssthresh = 100;
    c.tcp.test_fault = TestFault::ignore_pacing_gate;
  };
  const Outcome o = paced_bulk(9101, 2'000'000, tweak, true, false);
  ASSERT_TRUE(o.ok()) << o.violations();
  const Replay r = replay(bursts(o, 0));
  EXPECT_GT(r.early, 10u);
}

bool covers_window(Time end, Time first) {
  return end >= first + 11s;
}

TEST(TcpPacingSim, FixedRateWindowRequiresElevenSecondsAfterFirstArrival) {
  const Time first{42};
  EXPECT_FALSE(covers_window(first + 11s - 1ns, first));
  EXPECT_TRUE(covers_window(first + 11s, first));
}

// test_fixed_pacing_rate is payload bytes per second (M2-DESIGN §2.5; the
// `--set test_fixed_pacing_rate=50Mbit` text gives 6 250 000). Over 10 s,
// from 1 s after the first data segment reaches the receiver, the payload
// that arrives is within 1 % of 62.5 MB; every paced burst uses the fixed
// rate and follows the replay.
TEST(TcpPacingSim, FixedRateGivesItsPayloadRate) {
  static constexpr std::uint64_t rate = 6'250'000;
  const auto tweak = [](StackConfig& c) { c.tcp.test_fixed_pacing_rate = rate; };
  const Outcome o = paced_bulk(9102, 12 * rate, tweak, true, true);
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.stats[0].TcpRetransSegs, 0u);
  const std::vector<Seg> in = o.segs(1, false);
  std::optional<Time> first;
  for (const Seg& g : in) {
    if (g.len > 0) {
      first = g.t;
      break;
    }
  }
  ASSERT_TRUE(first.has_value());
  const Time from = *first + 1s, to = from + 10s;
  ASSERT_TRUE(covers_window(o.result.end, *first));
  std::uint64_t bytes = 0;
  for (const Seg& g : in) {
    if (g.t >= from && g.t < to) {
      bytes += g.len;
    }
  }
  const std::uint64_t want = rate * 10;
  EXPECT_GE(bytes * 100, want * 99) << bytes;
  EXPECT_LE(bytes * 100, want * 101) << bytes;
  const std::vector<Burst> bs = bursts(o, 0);
  ASSERT_GT(bs.size(), 1000u);
  for (const Burst& b : bs) {
    ASSERT_EQ(b.rate, rate);
  }
  const Replay r = replay(bs);
  EXPECT_EQ(r.early, 0u) << r.first_early;
  RecordProperty("payload_bytes_10s", std::to_string(bytes));
}

}  // namespace
}  // namespace utcp::sim
