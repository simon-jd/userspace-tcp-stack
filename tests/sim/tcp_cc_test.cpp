#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <functional>
#include <iterator>
#include <iostream>

#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

struct CcTransfer {
  std::vector<TraceEvent> acks;
  StackStats stats;
  unsigned drops = 0;
  Time dropped{};
};

void run_bulk(CcTransfer& trace, ProfileId profile, std::uint64_t bytes,
              const std::function<void(TcpConfig&)>& configure = {}) {
  LinkParams link;
  link.delay = 10ms;
  link.rate_bps = 100'000'000;
  // The receiver bounds outstanding payload to at most 4 MiB; even a
  // full window of 1500-byte packets fits the 8 MiB bottleneck queue.
  link.queue_bytes = 8 * 1024 * 1024;
  auto s = two_node_scenario(9406, link, link);
  s.node[0].profile = profile;
  s.node[1].rcv_buf = 4 * 1024 * 1024;
  s.conn.push_back(bulk(bytes, 0));
  BulkClient client;
  client.total = bytes;
  client.start = s.start + 1ms;
  auto sender = std::make_unique<AppNode>(s, 0, [&](StackConfig& c) {
    c.tcp.cc = CcAlgo::cubic;
    if (configure) configure(c.tcp);
    c.tcp.snd_buf_init = c.tcp.snd_buf_max = 4 * 1024 * 1024;
  });
  auto* stack = &sender->stack();
  sender->script = [&](AppNode& n, Time now) { client.step(n, now); };
  auto tap = std::make_unique<Tap>(std::move(sender), stack);
  if (profile == ProfileId::linux_compat) {
    tap->egress = [&](Tap&, Time now, std::span<const std::byte> d) {
      if (trace.drops == 0 && now >= s.start + 5s) {
        const auto p = parse_tcp_packet(d);
        if (p && !p->tcp.payload.empty()) {
          trace.dropped = now;
          ++trace.drops;
          return false;
        }
      }
      return true;
    };
  }
  auto receiver = std::make_unique<StackNode>(s, 1);
  auto* peer = receiver.get();
  std::vector<std::unique_ptr<Node>> nodes;
  nodes.push_back(std::move(tap));
  nodes.push_back(std::move(receiver));
  WorldOptions opt;
  opt.trace_out = [&](std::uint32_t n, const TraceEvent& e) {
    if (n == 0 && e.kind == TraceKind::ack) trace.acks.push_back(e);
  };
  World world(s, std::move(nodes), opt);
  const auto result = world.run();
  for (const auto& v : result.violations) ADD_FAILURE() << v.message;
  EXPECT_EQ(result.verdict, Verdict::ok);
  EXPECT_EQ(stack->stats().TcpRetransSegs, trace.drops);
  trace.stats = stack->stats();
  EXPECT_EQ(client.sent, bytes);
  EXPECT_EQ(peer->counts().tcp_bytes_received, bytes);
  for (const auto& segment : result.links) {
    EXPECT_EQ(segment.queue_drops, 0u);
    EXPECT_EQ(segment.lost, 0u);
    EXPECT_EQ(segment.mtu_drops, 0u);
  }
}

TEST(TcpCcSim, RfcCubicResumesFromTheRestartWindow) {
  LinkParams link;
  link.delay = 5ms;
  link.rate_bps = 100'000'000;
  link.queue_bytes = 8 * 1024 * 1024;
  auto s = two_node_scenario(9406, link, link);
  s.node[0].profile = ProfileId::rfc;
  TrickleClient client;
  client.chunk = 512 * 1024;
  client.total = 2 * client.chunk;
  client.start = s.start + 1ms;
  client.gap = 4s;
  s.conn.push_back(bulk(client.total, 0));
  RunSpec spec;
  spec.keep_wire = false;
  spec.make = [&](const Scenario& scenario, std::uint32_t node) -> std::unique_ptr<Node> {
    if (node != 0) return nullptr;
    auto sender = std::make_unique<AppNode>(scenario, node, [](StackConfig& cfg) {
      cfg.tcp.cc = CcAlgo::cubic;
      cfg.tcp.initial_cwnd = cfg.tcp.initial_ssthresh = 10;
      cfg.tcp.snd_buf_init = cfg.tcp.snd_buf_max = 2 * 1024 * 1024;
    });
    sender->script = [&](AppNode& app, Time now) { client.step(app, now); };
    return sender;
  };
  const auto result = run_sim(s, spec);
  ASSERT_TRUE(result.ok()) << result.violations();
  ASSERT_EQ(result.counts[1].tcp_bytes_received, client.total);
  ASSERT_EQ(result.stats[0].TcpRetransSegs, 0u);
  const auto events = result.events(0, [](const auto& e) {
    return e.kind == TraceKind::ack || (e.kind == TraceKind::tx && e.tx == TxKind::data);
  });
  const auto last = events.end();
  const auto restart = std::find_if(events.begin(), last, [&](const auto& e) {
    return e.t >= client.start + client.gap && e.kind == TraceKind::tx;
  });
  ASSERT_NE(restart, events.begin());
  ASSERT_NE(restart, last);
  const auto& drained = *std::prev(restart);
  ASSERT_EQ(drained.in_flight, 0u);
  ASSERT_GT(drained.cwnd, 11u);
  ASSERT_GT((restart->t - drained.t).count(), drained.rto_ns);
  EXPECT_EQ(restart->cwnd, 10u);
  const auto is_ack = [](const auto& e) { return e.kind == TraceKind::ack; };
  const auto first_ack = std::find_if(restart, last, is_ack);
  ASSERT_NE(first_ack, last);
  EXPECT_LE(first_ack->cwnd, restart->cwnd + 1);
  const auto next_ack = std::find_if(std::next(first_ack), last, is_ack);
  ASSERT_NE(next_ack, last);
  ASSERT_NE(std::next(first_ack), next_ack);
  const auto burst = std::max_element(std::next(first_ack), next_ack,
      [](const auto& a, const auto& b) { return a.in_flight < b.in_flight; });
  EXPECT_LE(burst->in_flight, restart->cwnd + 1);
  RecordProperty("pre_idle_cwnd", drained.cwnd);
  RecordProperty("restart_cwnd", restart->cwnd);
  RecordProperty("first_ack_cwnd", first_ack->cwnd);
  RecordProperty("next_burst_in_flight", burst->in_flight);
}

TEST(TcpCcSim, ClassicOverridePublishesTrainAndDelayExitCounters) {
  for (bool train : {true, false}) {
    SCOPED_TRACE(train);
    CcTransfer trace;
    run_bulk(trace, ProfileId::rfc, 8'000'000, [train](TcpConfig& cfg) {
      cfg.hystart = Hystart::hystart_classic;
      if (!train) cfg.hystart_ack_delta = 0us;
    });
    const auto exit = std::find_if(trace.acks.begin(), trace.acks.end(),
        [](const auto& e) { return e.ssthresh < cwnd_infinite; });
    ASSERT_NE(exit, trace.acks.end());
    ASSERT_GT(trace.acks.end() - exit, 100);
    RecordProperty(train ? "train_exit_cwnd" : "delay_exit_cwnd", exit->ssthresh);
    EXPECT_EQ(trace.stats.TcpExtTCPHystartTrainDetect, train ? 1u : 0u);
    EXPECT_EQ(trace.stats.TcpExtTCPHystartTrainCwnd, train ? exit->ssthresh : 0u);
    EXPECT_EQ(trace.stats.TcpExtTCPHystartDelayDetect, train ? 0u : 1u);
    EXPECT_EQ(trace.stats.TcpExtTCPHystartDelayCwnd, train ? 0u : exit->ssthresh);
  }
}

TEST(TcpCcSim, ClassicHonorsConfiguredLowWindow) {
  CcTransfer control;
  run_bulk(control, ProfileId::rfc, 1'000'000, [](TcpConfig& cfg) {
    cfg.hystart = Hystart::hystart_classic;
  });
  ASSERT_EQ(control.stats.TcpExtTCPHystartTrainDetect, 1u);
  CcTransfer trace;
  run_bulk(trace, ProfileId::rfc, 1'000'000, [](TcpConfig& cfg) {
    cfg.hystart = Hystart::hystart_classic;
    cfg.hystart_low_window = 1024;
  });
  const auto peak = std::max_element(trace.acks.begin(), trace.acks.end(),
      [](const auto& a, const auto& b) { return a.cwnd < b.cwnd; });
  ASSERT_NE(peak, trace.acks.end());
  EXPECT_GT(peak->cwnd, control.stats.TcpExtTCPHystartTrainCwnd);
  RecordProperty("raised_low_window_peak", peak->cwnd);
  EXPECT_LT(peak->cwnd, 1024u);
  EXPECT_EQ(peak->ssthresh, cwnd_infinite);
  EXPECT_EQ(trace.stats.TcpExtTCPHystartTrainDetect, 0u);
  EXPECT_EQ(trace.stats.TcpExtTCPHystartDelayDetect, 0u);
}

TEST(TcpCcSim, LinuxSingleDropAndReturnToPreviousMaximum) {
  CcTransfer trace;
  run_bulk(trace, ProfileId::linux_compat, 200'000'000);
  ASSERT_EQ(trace.drops, 1u);
  const auto first = trace.acks.begin(), last = trace.acks.end();
  const auto loss = std::find_if(first, last, [&](const auto& e) {
    return e.t >= trace.dropped && e.ca == CaState::recovery;
  });
  ASSERT_NE(loss, first);
  ASSERT_NE(loss, last);
  const auto previous = std::prev(loss)->cwnd;
  EXPECT_EQ(loss->ssthresh, std::uint64_t{previous} * 717 / 1024);
  const auto epoch = std::find_if(loss, last, [](const auto& e) { return e.ca == CaState::open; });
  ASSERT_NE(epoch, last);
  ASSERT_LT(epoch->cwnd, previous);
  EXPECT_EQ(epoch->cwnd, loss->ssthresh);
  const auto regained = std::find_if(epoch, last, [&](const auto& e) { return e.cwnd >= previous; });
  std::cout << "drop_time=" << trace.dropped.ns << " last_max=" << previous
            << " epoch_time=" << epoch->t.ns << " epoch_cwnd=" << epoch->cwnd
            << " ssthresh=" << loss->ssthresh << '\n';
  auto next = epoch->t;
  for (auto i = epoch; i != last; ++i) {
    if (i->t >= next) {
      std::cout << "curve " << i->t.ns << ' ' << i->cwnd << ' ' << i->in_flight << ' ' << i->snd_wnd << '\n';
      next += 1s;
    }
  }
  ASSERT_NE(regained, last);
  const double k = std::cbrt((previous - epoch->cwnd) / (410.0 / 1024));
  const double seconds = std::chrono::duration<double>(regained->t - epoch->t).count();
  std::cout << "linux previous=" << previous << " epoch=" << epoch->cwnd << " K=" << k
            << " first_return_seconds=" << seconds << '\n';
  EXPECT_NEAR(seconds, k, k * 0.1);
}

TEST(TcpCcSim, RfcConservativeGrowthForFiveRoundsWithoutLoss) {
  CcTransfer trace;
  run_bulk(trace, ProfileId::rfc, 8'000'000);
  ASSERT_EQ(trace.drops, 0u);
  ASSERT_GT(trace.acks.size(), 2u);
  std::uint64_t end = 0, credit = 0;
  unsigned css_rounds = 0, css_acks = 0;
  bool css = false, exited = false;
  for (std::size_t i = 1; i < trace.acks.size(); ++i) {
    const auto& prev = trace.acks[i-1];
    const auto& e = trace.acks[i];
    EXPECT_NE(e.ca, CaState::loss);
    EXPECT_NE(e.ca, CaState::recovery);
    if (exited) continue;
    if (end == 0) end = prev.snd_nxt_off;
    if (e.snd_una_off >= end && e.snd_nxt_off > end) {
      end = e.snd_nxt_off;
      if (css) ++css_rounds;
    }
    if (e.ssthresh < cwnd_infinite) {
      EXPECT_TRUE(css);
      EXPECT_EQ(css_rounds, 5u);
      EXPECT_EQ(e.ssthresh, prev.cwnd);
      std::cout << "rfc CSS ACKs=" << css_acks << " rounds=" << css_rounds
                << " exit_cwnd=" << e.ssthresh << '\n';
      exited = true;
      continue;
    }
    const auto n = std::min<std::uint64_t>(8, e.delivered - prev.delivered);
    if (!n) continue;
    // While the sender is backlogged each ACK grows by N in initial slow
    // start. The first smaller increment marks the first CSS-priced ACK.
    if (!css && e.cwnd - prev.cwnd < n) css = true;
    if (css) {
      credit += n;
      EXPECT_EQ(e.cwnd - prev.cwnd, credit / 4) << i;
      credit %= 4;
      ++css_acks;
    }
  }
  EXPECT_TRUE(exited);
  EXPECT_GT(css_acks, 8u);
}
}  // namespace
}  // namespace utcp::sim
