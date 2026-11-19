// Linux v7.0 BBR over the ordinary full-duplex simulator and application.
#include "tcp_sim_util.hpp"

#include <iostream>

namespace utcp::sim {
namespace {

struct BbrFlow {
  std::vector<std::pair<BbrMode, Time>> transitions;
  std::uint64_t received = 0, offered = 0, dropped = 0, queue_samples = 0;
  std::uint32_t max_steady_queue = 0;
  std::uint64_t lt_acks = 0, recovery_acks = 0, loss_heads = 0, probe_restores = 0;
};

constexpr std::uint64_t transfer = 200'000'000;

void run_bbr(BbrFlow& result, bool lossy) {
  LinkParams forward;
  forward.delay = 10ms;
  forward.rate_bps = lossy ? 10'000'000 : 100'000'000;
  forward.queue_bytes = static_cast<std::uint32_t>(forward.rate_bps / 200);  // 2 x 20 ms BDP
  auto reverse = forward;
  if (lossy) forward.loss_ppm = 250'000;
  auto s = two_node_scenario(9406, forward, reverse);
  s.gen_version = 6;
  s.node[0].profile = ProfileId::linux_compat;
  s.node[0].cc = CcAlgo::bbr;
  s.node[0].pacing = Pacing::cc_requested;
  s.node[0].rack_tlp = true;
  s.node[0].recovery_reduction = RecoveryReduction::prr;
  s.node[0].snd_buf = s.node[1].rcv_buf = 4 * 1024 * 1024;
  s.conn.push_back(bulk(transfer, 0));

  std::optional<BbrMode> pre_rto_mode;
  World* active = nullptr;
  WorldOptions opt;
  if (!lossy) {
    opt.on_wire = [&](const WireEvent& w) {
      if (w.egress && w.node == 0 && w.t >= s.start + 1s) {
        // The callback precedes admission. Adding this datagram gives its
        // post-admission occupancy (an upper bound even if it is dropped).
        ++result.queue_samples;
        const auto size = static_cast<std::uint32_t>(w.datagram.size());
        const auto peak = active->link(0).queued_bytes(w.t) + size;
        result.max_steady_queue = std::max(result.max_steady_queue, peak);
      }
    };
  }
  opt.trace_out = [&](std::uint32_t n, const TraceEvent& e) {
    if (n != 0 || !e.bbr) return;
    if (e.kind == TraceKind::rto) pre_rto_mode = e.bbr->mode;
    if (e.tx == TxKind::rto_rexmit && e.kind == TraceKind::tx) {
      ++result.loss_heads;
      EXPECT_EQ(e.ca, CaState::loss);
      ASSERT_TRUE(pre_rto_mode.has_value());
      if (*pre_rto_mode == BbrMode::probe_rtt && e.bbr->mode == BbrMode::probe_bw) {
        // bbr_cwnd_event(TX_START) completes an expired probe after tcp_enter_loss.
        ++result.probe_restores;
        EXPECT_GE(e.cwnd, e.in_flight);
      } else {
        EXPECT_EQ(e.cwnd, e.in_flight);  // remaining flight + the head just sent
      }
      pre_rto_mode.reset();
    }
    if (e.kind != TraceKind::ack) return;
    if (e.bbr->lt_use_bw) ++result.lt_acks;
    if (e.ca == CaState::recovery) ++result.recovery_acks;
    if (result.transitions.empty() || result.transitions.back().first != e.bbr->mode) {
      result.transitions.emplace_back(e.bbr->mode, e.t);
    }
  };
  World world(s, opt);
  active = &world;
  const auto run = world.run();
  for (const auto& v : run.violations) ADD_FAILURE() << v.message;
  EXPECT_EQ(run.verdict, Verdict::ok);
  result.received = static_cast<StackNode&>(world.node(1)).counts().tcp_bytes_received;
  result.offered = run.links[0].offered;
  result.dropped = run.links[0].lost;
  std::cout << "BBR loss_ppm=" << forward.loss_ppm << " received=" << result.received
            << " offered=" << result.offered << " dropped=" << result.dropped
            << " steady_samples=" << result.queue_samples
            << " max_queue_bytes=" << result.max_steady_queue << " lt_acks=" << result.lt_acks
            << " recovery_acks=" << result.recovery_acks << " rto_heads=" << result.loss_heads
            << " probe_restores=" << result.probe_restores << " queue_drops=" << run.links[0].queue_drops
            << " transitions=" << result.transitions.size();
  for (std::size_t i = 0; i < std::min<std::size_t>(result.transitions.size(), 12); ++i) {
    const auto& [mode, time] = result.transitions[i];
    std::cout << " " << to_string(mode) << "@" << (time - s.start).count() / 1'000'000 << "ms";
  }
  std::cout << "\n";
  EXPECT_EQ(result.received, transfer);
}

TEST(TcpBbrSim, CleanBulkChecksModelAndBottleneckQueue) {
  BbrFlow flow;
  run_bbr(flow, false);
  ASSERT_GE(flow.transitions.size(), 5u);
  EXPECT_EQ(flow.transitions[0].first, BbrMode::startup);
  EXPECT_EQ(flow.transitions[1].first, BbrMode::drain);
  EXPECT_EQ(flow.transitions[2].first, BbrMode::probe_bw);
  EXPECT_EQ(flow.transitions[3].first, BbrMode::probe_rtt);
  EXPECT_EQ(flow.transitions[4].first, BbrMode::probe_bw);
  EXPECT_GE(flow.transitions[3].second - flow.transitions[0].second, 9s);
  EXPECT_LE(flow.transitions[3].second - flow.transitions[0].second, 12s);
  EXPECT_GE(flow.transitions[4].second - flow.transitions[3].second, 200ms);
  EXPECT_GT(flow.queue_samples, 1000u);
  EXPECT_LT(flow.max_steady_queue, 250'000u);
  EXPECT_EQ(flow.dropped, 0u);
}

TEST(TcpBbrSim, IdleProbeBandwidthRestartPacesFirstPayloadAtUnityGain) {
  LinkParams link;
  link.delay = 10ms;
  link.rate_bps = 100'000'000;
  link.queue_bytes = 500'000;
  auto s = two_node_scenario(9406, link, link);
  TrickleClient client;
  client.chunk = 2 * 1024 * 1024;
  client.total = 12 * client.chunk;
  client.start = s.start + 1ms;
  client.gap = 700ms;
  client.opts.cc = CcAlgo::bbr;  // request pacing on this socket of a NewReno stack
  s.conn.push_back(bulk(client.total, 0));
  RunSpec spec;
  spec.keep_wire = false;
  spec.make = [&](const Scenario& scenario, std::uint32_t n) -> std::unique_ptr<Node> {
    if (n != 0) return nullptr;
    auto sender = std::make_unique<AppNode>(scenario, n, [](StackConfig& cfg) {
      cfg.tcp.pacing = Pacing::cc_requested;
      cfg.tcp.snd_buf_init = cfg.tcp.snd_buf_max = 2 * 1024 * 1024;
    });
    sender->script = [&](AppNode& app, Time now) { client.step(app, now); };
    return sender;
  };
  const auto r = run_sim(s, spec);
  ASSERT_TRUE(r.ok()) << r.violations();
  ASSERT_EQ(r.counts[1].tcp_bytes_received, client.total);
  const TraceEvent* drained = nullptr;
  const TraceEvent* opening = nullptr;
  std::uint64_t opening_bytes = 0;
  unsigned changed = 0, charged = 0;
  for (const auto& [n, e] : r.trace) {
    if (n != 0 || !e.bbr) continue;
    if (e.kind == TraceKind::ack) drained = e.in_flight == 0 ? &e : nullptr;
    if (e.kind != TraceKind::tx || !e.len) continue;
    if (opening) {
      if (e.burst_start) {
        // A long idle interval credits half the opening burst. Data is
        // queued and cwnd available: the next burst departs at that EDT.
        const auto cost = opening_bytes * 1'000'000'000 / opening->gate_rate;
        EXPECT_EQ(e.t - opening->t, Duration(static_cast<std::int64_t>(cost - cost / 2)));
        ++charged;
        opening = nullptr;
      } else {
        opening_bytes += e.len;
      }
    }
    if (drained && e.t - drained->t > 50ms && e.bbr->mode == BbrMode::probe_bw) {
      const auto unity = std::uint64_t{e.bbr->bandwidth_q24} * e.mss * 990'000 / (1u << 24);
      EXPECT_EQ(e.pacing_rate, unity);
      EXPECT_EQ(e.gate_rate, unity);
      EXPECT_TRUE(e.burst_start);
      if (drained->pacing_rate != unity) {
        ++changed;
        opening = &e;
        opening_bytes = e.len;
      }
    }
    drained = nullptr;
  }
  EXPECT_EQ(charged, changed);
  EXPECT_GT(changed, 0u);  // ensure the old cached rate would disagree
}

// Only the observer changes in the negative cases. Real packets and socket
// selection follow the normal World path; optional BBR diagnostics are
// missing in both controls and faults.
TEST(TcpBbrSim, CheckerUsesSocketSelectionWhenModelDiagnosticsAreMissing) {
  struct Observer final : TraceSink {
    AppNode* app = nullptr;
    bool corrupt = false, paced = false;
    unsigned payloads = 0;
    void on_event(const TraceEvent& original) override {
      auto e = original;
      e.bbr.reset();
      if (e.kind == TraceKind::tx && e.tx == TxKind::data) {
        ++payloads;
        if (corrupt) {
          e.gate_rate = paced ? 0 : e.pacing_rate;
          e.burst_start = !paced;
        }
      }
      app->on_event(e);
    }
  };
  for (const auto& [node_cc, socket_cc] : {
         std::pair{CcAlgo::bbr, std::optional<CcAlgo>{}},
         std::pair{CcAlgo::newreno, std::optional{CcAlgo::bbr}},
         std::pair{CcAlgo::bbr, std::optional{CcAlgo::newreno}}}) {
    for (bool corrupt : {false, true}) {
      SCOPED_TRACE(to_string(node_cc));
      SCOPED_TRACE(to_string(socket_cc.value_or(node_cc)));
      SCOPED_TRACE(corrupt);
      auto s = two_node_scenario(9406, clean_link(10ms), clean_link(10ms));
      TrickleClient client;
      client.chunk = 32 * 1024;
      client.total = client.chunk;
      client.start = s.start + 1ms;
      client.opts.cc = socket_cc;
      s.conn.push_back(bulk(client.total, 0));
      Observer observer;
      observer.corrupt = corrupt;
      observer.paced = socket_cc.value_or(node_cc) == CcAlgo::bbr;
      RunSpec spec;
      spec.keep_trace = spec.keep_wire = false;
      spec.make = [&](const Scenario& sc, std::uint32_t n) -> std::unique_ptr<Node> {
        if (n != 0) return nullptr;
        auto sender = std::make_unique<AppNode>(sc, n, [&](StackConfig& cfg) {
          cfg.tcp.cc = node_cc;
          cfg.tcp.pacing = Pacing::cc_requested;
        });
        observer.app = sender.get();
        sender->script = [&](AppNode& app, Time now) {
          app.stack().set_trace_sink(&observer);
          client.step(app, now);
        };
        return sender;
      };
      const auto r = run_sim(s, spec);
      if (corrupt) {
        EXPECT_EQ(r.result.verdict, Verdict::pacing) << r.violations();
        const char* cause = observer.paced ? "ordinary paced payload missing gate rate"
                                          : "gate rate disagrees with sender pacing rate";
        EXPECT_NE(r.violations().find(cause), std::string::npos);
      } else {
        EXPECT_TRUE(r.ok()) << r.violations();
        EXPECT_EQ(r.counts[1].tcp_bytes_received, client.total);
        EXPECT_GT(observer.payloads, 10u);
      }
    }
  }
}

TEST(TcpBbrSim, LossyBulkActivatesLongTermBandwidthSampling) {
  BbrFlow flow;
  run_bbr(flow, true);
  EXPECT_GT(flow.dropped, 0u);
  EXPECT_GT(flow.lt_acks, 0u);
  EXPECT_GT(flow.recovery_acks, 0u);
  EXPECT_GT(flow.loss_heads, flow.probe_restores);
  EXPECT_GT(flow.probe_restores, 0u);
}

}  // namespace
}  // namespace utcp::sim
