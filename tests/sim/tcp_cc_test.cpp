#include <gtest/gtest.h>

#include <cmath>
#include <iostream>

#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

struct CcTransfer {
  std::vector<TraceEvent> acks;
  unsigned drops = 0;
  Time dropped{};
};

void run_bulk(CcTransfer& trace, ProfileId profile, std::uint64_t bytes) {
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
  auto sender = std::make_unique<AppNode>(s, 0, [](StackConfig& c) {
    c.tcp.cc = CcAlgo::cubic;
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
  EXPECT_EQ(client.sent, bytes);
  EXPECT_EQ(peer->counts().tcp_bytes_received, bytes);
  for (const auto& segment : result.links) {
    EXPECT_EQ(segment.queue_drops, 0u);
    EXPECT_EQ(segment.lost, 0u);
    EXPECT_EQ(segment.mtu_drops, 0u);
  }
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
