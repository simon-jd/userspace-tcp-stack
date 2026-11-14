// Directed simulator scenarios for zero windows (m1-tcp-robust acceptance
// tests 3 and 6) over links with loss and reordering: a receiver that
// stops reading for 40 s, so the sender probes a zero window, and a
// receiver whose packets stop arriving while its window is zero, so the
// probes go unanswered and the sender gives up.
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

// §4.9, P5: zero-length probes <SEQ = SND.UNA - 1> at RTO-based intervals
// that double up to rto_max; an answered probe never aborts the
// connection, leaves cwnd and ssthresh alone and is not an rto_rexmit; the
// transfer completes once the reader resumes.
TEST(TcpZeroWindowSim, PausedReaderIsProbed) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(static_cast<int>(profile));
    Scenario s = two_node_scenario(9200 + static_cast<std::uint64_t>(profile),
                                   impaired(5ms, 20'000), impaired(5ms, 20'000));
    for (NodeSpec& n : s.node) {
      n.profile = profile;
    }
    s.node[1].rcv_buf = 64 * 1024;
    ConnSpec c = bulk(1'000'000, 0);
    c.pause_every_s = 300'000;
    c.pause_s = 40s;
    s.conn.push_back(c);
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, 1'000'000u);
    EXPECT_GT(o.stats[0].TcpExtTCPWinProbe, 3u);
    EXPECT_GT(o.stats[1].TcpExtTCPToZeroWindowAdv, 0u);
    // Probes on the wire: zero-length, one below the highest ACK a has seen.
    std::optional<Seq32> high_ack;
    int probes = 0;
    for (const Seg& g : o.wire) {
      if (g.node != 0) {
        continue;
      }
      if (!g.egress && g.has(wire::tcp_ack) && !g.has(wire::tcp_syn) &&
          (!high_ack || after(g.h.ack, *high_ack))) {
        high_ack = g.h.ack;
      }
      if (g.egress && high_ack && g.len == 0 && !g.has(wire::tcp_fin) &&
          !g.has(wire::tcp_syn) && g.h.seq == *high_ack - 1) {
        ++probes;
      }
    }
    EXPECT_GE(probes, static_cast<int>(o.stats[0].TcpExtTCPWinProbe) - 2);
    // The trace: zwp intervals within one zero-window period double up to
    // rto_max; cwnd and ssthresh do not change between probes. The timer is
    // re-armed when the window-0 answer arrives (Linux tcp_ack_probe), so a
    // gap is the doubled interval plus a round trip (at most 30 ms here).
    const Duration rto_max = tcp_config(profile).rto_max;
    std::optional<TraceEvent> prev;
    Duration prev_gap{};
    int doubled = 0;
    for (const Rec& r : o.trace) {
      if (r.node != 0 || r.e.tuple.remote.port != 5000) {
        continue;
      }
      if (r.e.kind == TraceKind::tx && r.e.tx != TxKind::zwp && r.e.tx != TxKind::ack) {
        prev.reset();  // data moved: a new period
        prev_gap = Duration{};
        continue;
      }
      if (r.e.kind != TraceKind::tx || r.e.tx != TxKind::zwp) {
        continue;
      }
      if (prev) {
        const Duration gap = r.e.t - prev->t;
        EXPECT_LE(gap, rto_max + 30ms);
        if (prev_gap > Duration{}) {
          EXPECT_GE(gap, std::min(prev_gap * 2, rto_max) - 60ms);
          doubled += gap >= prev_gap * 2 - 60ms ? 1 : 0;
        }
        EXPECT_EQ(r.e.cwnd, prev->cwnd);
        EXPECT_EQ(r.e.ssthresh, prev->ssthresh);
        prev_gap = gap;
      }
      prev = r.e;
    }
    EXPECT_GT(doubled, 0);
  }
}

// §4.8, P5: once b has advertised a zero window, nothing b sends arrives.
// a's probes go unanswered; after data_retries of them (Linux
// tcp_probe_timer, tcp_retries2) a sends RST and ends with timed_out.
TEST(TcpZeroWindowSim, UnansweredProbesAbort) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(static_cast<int>(profile));
    Scenario s = two_node_scenario(9300 + static_cast<std::uint64_t>(profile),
                                   impaired(5ms, 20'000), impaired(5ms, 20'000));
    for (NodeSpec& n : s.node) {
      n.profile = profile;
    }
    s.app_idle_timeout = 3000s;
    s.node[1].rcv_buf = 64 * 1024;
    ConnSpec c = bulk(1'000'000, 0);
    c.pause_every_s = 200'000;
    c.pause_s = 2500s;
    s.conn.push_back(c);
    bool zero = false;
    RunSpec spec;
    spec.setup = [&](std::vector<Tap*>& taps) {
      taps[1]->egress = [&](Tap&, Time t, std::span<const std::byte> d) {
        const auto g = parse_seg(1, true, t, d);
        const bool pass = !zero;
        if (g && !g->has(wire::tcp_syn) && g->h.window == 0) {
          zero = true;
        }
        return pass;
      };
    };
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_TRUE(zero);
    EXPECT_EQ(o.closes(0), std::vector<CloseCause>{CloseCause::timed_out});
    EXPECT_GE(o.stats[0].TcpExtTCPWinProbe, tcp_config(profile).data_retries);
    EXPECT_EQ(o.stats[0].TcpExtTCPAbortOnTimeout, 1u);
    EXPECT_EQ(o.closes(1), std::vector<CloseCause>{CloseCause::rst_received});
  }
}

}  // namespace
}  // namespace utcp::sim
