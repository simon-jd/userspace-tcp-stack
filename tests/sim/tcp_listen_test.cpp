// Directed simulator scenarios for listeners (m1-tcp-core acceptance test
// 6, m1-tcp-robust test 6) over links with loss and reordering: SYNs beyond
// the backlog, a connection to a closed port, and 1000 connections through
// one listener.
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

// §3.5 tcp_listen: eight clients start within 700 us against a listener with
// backlog 1. SYNs beyond the backlog are dropped (ListenOverflows /
// ListenDrops) and retransmitted; every client gets through and its bytes
// reach the right connection (the shared listener tells them apart by the
// client port).
TEST(TcpListenSim, SynsBeyondTheBacklogAreDroppedAndRetried) {
  for (std::uint64_t seed = 0; seed < 4; ++seed) {
    SCOPED_TRACE(seed);
    Scenario s = two_node_scenario(8000 + seed, impaired(10ms, 50'000), impaired(10ms, 50'000));
    std::uint64_t c2s = 0, s2c = 0;
    for (std::uint32_t i = 0; i < 8; ++i) {
      ConnSpec c = bulk(30'000 + i * 1000, 10'000 + i);
      c.client_port = static_cast<std::uint16_t>(41000 + i);
      c.start = 1ms + i * 100us;
      c2s += c.bytes_c2s;
      s2c += c.bytes_s2c;
      s.conn.push_back(c);
    }
    RunSpec spec;
    spec.keep_wire = false;
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, c2s);
    EXPECT_EQ(o.counts[0].tcp_bytes_received, s2c);
    EXPECT_GT(o.stats[1].TcpExtListenDrops, 0u);
    EXPECT_EQ(o.stats[1].TcpPassiveOpens, 8u + o.stats[1].TcpAttemptFails);
    EXPECT_EQ(o.counts[0].tcp_errors + o.counts[1].tcp_errors, 0u);
  }
}

// RFC 9293 §3.10.7.3: a SYN to a port without a listener draws an RST; the
// client fails with connection_refused, also when SYNs or RSTs are lost
// (the retransmitted SYN draws another RST).
TEST(TcpListenSim, ConnectToClosedPortIsRefused) {
  int retried = 0;
  for (std::uint64_t seed = 0; seed < 12; ++seed) {
    SCOPED_TRACE(seed);
    Scenario s = two_node_scenario(8100 + seed, impaired(10ms, 300'000), impaired(10ms, 300'000));
    s.conn.push_back(bulk(10'000, 10'000, CloseMode::refused));
    s.conn.back().server_port = 6001;
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.closes(0), std::vector<CloseCause>{CloseCause::refused});
    EXPECT_GE(o.stats[1].TcpOutRsts, 1u);
    retried += o.stats[0].TcpExtTCPSynRetrans > 0 ? 1 : 0;
  }
  EXPECT_GT(retried, 0);
}

// §4.3 (m1-tcp-core test 6): 1000 connections through one listener (backlog
// 128) at the same time. The clients start within 2 ms, so SYNs beyond the
// backlog are dropped and retried; each server reader pauses for 30 s before
// it reads EOF, so every connection stays open until all have connected.
// A tap samples the server's slot count: all 1000 children (and the
// listener) are open at once. Under loss and reordering every byte arrives.
TEST(TcpListenSim, ThousandConnectionsThroughOneListener) {
  Scenario s = two_node_scenario(8200, impaired(5ms, 10'000), impaired(5ms, 10'000));
  std::uint64_t total = 0;
  for (std::uint32_t i = 0; i < 1000; ++i) {
    ConnSpec c = bulk(2000 + i, 1000 + i);
    c.client_port = static_cast<std::uint16_t>(20000 + i);
    c.backlog = 128;
    c.start = 1ms + i * 2us;
    c.write_max_c = c.write_max_s = 1500;
    c.pause_every_s = c.bytes_c2s;  // once, after the last byte and before EOF
    c.pause_s = 30s;
    total += c.bytes_c2s + c.bytes_s2c;
    s.conn.push_back(c);
  }
  std::uint32_t peak = 0;
  RunSpec spec;
  spec.keep_wire = false;
  spec.keep_trace = false;
  spec.setup = [&](std::vector<Tap*>& taps) {
    taps[1]->egress = [&](Tap& tap, Time, std::span<const std::byte>) {
      peak = std::max(peak, tap.stack().debug_usage().tcp_slots);
      return true;
    };
  };
  const Outcome o = run_sim(s, spec);
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[0].tcp_bytes_received + o.counts[1].tcp_bytes_received, total);
  EXPECT_EQ(o.stats[0].TcpActiveOpens, 1000u);
  EXPECT_GE(o.stats[1].TcpPassiveOpens, 1000u);
  EXPECT_EQ(peak, 1001u);  // every child and the listener
  // 1000 SYNs within 2 ms against a backlog of 128: the SYN queue overflows.
  EXPECT_GT(o.stats[1].TcpExtListenDrops, 0u);
  EXPECT_GT(o.stats[0].TcpExtTCPSynRetrans, 0u);
  EXPECT_EQ(o.counts[0].tcp_errors + o.counts[1].tcp_errors, 0u);
  EXPECT_GT(o.stats[0].TcpRetransSegs + o.stats[1].TcpRetransSegs, 0u);
}

}  // namespace
}  // namespace utcp::sim
