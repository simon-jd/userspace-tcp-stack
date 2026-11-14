// Directed simulator scenarios for bulk transfer (m1-tcp-core acceptance
// tests 2 and 6, m1-tcp-robust tests 5 and 6) over links with loss,
// reordering and duplication: 10 MB each way, sequence wrap, a reneging
// receiver, and connections blocked on a small transmit queue. The
// StreamChecker compares every byte read with the byte written at its
// offset and the length at EOF, so a passing run has equal data both ways.
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

constexpr std::uint64_t mb = 1'000'000;

// 10 MB each way with all options on and all off, per profile. SACK blocks
// and D-SACKs never leave the payload (duplicated FINs, SYN-ACKs and pure
// ACKs are not D-SACKed; ranges over the FIN are clipped).
TEST(TcpTransferSim, TenMegabytesEachWayUnderLossReorderingAndDuplication) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    for (const bool options : {true, false}) {
      SCOPED_TRACE(std::to_string(static_cast<int>(profile)) + (options ? " options" : " none"));
      Scenario s = two_node_scenario(4000 + (options ? 1 : 0) + (profile == ProfileId::rfc ? 2 : 0),
                                     impaired(2ms, 10'000, 5'000), impaired(2ms, 10'000, 5'000));
      for (NodeSpec& n : s.node) {
        n.profile = profile;
        n.sack = n.timestamps = n.window_scaling = options;
      }
      s.conn.push_back(bulk(10 * mb, 10 * mb));
      RunSpec spec;
      spec.keep_trace = false;
      const Outcome o = run_sim(s, spec);
      ASSERT_TRUE(o.ok()) << o.violations();
      EXPECT_EQ(o.counts[0].tcp_bytes_received, 10 * mb);
      EXPECT_EQ(o.counts[1].tcp_bytes_received, 10 * mb);
      const auto bad = sack_outside_payload(o);
      EXPECT_FALSE(bad) << *bad;
      for (std::uint32_t n = 0; n < 2; ++n) {
        EXPECT_GT(o.stats[n].TcpRetransSegs, 0u) << n;
        EXPECT_EQ(o.stats[n].TcpExtTCPSACKDiscard, 0u) << n;
        if (options) {
          EXPECT_GT(o.stats[n].TcpExtTCPSackRecovery, 0u) << n;
          EXPECT_GT(o.stats[n].TcpExtTCPDSACKRecv, 0u) << n;  // duplicated data segments
        } else {
          EXPECT_GT(o.stats[n].TcpExtTCPRenoRecovery, 0u) << n;
        }
      }
    }
  }
}

// RFC 9293 §3.4: sequence numbers wrap. Both sides start at 0xFFFFF000, so
// the first 4 KiB of each direction cross 2^32, under loss and reordering.
TEST(TcpTransferSim, SequenceWrap) {
  for (const bool sack : {true, false}) {
    SCOPED_TRACE(sack);
    Scenario s = two_node_scenario(4100 + (sack ? 1 : 0), impaired(5ms, 30'000, 10'000),
                                   impaired(5ms, 30'000, 10'000));
    for (NodeSpec& n : s.node) {
      n.test_isn = 0xFFFF'F000u;
      n.sack = sack;
    }
    s.conn.push_back(bulk(2 * mb, 2 * mb));
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[0].tcp_bytes_received, 2 * mb);
    EXPECT_EQ(o.counts[1].tcp_bytes_received, 2 * mb);
    const auto bad = sack_outside_payload(o);
    EXPECT_FALSE(bad) << *bad;
    for (std::uint32_t n = 0; n < 2; ++n) {
      bool syn = false, wrapped = false;
      for (const Seg& g : o.segs(n, true)) {
        if (g.has(wire::tcp_syn)) {
          EXPECT_EQ(g.h.seq.raw(), 0xFFFF'F000u);
          syn = true;
        } else if (g.len > 0 && g.h.seq.raw() < 0x1000'0000u) {
          wrapped = true;
        }
      }
      EXPECT_TRUE(syn);
      EXPECT_TRUE(wrapped);
      EXPECT_GT(o.stats[n].TcpRetransSegs, 0u);
    }
  }
}

// RFC 2018 §8, DESIGN §5.3 (m1-tcp-robust test 5): the receiver drops
// SACKed out-of-order data now and then (test_renege_ppm); the sender's RTO
// finds the head SACKed, forgets the SACK marks, resends and counts
// TCPSACKReneging; the data arrives intact.
TEST(TcpTransferSim, RenegingReceiver) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(static_cast<int>(profile));
    Scenario s = two_node_scenario(4200 + static_cast<std::uint64_t>(profile),
                                   impaired(5ms, 30'000), impaired(5ms, 10'000));
    for (NodeSpec& n : s.node) {
      n.profile = profile;
    }
    s.node[1].renege_ppm = 300'000;
    s.conn.push_back(bulk(4 * mb, 0));
    RunSpec spec;
    spec.keep_trace = false;
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, 4 * mb);
    EXPECT_GT(o.stats[0].TcpExtTCPSACKReneging, 0u);
    EXPECT_GT(o.stats[0].TcpExtTCPTimeouts, 0u);
  }
}

// §3.4, D12 (m1-tcp-core test 6): with an 8-packet transmit queue, a small
// packet pool and a host that drains two datagrams per wake-up, connections
// block on transmit space and resume when the host drains; four
// connections both ways complete under loss and reordering.
TEST(TcpTransferSim, BlockedConnectionsResumeWhenTheHostDrains) {
  Scenario s = two_node_scenario(4300, impaired(3ms, 10'000), impaired(3ms, 10'000));
  for (NodeSpec& n : s.node) {
    n.tx_queue_packets = 8;
    n.pool_buffers = 64;
    n.host_drain_max = 2;
    n.host_delay = 200us;
  }
  for (std::uint32_t i = 0; i < 4; ++i) {
    ConnSpec c = bulk(300'000 + i, 200'000 + i);
    c.client = i % 2;
    c.server_port = static_cast<std::uint16_t>(5000 + i);
    c.start = 1ms + i * 100us;
    s.conn.push_back(c);
  }
  RunSpec spec;
  spec.keep_wire = false;
  const Outcome o = run_sim(s, spec);
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[0].tcp_bytes_received + o.counts[1].tcp_bytes_received,
            2 * (300'000u + 200'000u) * 2 + 2 * (0 + 1 + 2 + 3));
}

}  // namespace
}  // namespace utcp::sim
