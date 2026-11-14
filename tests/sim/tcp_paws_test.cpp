// Directed simulator scenarios for PAWS (m1-tcp-robust acceptance tests 2
// and 6): links duplicate segments and deliver the copy a second later, so
// it carries an old TSval, while loss and reordering go on. Old duplicates
// are dropped by PAWS (RFC 7323 §5.3) and the data still arrives intact,
// also across the sequence wrap.
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

TEST(TcpPawsSim, LateDuplicatesAreDroppedByPaws) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    for (const bool wrap : {false, true}) {
      SCOPED_TRACE(std::to_string(static_cast<int>(profile)) + (wrap ? " wrap" : ""));
      LinkParams p = impaired(5ms, 10'000, 30'000);
      p.dup_extra_delay = 1s;
      Scenario s = two_node_scenario(9100 + (wrap ? 1 : 0) + (profile == ProfileId::rfc ? 2 : 0),
                                     p, p);
      for (NodeSpec& n : s.node) {
        n.profile = profile;
        if (wrap) {
          n.test_isn = 0xFFFF'0000u;
        }
      }
      s.conn.push_back(bulk(3'000'000, 1'000'000));
      RunSpec spec;
      spec.keep_trace = false;
      const Outcome o = run_sim(s, spec);
      ASSERT_TRUE(o.ok()) << o.violations();
      EXPECT_EQ(o.counts[1].tcp_bytes_received, 3'000'000u);
      EXPECT_EQ(o.counts[0].tcp_bytes_received, 1'000'000u);
      // Old data segments: dropped and answered (rate-limited) with an ACK.
      for (std::uint32_t n = 0; n < 2; ++n) {
        EXPECT_GT(o.stats[n].TcpExtPAWSEstab, 0u) << n;
      }
      // Old pure ACKs: rfc drops them with an ACK (R1); linux_compat drops
      // them without a reply (tcp_validate_incoming, PAWSOldAck).
      const std::uint64_t old_acks = o.stats[0].TcpExtPAWSOldAck + o.stats[1].TcpExtPAWSOldAck;
      if (profile == ProfileId::rfc) {
        EXPECT_EQ(old_acks, 0u);
      } else {
        EXPECT_GT(old_acks, 0u);
      }
    }
  }
}

}  // namespace
}  // namespace utcp::sim
