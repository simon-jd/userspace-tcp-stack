// Directed simulator scenarios for path MTU discovery and ICMP errors
// (m1-tcp-robust acceptance tests 4 and 6): a router with a 1400-byte link
// answering with frag-needed, forged frag-needed messages, and port
// unreachable in SYN-SENT, with loss and reordering on the other segments.
#include "tcp_sim_util.hpp"

#include "support/packet_builder.hpp"

namespace utcp::sim {
namespace {

// a -> r -> b where r>b has MTU 1400 and r answers too-big DF datagrams with
// ICMP 3/4. a's mss_cache drops from 1448 to 1348 (1400 - 40 - 12 bytes of
// TS), the oversized segments are resent as pmtu_rexmit under cwnd (no
// InFlightChecker violation), and no later new segment exceeds 1348 bytes.
TEST(TcpPmtuSim, NarrowRouterLowersTheMss) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(static_cast<int>(profile));
    Scenario s = two_node_scenario(9400 + static_cast<std::uint64_t>(profile),
                                   clean_link(1ms), clean_link(1ms));
    LinkParams narrow = clean_link(1ms);
    narrow.mtu = 1400;
    narrow.send_frag_needed = true;
    s.link = {LinkSpec{"a>r", impaired(5ms, 20'000)}, LinkSpec{"r>b", narrow},
              LinkSpec{"b>r", impaired(5ms, 20'000)}, LinkSpec{"r>a", clean_link(1ms)}};
    s.path = {PathSpec{0, 1, {0, 1}}, PathSpec{1, 0, {2, 3}}};
    for (NodeSpec& n : s.node) {
      n.profile = profile;
    }
    s.conn.push_back(bulk(2'000'000, 500'000));
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, 2'000'000u);
    EXPECT_GT(o.result.links[1].frag_needed, 0u);
    std::optional<Time> lowered;
    int pmtu_rexmit = 0;
    for (const Rec& r : o.trace) {
      if (r.node != 0 || r.e.kind != TraceKind::tx) {
        continue;
      }
      if (r.e.mss == 1348 && !lowered) {
        lowered = r.e.t;
      }
      if (lowered) {
        EXPECT_EQ(r.e.mss, 1348);
        EXPECT_LE(r.e.len, 1348u);
      }
      pmtu_rexmit += r.e.tx == TxKind::pmtu_rexmit ? 1 : 0;
    }
    ASSERT_TRUE(lowered.has_value());
    EXPECT_GT(pmtu_rexmit, 0);
    // b sends through a 1500-byte path: its MSS stays.
    for (const Seg& g : o.segs(1, true)) {
      EXPECT_LE(g.len, 1448u);
    }
  }
}

// RFC 5927 §4.1: forged frag-needed messages with random sequence numbers
// (icmp_spoof_ppm) quote nothing in [SND.UNA, SND.NXT); they are ignored and
// counted, and the MSS stays 1448.
TEST(TcpPmtuSim, ForgedFragNeededIsIgnored) {
  LinkParams ab = impaired(5ms, 20'000);
  ab.icmp_spoof_ppm = 50'000;
  Scenario s = two_node_scenario(9500, ab, impaired(5ms, 20'000));
  s.conn.push_back(bulk(2'000'000, 0));
  const Outcome o = run_sim(s);
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_GT(o.result.links[0].spoofed, 50u);
  EXPECT_GT(o.stats[0].icmp_seq_invalid, 50u);
  for (const Rec& r : o.trace) {
    if (r.node == 0 && r.e.kind == TraceKind::tx && r.e.tx == TxKind::data) {
      EXPECT_EQ(r.e.mss, 1448);
    }
  }
}

// RFC 1122 §4.2.3.9, §4.7: ICMP port unreachable for the SYN of a
// connection in SYN-SENT is a hard error: connection_refused. Every SYN is
// lost on the way; the error arrives 20 ms after the second SYN.
TEST(TcpPmtuSim, PortUnreachableInSynSentRefuses) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(static_cast<int>(profile));
    Scenario s = two_node_scenario(9600, impaired(10ms, 1'000'000), impaired(10ms, 50'000));
    for (NodeSpec& n : s.node) {
      n.profile = profile;
    }
    s.conn.push_back(bulk(10'000, 0, CloseMode::refused));
    int syns = 0;
    RunSpec spec;
    spec.setup = [&](std::vector<Tap*>& taps) {
      taps[0]->egress = [&](Tap& t, Time now, std::span<const std::byte> d) {
        const auto g = parse_seg(0, true, now, d);
        if (g && g->has(wire::tcp_syn) && ++syns == 2) {
          t.inject_at(now + 20ms, test::icmp_error(node_addr(1), node_addr(0), 3, 3, 0,
                                                   std::vector<std::byte>(d.begin(), d.end())));
        }
        return true;
      };
    };
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(syns, 2);
    EXPECT_EQ(o.closes(0), std::vector<CloseCause>{CloseCause::refused});
  }
}

}  // namespace
}  // namespace utcp::sim
