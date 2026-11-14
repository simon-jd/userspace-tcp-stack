// Directed simulator scenarios for the handshake (m1-tcp-core acceptance
// test 1, m1-tcp-robust test 6): every SACK/TS/WS combination per side,
// simultaneous open and the initial window after SYN loss, over links with
// loss, reordering and duplication. Every run also passes all checkers.
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

// §4.5: TS on every segment iff both SYNs carried it; SACK blocks only if both
// offered SACK; window scale only in SYNs, and only if the side has it on;
// full segments carry 1460 bytes, 1448 with TS (MTU 1500).
TEST(TcpHandshakeSim, OptionCombinationsUnderLossReorderingAndDuplication) {
  int recovered = 0;
  for (std::uint32_t i = 0; i < 8; ++i) {
    for (std::uint32_t j = 0; j < 8; ++j) {
      SCOPED_TRACE("a=" + std::to_string(i) + " b=" + std::to_string(j));
      Scenario s = two_node_scenario(1000 + i * 8 + j, impaired(5ms, 20'000, 10'000),
                                     impaired(5ms, 20'000, 10'000));
      const std::uint32_t bits[2] = {i, j};
      for (std::uint32_t n = 0; n < 2; ++n) {
        s.node[n].sack = (bits[n] & 1) != 0;
        s.node[n].timestamps = (bits[n] & 2) != 0;
        s.node[n].window_scaling = (bits[n] & 4) != 0;
        s.node[n].profile = (i + j + n) % 2 == 0 ? ProfileId::linux_compat : ProfileId::rfc;
      }
      s.conn.push_back(bulk(40'000, 60'000));
      const Outcome o = run_sim(s);
      ASSERT_TRUE(o.ok()) << o.violations();
      EXPECT_EQ(o.counts[1].tcp_bytes_received, 40'000u);
      EXPECT_EQ(o.counts[0].tcp_bytes_received, 60'000u);
      const auto bad = sack_outside_payload(o);
      EXPECT_FALSE(bad) << *bad;
      const bool ts = s.node[0].timestamps && s.node[1].timestamps;
      const bool sack = s.node[0].sack && s.node[1].sack;
      for (std::uint32_t n = 0; n < 2; ++n) {
        const NodeSpec& me = s.node[n];
        for (const Seg& g : o.segs(n, true)) {
          if (g.has(wire::tcp_rst)) {
            continue;
          }
          if (g.has(wire::tcp_syn)) {
            EXPECT_EQ(g.opt.ts.has_value(), me.timestamps && (!g.has(wire::tcp_ack) || ts));
            EXPECT_EQ(g.opt.sack_permitted, me.sack && (!g.has(wire::tcp_ack) || sack));
            EXPECT_EQ(g.opt.wscale.has_value(),
                      me.window_scaling &&
                          (!g.has(wire::tcp_ack) || s.node[1 - n].window_scaling));
            EXPECT_TRUE(g.opt.mss.has_value());
            continue;
          }
          EXPECT_EQ(g.opt.ts.has_value(), ts);
          EXPECT_FALSE(g.opt.wscale.has_value());
          if (!sack) {
            EXPECT_EQ(g.opt.sack_count, 0);
          }
          EXPECT_LE(g.len, ts ? 1448u : 1460u);
        }
        const auto data = o.events(n, [](const TraceEvent& e) {
          return e.kind == TraceKind::tx && e.len > 0;
        });
        ASSERT_FALSE(data.empty());
        for (const TraceEvent& e : data) {
          EXPECT_EQ(e.mss, ts ? 1448 : 1460);
        }
      }
      recovered += o.stats[0].TcpRetransSegs > 0 && o.stats[1].TcpRetransSegs > 0 ? 1 : 0;
    }
  }
  EXPECT_GT(recovered, 10);  // the impairments did make both sides retransmit
}

// RFC 9293 §3.5 figure 8: both sides connect at the same time; each SYN
// crosses the other, both pass through SYN-RECEIVED. On a clean path each
// side sends one SYN and one SYN-ACK (crossing SYN-ACKs complete the
// handshake, no repeated SYN-ACKs); with loss and reordering every run still
// ends cleanly.
TEST(TcpHandshakeSim, SimultaneousOpen) {
  {
    Scenario s = two_node_scenario(2000, clean_link(10ms), clean_link(10ms));
    ConnSpec c = bulk(30'000, 30'000, CloseMode::simultaneous);
    c.client_port = 6000;
    s.conn.push_back(c);
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    for (std::uint32_t n = 0; n < 2; ++n) {
      int syn = 0, synack = 0;
      for (const Seg& g : o.segs(n, true)) {
        if (g.has(wire::tcp_syn)) {
          ++(g.has(wire::tcp_ack) ? synack : syn);
        }
      }
      EXPECT_EQ(syn, 1) << n;
      EXPECT_EQ(synack, 1) << n;
      EXPECT_FALSE(o.events(n, [](const TraceEvent& e) {
                      return e.kind == TraceKind::state && e.state == TcpState::syn_received;
                    }).empty());
    }
  }
  int both_syn_received = 0;
  for (std::uint64_t seed = 0; seed < 24; ++seed) {
    SCOPED_TRACE(seed);
    Scenario s = two_node_scenario(2100 + seed, impaired(10ms, 100'000, 20'000),
                                   impaired(10ms, 100'000, 20'000));
    s.node[seed % 2].profile = ProfileId::rfc;
    ConnSpec c = bulk(20'000, 20'000, CloseMode::simultaneous);
    c.client_port = 6000;
    s.conn.push_back(c);
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[0].tcp_bytes_received + o.counts[1].tcp_bytes_received, 40'000u);
    int n_syn_rcvd = 0;
    for (std::uint32_t n = 0; n < 2; ++n) {
      n_syn_rcvd += o.events(n, [](const TraceEvent& e) {
                      return e.kind == TraceKind::state && e.state == TcpState::syn_received;
                    }).empty()
                        ? 0
                        : 1;
    }
    both_syn_received += n_syn_rcvd == 2 ? 1 : 0;
  }
  EXPECT_GT(both_syn_received, 0);
}

// §3.9 iw_after_syn_loss: the client's first SYN (and second, for two
// losses) is dropped on its way out; the cwnd of the first data segment the
// client sends is IW = 1 after one SYN retransmission under rfc, after two
// under linux_compat, else the profile's IW (3 at MSS 1448, 10). The rest of
// the path reorders and loses packets.
TEST(TcpHandshakeSim, InitialWindowAfterSynLoss) {
  struct Case {
    ProfileId profile;
    int drops;
    std::uint32_t cwnd;
  };
  const Case cases[] = {{ProfileId::rfc, 0, 3},
                        {ProfileId::rfc, 1, 1},
                        {ProfileId::linux_compat, 0, 10},
                        {ProfileId::linux_compat, 1, 10},
                        {ProfileId::linux_compat, 2, 1}};
  for (const Case& c : cases) {
    SCOPED_TRACE(std::to_string(static_cast<int>(c.profile)) + "/" + std::to_string(c.drops));
    Scenario s = two_node_scenario(3000 + c.drops, impaired(20ms, 0), impaired(20ms, 0));
    s.node[0].profile = s.node[1].profile = c.profile;
    s.conn.push_back(bulk(200'000, 0));
    int dropped = 0;
    RunSpec spec;
    spec.setup = [&](std::vector<Tap*>& taps) {
      taps[0]->egress = [&](Tap&, Time, std::span<const std::byte> d) {
        const auto g = parse_seg(0, true, Time{}, d);
        if (g && g->has(wire::tcp_syn) && dropped < c.drops) {
          ++dropped;
          return false;
        }
        return true;
      };
    };
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(dropped, c.drops);
    const auto data = o.events(0, [](const TraceEvent& e) {
      return e.kind == TraceKind::tx && e.tx == TxKind::data && e.len > 0;
    });
    ASSERT_FALSE(data.empty());
    EXPECT_EQ(data.front().cwnd, c.cwnd);
    EXPECT_EQ(o.stats[0].TcpExtTCPSynRetrans, static_cast<std::uint64_t>(c.drops));
  }
}

}  // namespace
}  // namespace utcp::sim
