// Directed simulator scenarios for closing (m1-tcp-core acceptance test 3,
// m1-tcp-robust test 6) over links with loss and reordering: half-close each
// way with the other direction still sending, abort in the middle of a
// transfer, close with unread data and data after close. The
// TerminationChecker accepts each end only if it is legal (§7.3).
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

// RFC 9293 §3.6: after the client's FIN the server keeps sending (half_close
// mode: the server reads to EOF, then sends its data back and closes), in
// both directions at once (one connection opened from each node).
TEST(TcpCloseSim, HalfCloseEachWay) {
  for (std::uint64_t seed = 0; seed < 6; ++seed) {
    SCOPED_TRACE(seed);
    Scenario s = two_node_scenario(5000 + seed, impaired(4ms, 50'000, 10'000),
                                   impaired(4ms, 50'000, 10'000));
    s.node[seed % 2].profile = ProfileId::rfc;
    ConnSpec a = bulk(300'000, 500'000, CloseMode::half_close);
    ConnSpec b = a;
    b.client = 1;
    b.server_port = 5001;
    b.bytes_c2s = 200'000;
    b.bytes_s2c = 400'000;
    s.conn = {a, b};
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[0].tcp_bytes_received, 500'000u + 200'000u);
    EXPECT_EQ(o.counts[1].tcp_bytes_received, 300'000u + 400'000u);
    // The server of each connection sent data after it received the FIN.
    for (std::uint32_t n = 0; n < 2; ++n) {
      std::optional<Time> fin_in;
      bool data_after = false;
      for (const Seg& g : o.wire) {
        if (g.node != n) {
          continue;
        }
        const std::uint16_t server_port = n == 1 ? 5000 : 5001;
        if (!g.egress && g.has(wire::tcp_fin) && g.dst.port == server_port && !fin_in) {
          fin_in = g.t;
        }
        if (g.egress && fin_in && g.src.port == server_port && g.len > 0 && g.t > *fin_in) {
          data_after = true;
        }
      }
      EXPECT_TRUE(fin_in.has_value()) << n;
      EXPECT_TRUE(data_after) << n;
    }
  }
}

// §3.5 tcp_abort: the client aborts 50 ms into a 1 MB transfer each way; it
// sends RST, the server's connection ends with rst_received, also when the
// RST is lost and a later segment of the server draws a new one.
TEST(TcpCloseSim, AbortInTheMiddleOfATransfer) {
  for (std::uint64_t seed = 0; seed < 8; ++seed) {
    SCOPED_TRACE(seed);
    Scenario s = two_node_scenario(5100 + seed, impaired(4ms, 100'000), impaired(4ms, 100'000));
    ConnSpec c = bulk(1'000'000, 1'000'000, CloseMode::abort);
    c.abort_after = 50ms;
    s.conn.push_back(c);
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.closes(0), std::vector<CloseCause>{CloseCause::aborted});
    EXPECT_EQ(o.closes(1), std::vector<CloseCause>{CloseCause::rst_received});
    EXPECT_GE(o.stats[0].TcpOutRsts, 1u);
    EXPECT_LT(o.counts[1].tcp_bytes_received, 1'000'000u);
  }
}

// A server application for the close tests: listens on 5000, accepts one
// connection and closes the listener; `act` decides when to close the child.
struct OneShotServer {
  std::optional<Handle> listener, child;
  bool listened = false, closed = false;
  std::uint64_t read = 0;

  void step(AppNode& n, const std::function<bool(AppNode&, Handle, OneShotServer&)>& act) {
    Stack& st = n.stack();
    while (st.poll_event()) {
    }
    if (!listened) {
      const auto l = st.tcp_listen(Endpoint{node_addr(n.index()), 5000}, 1);
      ASSERT_TRUE(l.has_value());
      listener = *l;
      listened = true;
    }
    if (listener && !child) {
      if (const auto c = st.tcp_accept(*listener)) {
        child = *c;
        n.closing(*listener);
        ASSERT_TRUE(st.tcp_close(*listener).has_value());
        listener.reset();
      }
    }
    if (child && !closed && act(n, *child, *this)) {
      n.closing(*child);
      ASSERT_TRUE(st.tcp_close(*child).has_value());
      closed = true;
      n.done = true;
    }
  }
};

// RFC 1122 §4.2.2.13, §3.5 tcp_close: the server closes with unread data, so
// it sends RST at once (TCPAbortOnClose); the client's connection is reset.
TEST(TcpCloseSim, CloseWithUnreadDataSendsRst) {
  for (std::uint64_t seed = 0; seed < 6; ++seed) {
    SCOPED_TRACE(seed);
    Scenario s = two_node_scenario(5200 + seed, impaired(4ms, 50'000), impaired(4ms, 50'000));
    s.conn.push_back(bulk(400'000, 0));
    OneShotServer srv;
    RunSpec spec;
    spec.make = [&](const Scenario& sc, std::uint32_t i) -> std::unique_ptr<Node> {
      if (i != 1) {
        return nullptr;
      }
      auto n = std::make_unique<AppNode>(sc, i);
      n->script = [&](AppNode& node, Time) {
        srv.step(node, [](AppNode& nn, Handle h, OneShotServer&) {
          const auto info = nn.stack().tcp_info(h);
          return info && info->bytes_received >= 50'000;  // nothing read
        });
      };
      return n;
    };
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_TRUE(srv.closed);
    EXPECT_EQ(o.stats[1].TcpExtTCPAbortOnClose, 1u);
    EXPECT_EQ(o.closes(1), std::vector<CloseCause>{CloseCause::aborted});
    EXPECT_EQ(o.closes(0), std::vector<CloseCause>{CloseCause::rst_received});
    EXPECT_EQ(o.counts[0].tcp_errors, 1u);
  }
}

// §3.5 tcp_close, Linux tcp_rcv_state_process: the server reads everything
// it has and closes (FIN); the client keeps sending, and data arriving after
// the close draws an RST (TCPAbortOnData).
TEST(TcpCloseSim, DataAfterCloseSendsRst) {
  for (std::uint64_t seed = 0; seed < 6; ++seed) {
    SCOPED_TRACE(seed);
    Scenario s = two_node_scenario(5300 + seed, impaired(4ms, 50'000), impaired(4ms, 50'000));
    s.conn.push_back(bulk(2'000'000, 0));
    OneShotServer srv;
    RunSpec spec;
    spec.make = [&](const Scenario& sc, std::uint32_t i) -> std::unique_ptr<Node> {
      if (i != 1) {
        return nullptr;
      }
      auto n = std::make_unique<AppNode>(sc, i);
      n->script = [&](AppNode& node, Time) {
        srv.step(node, [](AppNode& nn, Handle h, OneShotServer& me) {
          std::vector<std::byte> buf(65536);
          for (;;) {
            const auto r = nn.stack().tcp_recv(h, buf);
            if (!r || *r == 0) {
              break;
            }
            me.read += *r;
          }
          return me.read >= 100'000;
        });
      };
      return n;
    };
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_TRUE(srv.closed);
    EXPECT_GE(srv.read, 100'000u);
    EXPECT_GE(o.stats[1].TcpExtTCPAbortOnData, 1u);
    EXPECT_EQ(o.stats[1].TcpExtTCPAbortOnClose, 0u);
    EXPECT_EQ(o.closes(1), std::vector<CloseCause>{CloseCause::aborted});
    EXPECT_EQ(o.closes(0), std::vector<CloseCause>{CloseCause::rst_received});
    // The server sent its FIN before the RST.
    bool fin = false, rst_after_fin = false;
    for (const Seg& g : o.segs(1, true)) {
      fin = fin || g.has(wire::tcp_fin);
      rst_after_fin = rst_after_fin || (fin && g.has(wire::tcp_rst));
    }
    EXPECT_TRUE(rst_after_fin);
  }
}

}  // namespace
}  // namespace utcp::sim
