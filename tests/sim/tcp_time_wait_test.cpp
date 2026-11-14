// Directed simulator scenarios for TIME-WAIT and FIN-WAIT-2 (m1-tcp-core
// acceptance test 5, m1-tcp-robust test 6) over links with loss and
// reordering: the TIME-WAIT length per profile, a new SYN taking a TIME-WAIT
// tuple over, and the orphan FIN-WAIT-2 timeout.
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

// §3.9 time_wait: 60 s (linux_compat) or 240 s (rfc) after the last segment
// with an ACK that reached the entry (Linux tcp_timewait_state_process
// reschedules the entry on each, e.g. a retransmitted FIN).
TEST(TcpTimeWaitSim, LastsPerProfile) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    for (std::uint64_t seed = 0; seed < 4; ++seed) {
      SCOPED_TRACE(std::to_string(static_cast<int>(profile)) + "/" + std::to_string(seed));
      Scenario s = two_node_scenario(7000 + seed, impaired(10ms, 100'000, 20'000),
                                     impaired(10ms, 100'000, 20'000));
      s.node[0].profile = s.node[1].profile = profile;
      s.conn.push_back(bulk(100'000, 100'000));
      const Outcome o = run_sim(s);
      ASSERT_TRUE(o.ok()) << o.violations();
      const Duration tw = tcp_config(profile).time_wait;
      int entries = 0;
      for (std::uint32_t n = 0; n < 2; ++n) {
        std::optional<TraceEvent> enter;
        for (const Rec& r : o.trace) {
          if (r.node != n || r.e.kind != TraceKind::state || r.e.tuple.remote.port == 0) {
            continue;
          }
          if (r.e.state == TcpState::time_wait) {
            enter = r.e;
          } else if (enter && r.e.state == TcpState::closed) {
            EXPECT_EQ(r.e.cause, CloseCause::time_wait_expired);
            Time last = enter->t;
            for (const Seg& g : o.segs(n, false)) {
              if (g.t >= enter->t && g.t < r.e.t && g.dst == enter->tuple.local &&
                  g.src == enter->tuple.remote && g.has(wire::tcp_ack) &&
                  !g.has(wire::tcp_rst) && !g.has(wire::tcp_syn)) {
                last = g.t;
              }
            }
            EXPECT_EQ(r.e.t - last, tw);
            EXPECT_GE(r.e.t - enter->t, tw);
            ++entries;
            enter.reset();
          }
        }
      }
      EXPECT_GE(entries, 1);
    }
  }
}

// RFC 6191, §4.3: the server has nothing to send and shuts down at once,
// while the client is still sending 3 MB, so only the server's side of the
// connection ends in TIME-WAIT; 30 s in, the client connects again from the
// same port. The SYN carries a newer TSval, so the listener takes the tuple over
// (time_wait_reused) with ISS = the old SND.NXT + 65537, and the new
// connection carries its data.
TEST(TcpTimeWaitSim, NewSynTakesTheTupleOver) {
  for (std::uint64_t seed = 0; seed < 4; ++seed) {
    SCOPED_TRACE(seed);
    Scenario s = two_node_scenario(7100 + seed, impaired(10ms, 20'000), impaired(10ms, 20'000));
    ConnSpec first = bulk(3'000'000, 0);  // the server has nothing to send: it shuts down first
    first.client_port = 41000;
    ConnSpec second = bulk(60'000, 30'000);
    second.client_port = 41000;
    second.start = 30s;
    s.conn = {first, second};
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, 3'060'000u);
    EXPECT_EQ(o.counts[0].tcp_bytes_received, 30'000u);
    const auto reused = o.events(1, [](const TraceEvent& e) {
      return e.kind == TraceKind::state && e.state == TcpState::closed &&
             e.cause == CloseCause::time_wait_reused;
    });
    ASSERT_EQ(reused.size(), 1u);
    // The server's FIN of the first connection, and the SYN-ACK of the second.
    std::optional<Seq32> fin_end, synack;
    for (const Seg& g : o.segs(1, true)) {
      if (g.has(wire::tcp_fin) && g.t < reused[0].t) {
        fin_end = g.h.seq + g.seq_len();
      }
      if (g.has(wire::tcp_syn) && g.t >= reused[0].t && !synack) {
        synack = g.h.seq;
      }
    }
    ASSERT_TRUE(fin_end && synack);
    EXPECT_EQ(synack->raw(), (*fin_end + 65537).raw());
  }
}

// §4.12, §3.9 orphan_fin_wait2_timeout: the server reads to EOF but holds
// its side open for 700 s. The client's application closes after its idle
// timeout (300 s) in FIN-WAIT-2; the orphan is freed 60 s (linux_compat) or
// 240 s (rfc) after its fin_wait2 timer is armed. The server's later FIN
// draws an RST.
TEST(TcpTimeWaitSim, OrphanFinWait2Timeout) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(static_cast<int>(profile));
    Scenario s = two_node_scenario(7200, impaired(10ms, 50'000), impaired(10ms, 50'000));
    s.node[0].profile = s.node[1].profile = profile;
    s.conn.push_back(bulk(50'000, 0));
    std::optional<Handle> listener, child;
    bool listened = false, eof = false, closed = false;
    std::uint64_t got = 0;
    RunSpec spec;
    spec.make = [&](const Scenario& sc, std::uint32_t i) -> std::unique_ptr<Node> {
      if (i != 1) {
        return nullptr;
      }
      auto n = std::make_unique<AppNode>(sc, i);
      n->script = [&](AppNode& node, Time now) {
        Stack& st = node.stack();
        while (st.poll_event()) {
        }
        if (!listened) {
          listened = true;
          listener = st.tcp_listen(Endpoint{node_addr(1), 5000}, 1).value();
          node.wake_at(sc.start + 700s);
        }
        if (listener && !child) {
          if (const auto c = st.tcp_accept(*listener)) {
            child = *c;
            node.closing(*listener);
            ASSERT_TRUE(st.tcp_close(*listener).has_value());
            listener.reset();
          }
        }
        if (child && !eof) {
          std::vector<std::byte> buf(65536);
          for (;;) {
            const auto r = st.tcp_recv(*child, buf);
            if (!r) {
              break;
            }
            if (*r == 0) {
              eof = true;
              ASSERT_FALSE(node.ctx().stream().on_eof(0, 0, got).has_value());
              break;
            }
            const auto v = node.ctx().stream().on_read(0, 0, got, std::span(buf).first(*r));
            ASSERT_FALSE(v.has_value()) << *v;
            got += *r;
            node.ctx().on_progress();
          }
        }
        if (child && eof && !closed && now >= sc.start + 700s) {
          node.closing(*child);
          ASSERT_TRUE(st.tcp_close(*child).has_value());
          closed = true;
          node.done = true;
        }
      };
      return n;
    };
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(got, 50'000u);
    const auto armed = o.events(0, [](const TraceEvent& e) {
      return e.kind == TraceKind::timer && e.timer == TraceTimer::fin_wait2 &&
             e.timer_op == TimerOp::armed;
    });
    const auto end = o.events(0, [](const TraceEvent& e) {
      return e.kind == TraceKind::state && e.state == TcpState::closed && e.tuple.remote.port != 0;
    });
    ASSERT_FALSE(armed.empty());
    ASSERT_EQ(end.size(), 1u);
    EXPECT_EQ(end[0].cause, CloseCause::fin_wait2_timeout);
    EXPECT_EQ(end[0].t - armed.back().t, tcp_config(profile).orphan_fin_wait2_timeout);
    EXPECT_EQ(o.closes(1), std::vector<CloseCause>{CloseCause::rst_received});
  }
}

}  // namespace
}  // namespace utcp::sim
