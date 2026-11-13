// The World with test nodes that emit synthetic IPv4 (m1-sim acceptance
// tests 5 and 7, and the World-driven checks of test 6: leak, progress,
// stuck, livelock).
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "utcp/sim/checkers.hpp"
#include "utcp/sim/datagram.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/sim/synthetic_node.hpp"
#include "utcp/sim/world.hpp"

namespace utcp::sim {
namespace {

using namespace std::chrono_literals;

LinkParams with_delay(Duration d) {
  LinkParams p;
  p.delay = d;
  return p;
}

struct TestWorld {
  ScriptedNode* a = nullptr;
  ScriptedNode* b = nullptr;
  std::unique_ptr<World> w;
};

TestWorld scripted_world(const Scenario& s, WorldOptions opt = {}, std::uint32_t pool_a = 64) {
  auto a = std::make_unique<ScriptedNode>(pool_a);
  auto b = std::make_unique<ScriptedNode>();
  TestWorld t{a.get(), b.get(), nullptr};
  std::vector<std::unique_ptr<Node>> nodes;
  nodes.push_back(std::move(a));
  nodes.push_back(std::move(b));
  t.w = std::make_unique<World>(s, std::move(nodes), std::move(opt));
  return t;
}

std::vector<std::byte> udp_ab(std::uint32_t n, std::size_t len = 100) {
  std::vector<std::byte> payload(len);
  for (std::size_t i = 0; i < len; ++i) {
    payload[i] = static_cast<std::byte>(n + i);
  }
  return build_udp(Endpoint{node_addr(0), 1000}, Endpoint{node_addr(1), 2000}, payload,
                   static_cast<std::uint16_t>(n));
}

std::vector<std::byte> udp_ba(std::uint32_t n, std::size_t len = 100) {
  std::vector<std::byte> payload(len, std::byte{0x5a});
  return build_udp(Endpoint{node_addr(1), 2000}, Endpoint{node_addr(0), 1000}, payload,
                   static_cast<std::uint16_t>(n));
}

// --- Test 7: the World.

TEST(SimWorld, DatagramBytesCopiedAtDrain) {
  const Scenario s = two_node_scenario(1, with_delay(10ms), with_delay(10ms));
  auto t = scripted_world(s, {}, 4);
  std::vector<std::vector<std::byte>> sent;
  for (std::uint32_t i = 0; i < 4; ++i) {
    sent.push_back(udp_ab(i));
    t.a->send_at(s.start, sent.back());
  }
  bool checked = false;
  t.a->app_at(s.start + 1ms);
  t.a->on_app = [&](ScriptedNode& n, Time now) {
    // All four datagrams are on the link, and the node's pool is full again.
    EXPECT_EQ(now, s.start + 1ms);
    EXPECT_EQ(n.pool_available(), n.pool_size());
    EXPECT_TRUE(t.b->received().empty());
    for (std::uint32_t i = 4; i < 8; ++i) {
      sent.push_back(udp_ab(i));
      n.send_now(sent.back());
    }
    EXPECT_EQ(n.pool_available(), 0u);
    checked = true;
  };
  const RunResult r = t.w->run();
  EXPECT_EQ(r.verdict, Verdict::ok) << (r.violations.empty() ? "" : r.violations[0].message);
  EXPECT_TRUE(checked);
  EXPECT_EQ(t.a->alloc_failures(), 0u);
  EXPECT_EQ(t.a->pool_available(), 4u);
  ASSERT_EQ(t.b->received().size(), 8u);
  for (std::size_t i = 0; i < 8; ++i) {
    EXPECT_EQ(t.b->received()[i].bytes, sent[i]) << i;
    EXPECT_EQ(t.b->received()[i].t, s.start + (i < 4 ? 10ms : 11ms));
  }
  EXPECT_EQ(r.packets, 8u);
}

TEST(SimWorld, AdvanceBeforeEveryApplicationAction) {
  const Scenario s = two_node_scenario(2, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  t.a->app_at(s.start + 5ms);
  t.a->app_at(s.start + 7ms);
  t.b->send_at(s.start + 4ms, udp_ba(1));  // reaches a at +5 ms, with the app action
  t.b->send_at(s.start + 8ms, udp_ba(2));
  // On receipt, a's application wants to act at once.
  t.a->on_receive = [](ScriptedNode& n, Time now, std::span<const std::byte>) { n.app_at(now); };
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::ok);
  const auto& calls = t.a->calls();
  int actions = 0;
  for (std::size_t i = 0; i < calls.size(); ++i) {
    if (calls[i].first != 'p') {
      continue;
    }
    ++actions;
    ASSERT_GT(i, 0u);
    EXPECT_EQ(calls[i - 1].first, 'a') << "action " << i;
    EXPECT_EQ(calls[i - 1].second, calls[i].second);
  }
  EXPECT_EQ(actions, 4);
  // The receive at +9 ms is followed by advance and the action.
  ASSERT_GE(calls.size(), 3u);
  EXPECT_EQ(calls[calls.size() - 3].first, 'r');
  EXPECT_EQ(calls[calls.size() - 3].second, s.start + 9ms);
}

TEST(SimWorld, AdvanceBeforeApplicationsThatActOnEveryCall) {
  // A StackNode's applications act on every call (they poll events and pump
  // every connection), after a receive too. A deadline due at the arrival
  // instant (here: the receive queues a datagram for now, as a receive that
  // frees transmit space makes next_deadline() == now, §3.4) is served by
  // advance(now) before they act.
  const Scenario s = two_node_scenario(18, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  t.a->act_on_every_call = true;
  t.b->send_at(s.start + 4ms, udp_ba(1));
  t.b->send_at(s.start + 6ms, udp_ba(2));
  t.a->on_receive = [](ScriptedNode& n, Time now, std::span<const std::byte>) {
    n.send_at(now, udp_ab(9));
  };
  std::size_t queued_at_action = 0;
  t.a->on_app = [&](ScriptedNode& n, Time) {
    // Whatever was due went out first: nothing is left pending.
    if (n.next_deadline() == Time::never()) {
      ++queued_at_action;
    }
  };
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::ok);
  const auto& calls = t.a->calls();
  int actions = 0, after_receive = 0;
  for (std::size_t i = 0; i < calls.size(); ++i) {
    if (calls[i].first != 'p') {
      continue;
    }
    ++actions;
    ASSERT_GT(i, 0u);
    EXPECT_EQ(calls[i - 1].first, 'a') << "action " << i;
    EXPECT_EQ(calls[i - 1].second, calls[i].second);
    if (i >= 2 && calls[i - 2].first == 'r') {
      ++after_receive;
    }
  }
  EXPECT_GE(actions, 3);
  EXPECT_EQ(after_receive, 2);  // both receives: r, a, p
  EXPECT_EQ(queued_at_action, static_cast<std::size_t>(actions));
  EXPECT_EQ(t.b->received().size(), 2u);
}

TEST(SimWorld, HostDrainMaxLimitsDrainsPerWakeup) {
  Scenario s = two_node_scenario(3, with_delay(1ms), with_delay(1ms));
  s.node[0].host_drain_max = 2;
  s.node[0].host_delay = 1ms;
  std::vector<Time> egress;
  WorldOptions opt;
  opt.on_wire = [&](const WireEvent& e) {
    if (e.egress && e.node == 0) {
      egress.push_back(e.t);
    }
  };
  auto t = scripted_world(s, std::move(opt));
  for (std::uint32_t i = 0; i < 5; ++i) {
    t.a->send_at(s.start, udp_ab(i));
  }
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::ok);
  const std::vector<Time> want{s.start, s.start, s.start + 1ms, s.start + 1ms, s.start + 2ms};
  EXPECT_EQ(egress, want);
  EXPECT_EQ(t.b->received().size(), 5u);
}

TEST(SimWorld, RunStartsAtScenarioStart) {
  Scenario s = two_node_scenario(4, with_delay(1ms), with_delay(1ms));
  s.start = Time{(std::int64_t{1} << 32) * 1'000'000 - 5'000'000'000};  // 5 s before 2^32 ms
  auto t = scripted_world(s);
  t.a->send_at(s.start + 10s, udp_ab(1));  // crosses 2^32 ms
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::ok);
  ASSERT_FALSE(t.a->calls().empty());
  EXPECT_EQ(t.a->calls().front(), std::make_pair('a', s.start));
  EXPECT_EQ(r.start, s.start);
  EXPECT_EQ(r.end, s.start + 10s + 1ms);
  ASSERT_EQ(t.b->received().size(), 1u);
}

TEST(SimWorld, FragNeededFromRouterReturnsAlongReversePath) {
  // a -(5 ms)- r -(5 ms, MTU 1000)- b: the router at the low-MTU segment's
  // entrance answers, and its ICMP crosses r>a only.
  Scenario s = two_node_scenario(5, LinkParams{}, LinkParams{});
  LinkParams narrow = with_delay(5ms);
  narrow.mtu = 1000;
  narrow.send_frag_needed = true;
  narrow.router_addr = Ipv4Addr::from_octets(198, 18, 0, 254);
  s.link = {LinkSpec{"a>r", with_delay(5ms)}, LinkSpec{"r>b", narrow},
            LinkSpec{"b>r", with_delay(5ms)}, LinkSpec{"r>a", with_delay(5ms)}};
  s.path = {PathSpec{0, 1, {0, 1}}, PathSpec{1, 0, {2, 3}}};
  auto t = scripted_world(s);
  const auto big = udp_ab(1, 1400);
  t.a->send_at(s.start, big);
  t.a->send_at(s.start, udp_ab(2, 900));
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::ok);
  ASSERT_EQ(t.b->received().size(), 1u);
  EXPECT_EQ(t.b->received()[0].t, s.start + 10ms);
  ASSERT_EQ(t.a->received().size(), 1u);
  const auto& got = t.a->received()[0];
  EXPECT_EQ(got.t, s.start + 10ms);
  const auto ip = wire::parse_ipv4(got.bytes);
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(ip->h.src, narrow.router_addr);
  const auto m = wire::parse_icmp(ip->payload, true);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->h.type, wire::icmp_dest_unreach);
  EXPECT_EQ(m->h.code, wire::icmp_frag_needed);
  EXPECT_EQ(m->h.next_hop_mtu(), 1000u);
  EXPECT_TRUE(std::equal(m->body.begin(), m->body.end(), big.begin()));
  EXPECT_EQ(r.links[1].frag_needed, 1u);
}

// --- Test 5: determinism.

TEST(SimWorld, SameScenarioSameDigest) {
  for (std::uint64_t seed = 0; seed < 30; ++seed) {
    const Scenario s = generate_scenario(seed, NodeKind::synthetic);
    const RunResult r1 = run_scenario(s);
    const RunResult r2 = run_scenario(s);
    ASSERT_EQ(r1.verdict, Verdict::ok)
        << "seed " << seed << ": " << (r1.violations.empty() ? "" : r1.violations[0].message);
    EXPECT_EQ(r1.digest, r2.digest) << seed;
    EXPECT_EQ(r1.events, r2.events) << seed;
    EXPECT_EQ(r1.end, r2.end) << seed;
    EXPECT_GT(r1.packets, 0u) << seed;
    EXPECT_EQ(r1.start, s.start);
  }
  EXPECT_NE(run_scenario(generate_scenario(1, NodeKind::synthetic)).digest,
            run_scenario(generate_scenario(2, NodeKind::synthetic)).digest);
}

TEST(SimWorld, StackNodesReplayIdentically) {
  for (std::uint64_t seed = 0; seed < 5; ++seed) {
    const Scenario s = generate_scenario(seed);
    const RunResult r1 = run_scenario(s);
    const RunResult r2 = run_scenario(s);
    EXPECT_EQ(r1.digest, r2.digest) << seed;
    EXPECT_EQ(r1.verdict, r2.verdict) << seed;
    EXPECT_EQ(r1.events, r2.events) << seed;
  }
}

TEST(SimWorld, StackNodesWithoutWorkloadQuiesce) {
  const Scenario s = two_node_scenario(6, with_delay(1ms), with_delay(1ms));
  const RunResult r = run_scenario(s);
  EXPECT_EQ(r.verdict, Verdict::ok) << (r.violations.empty() ? "" : r.violations[0].message);
}

TEST(SimWorld, PlantedFailure) {
  Scenario s = generate_scenario(7, NodeKind::synthetic);
  s.plant = Plant::fail;
  s.plant_after_events = 10;
  const RunResult r = run_scenario(s);
  EXPECT_EQ(r.verdict, Verdict::planted);
  EXPECT_EQ(r.events, 10u);
  EXPECT_EQ(run_scenario(s).digest, r.digest);
}

TEST(SimWorldDeathTest, PlantedAbort) {
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  Scenario s = generate_scenario(8, NodeKind::synthetic);
  s.plant = Plant::abort;
  s.plant_after_events = 5;
  EXPECT_DEATH(static_cast<void>(run_scenario(s)), "");
}

// --- Test 6: World-driven checks.

TEST(SimWorld, QuiescenceLeakFires) {
  const Scenario s = two_node_scenario(9, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  StackUsage u;
  u.tcp_slots = 1;
  u.pool_buffers = 16;
  u.pool_buffers_free = 15;
  t.a->usage = u;
  t.a->send_at(s.start + 1ms, udp_ab(1));
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::leak);
  EXPECT_NE(r.violations[0].message.find("tcp_slots 1"), std::string::npos);
  EXPECT_EQ(r.end, s.start + 2ms);  // judged once the datagram arrived
}

TEST(SimWorld, QuiescenceWaitsForConnectionTimers) {
  // A node whose connection timer stays armed is not judged until the bound;
  // then it is a leak.
  const Scenario s = two_node_scenario(10, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  StackUsage u;
  u.conn_timers_armed = 1;
  t.a->usage = u;
  t.a->fixed_deadline = s.start + 100'000s;
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::leak);
  EXPECT_EQ(r.end, s.start + progress_bound(tcp_config(ProfileId::linux_compat)));
}

TEST(SimWorld, ProgressBoundFires) {
  const Scenario s = two_node_scenario(11, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  t.a->done = false;
  for (int i = 1; i <= 30; ++i) {
    t.a->app_at(s.start + i * 100s);  // activity, but no progress
  }
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::progress);
  EXPECT_EQ(r.end, s.start + progress_bound(tcp_config(ProfileId::linux_compat)));
}

TEST(SimWorld, TraceEventsOtherThanStateAreNotProgress) {
  // Transmissions, timers, RTOs and probes without a state change are not
  // progress (§7.3): a connection that retransmits or probes forever trips
  // the bound.
  const Scenario s = two_node_scenario(19, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  t.a->done = false;
  for (int i = 1; i <= 30; ++i) {
    t.a->app_at(s.start + i * 100s);
  }
  t.a->on_app = [](ScriptedNode& n, Time now) {
    TraceEvent e;
    e.t = now;
    e.conn_id = 1;
    e.tuple = FourTuple{{node_addr(0), 40000}, {node_addr(1), 5000}};
    for (const TraceKind k : {TraceKind::tx, TraceKind::rx, TraceKind::ack, TraceKind::rtt,
                              TraceKind::rto, TraceKind::cwnd, TraceKind::recovery,
                              TraceKind::timer, TraceKind::icmp, TraceKind::drop}) {
      e.kind = k;
      e.tx = TxKind::zwp;
      e.timer = TraceTimer::persist;
      e.timer_op = TimerOp::fired;
      n.ctx()->on_trace(n.index(), e);
    }
  };
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::progress);
  EXPECT_EQ(r.end, s.start + progress_bound(tcp_config(ProfileId::linux_compat)));
}

TEST(SimWorld, StateChangesAreProgress) {
  const Scenario s = two_node_scenario(20, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  t.a->done = false;
  for (int i = 1; i <= 30; ++i) {
    t.a->app_at(s.start + i * 100s);
  }
  int step = 0;
  t.a->on_app = [&](ScriptedNode& n, Time now) {
    // One connection walks through states 100 s apart, then closes.
    static constexpr TcpState walk[] = {TcpState::syn_sent, TcpState::established,
                                        TcpState::fin_wait_1, TcpState::fin_wait_2,
                                        TcpState::time_wait};
    TraceEvent e;
    e.t = now;
    e.conn_id = 1;
    e.tuple = FourTuple{{node_addr(0), 40000}, {node_addr(1), 5000}};
    e.kind = TraceKind::state;
    if (++step < 30) {
      e.state = walk[std::min<std::size_t>(static_cast<std::size_t>(step - 1) / 6, 4)];
    } else {
      e.state = TcpState::closed;
      e.cause = CloseCause::time_wait_expired;
      n.done = true;
    }
    n.ctx()->on_trace(n.index(), e);
  };
  const RunResult r = t.w->run();
  EXPECT_EQ(r.verdict, Verdict::ok) << (r.violations.empty() ? "" : r.violations[0].message);
  EXPECT_EQ(r.end, s.start + 3000s);
}

TEST(SimWorld, ProgressKeepsTheRunAlive) {
  const Scenario s = two_node_scenario(12, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  t.a->done = false;
  for (int i = 1; i <= 30; ++i) {
    t.a->app_at(s.start + i * 100s);
  }
  int left = 30;
  t.a->on_app = [&](ScriptedNode& n, Time) {
    n.ctx()->on_progress();
    if (--left == 0) {
      n.done = true;
    }
  };
  const RunResult r = t.w->run();
  EXPECT_EQ(r.verdict, Verdict::ok);
  EXPECT_EQ(r.end, s.start + 3000s);
}

TEST(SimWorld, NoEventsLeftWithWorkPendingIsProgress) {
  const Scenario s = two_node_scenario(13, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  t.a->done = false;
  const RunResult r = t.w->run();
  EXPECT_EQ(r.verdict, Verdict::progress);
}

TEST(SimWorld, DeadlineThatNeverMovesIsStuck) {
  const Scenario s = two_node_scenario(14, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  t.a->fixed_deadline = s.start + 5ms;  // advance() never moves it
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::stuck);
  EXPECT_EQ(r.end, s.start + 5ms);
}

TEST(SimWorld, BusyDeadlineThatNeverMovesIsLivelock) {
  const Scenario s = two_node_scenario(15, with_delay(1ms), with_delay(1ms));
  WorldOptions opt;
  opt.max_events_per_instant = 10'000;
  auto t = scripted_world(s, std::move(opt));
  t.a->fixed_deadline = s.start + 5ms;
  t.a->activity_per_advance = 1;  // looks busy, never finishes
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::livelock);
  EXPECT_EQ(r.end, s.start + 5ms);
  EXPECT_GE(r.events, 10'000u);
}

TEST(SimWorld, EventLimitIsLivelock) {
  WorldOptions opt;
  opt.max_events = 50;
  Scenario s = generate_scenario(16, NodeKind::synthetic);
  s.conn[0].bytes_c2s = 100'000;
  World w(s, std::move(opt));
  EXPECT_EQ(w.run().verdict, Verdict::livelock);
}

// The wire shadow through the World: b scales its window by 4; a sender
// that scales it by 128 sends past the edge.
TEST(SimWorld, WireShadowCatchesUnscaledWindowSender) {
  const Scenario s = two_node_scenario(17, with_delay(1ms), with_delay(1ms));
  auto t = scripted_world(s);
  const Endpoint ea{node_addr(0), 40000}, eb{node_addr(1), 5000};
  const auto tcp = [](Endpoint from, Endpoint to, std::uint32_t seq, std::uint32_t ackn,
                      std::uint16_t flags, std::uint16_t win, std::size_t len,
                      std::optional<std::uint8_t> ws) {
    TcpSegmentSpec x;
    x.src = from;
    x.dst = to;
    x.seq = seq;
    x.ack = ackn;
    x.flags = flags;
    x.window = win;
    x.opt.wscale = ws;
    const std::vector<std::byte> payload(len);
    x.payload = payload;
    return build_tcp(x);
  };
  t.a->send_at(s.start, tcp(ea, eb, 100, 0, wire::tcp_syn, 65535, 0, 7));
  t.b->on_receive = [&](ScriptedNode& n, Time, std::span<const std::byte> d) {
    const auto p = parse_tcp_packet(d);
    if (p && (p->tcp.h.flags & wire::tcp_syn) != 0) {
      n.send_now(tcp(eb, ea, 5000, 101, wire::tcp_syn | wire::tcp_ack, 1000, 0, 2));
      n.send_now(tcp(eb, ea, 5001, 101, wire::tcp_ack, 1000, 0, std::nullopt));
    }
  };
  t.a->on_receive = [&](ScriptedNode& n, Time, std::span<const std::byte> d) {
    const auto p = parse_tcp_packet(d);
    if (p && (p->tcp.h.flags & wire::tcp_syn) == 0) {
      // 1000 << 7: the sender believes 128000 bytes are open.
      for (std::uint32_t i = 0; i < 5; ++i) {
        n.send_now(tcp(ea, eb, 101 + i * 1460, 5001, wire::tcp_ack, 500, 1460, std::nullopt));
      }
    }
  };
  const RunResult r = t.w->run();
  ASSERT_EQ(r.verdict, Verdict::inflight);
  EXPECT_NE(r.violations[0].message.find("right edge 4101"), std::string::npos)
      << r.violations[0].message;
}

}  // namespace
}  // namespace utcp::sim
