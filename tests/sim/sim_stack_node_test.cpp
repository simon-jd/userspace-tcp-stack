// StackNode scenarios over UDP, ICMP and TCP, run on the Stack's IPv4, UDP,
// ICMP and TCP engine.
#include <gtest/gtest.h>

#include "utcp/sim/datagram.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/sim/stack_node.hpp"
#include "utcp/sim/world.hpp"

namespace utcp::sim {
namespace {

using namespace std::chrono_literals;

LinkParams path(Duration delay, std::uint32_t loss_ppm = 0) {
  LinkParams p;
  p.delay = delay;
  p.loss_ppm = loss_ppm;
  return p;
}

struct StackRun {
  RunResult result;
  StackNode::Counts a, b;
};

StackRun run_stack(const Scenario& s) {
  std::vector<std::unique_ptr<Node>> nodes;
  nodes.push_back(std::make_unique<StackNode>(s, 0));
  nodes.push_back(std::make_unique<StackNode>(s, 1));
  auto* a = static_cast<StackNode*>(nodes[0].get());
  auto* b = static_cast<StackNode*>(nodes[1].get());
  World w(s, std::move(nodes));
  StackRun r;
  r.result = w.run();
  r.a = a->counts();
  r.b = b->counts();
  return r;
}

std::string first_violation(const RunResult& r) {
  return r.violations.empty() ? "" : r.violations[0].message;
}

TEST(SimStackNode, ConfigFollowsTheScenario) {
  Scenario s = two_node_scenario(1, path(1ms), path(1ms));
  s.node[1].profile = ProfileId::rfc;
  s.node[1].sack = false;
  s.node[1].test_isn = 0xffff'fff0u;
  s.node[1].pool_buffers = 32;
  s.node[1].chunk_limit = 20;
  const StackConfig c = stack_config(s, 1);
  EXPECT_EQ(c.local_addr, node_addr(1));
  EXPECT_FALSE(c.tcp.sack);
  EXPECT_EQ(c.tcp.test_isn, std::optional<std::uint32_t>{0xffff'fff0u});
  EXPECT_EQ(c.pool_buffers, 32u);
  EXPECT_EQ(c.chunk_limit, 20u);
  EXPECT_EQ(stack_config(s, 0).chunk_limit, StackConfig{}.chunk_limit);
  EXPECT_EQ(c.trace_mask, trace_mask_all);
  EXPECT_TRUE(c.assert_time_monotonic);
  EXPECT_NE(stack_config(s, 0).seed, c.seed);
}

TEST(SimStackNode, UdpEchoOverLossyPath) {
  Scenario s = two_node_scenario(2, path(5ms, 10'000), path(5ms, 10'000));
  s.udp.push_back(UdpSpec{0, 7, 0, true, 200, 1, 1400, 2ms, 10ms});
  const StackRun r = run_stack(s);
  ASSERT_EQ(r.result.verdict, Verdict::ok) << first_violation(r.result);
  EXPECT_EQ(r.a.udp_sent, 200u);
  EXPECT_GE(r.b.udp_echoed, 190u);
  EXPECT_GE(r.a.udp_replies, 180u);
  EXPECT_LE(r.a.udp_replies, r.b.udp_echoed);
}

TEST(SimStackNode, UdpToUnboundPortQuiesces) {
  Scenario s = two_node_scenario(3, path(1ms), path(1ms));
  s.udp.push_back(UdpSpec{0, 9, 0, false, 5, 10, 10, 1ms, 0ms});
  const StackRun r = run_stack(s);
  ASSERT_EQ(r.result.verdict, Verdict::ok) << first_violation(r.result);
  EXPECT_EQ(r.a.udp_sent, 5u);
  EXPECT_EQ(r.a.udp_replies, 0u);
}

TEST(SimStackNode, PingRepliesOverLossyPath) {
  Scenario s = two_node_scenario(4, path(2ms, 20'000), path(2ms));
  s.ping.push_back(PingSpec{0, 77, 100, 56, 10ms, 1ms});
  const StackRun r = run_stack(s);
  ASSERT_EQ(r.result.verdict, Verdict::ok) << first_violation(r.result);
  EXPECT_EQ(r.a.pings_sent, 100u);
  EXPECT_GE(r.a.ping_replies, 90u);
  EXPECT_LT(r.a.ping_replies, 100u);  // 2 % loss on the way out: some never return
}

TEST(SimStackNode, UdpThroughNarrowRouterLearnsPmtu) {
  Scenario s = two_node_scenario(5, path(1ms), path(1ms));
  LinkParams narrow = path(1ms);
  narrow.mtu = 1000;
  narrow.send_frag_needed = true;
  s.link = {LinkSpec{"a>r", path(1ms)}, LinkSpec{"r>b", narrow}, LinkSpec{"b>r", path(1ms)},
            LinkSpec{"r>a", path(1ms)}};
  s.path = {PathSpec{0, 1, {0, 1}}, PathSpec{1, 0, {2, 3}}};
  s.udp.push_back(UdpSpec{0, 7, 0, true, 20, 1200, 1200, 20ms, 0ms});
  const StackRun r = run_stack(s);
  ASSERT_EQ(r.result.verdict, Verdict::ok) << first_violation(r.result);
  EXPECT_EQ(r.result.links[1].frag_needed, 1u);  // later sends fail with message_too_big
}

// Backlog limits (§7.2): four clients start within 300 us against one
// listener with backlog 1. SYNs beyond the backlog are dropped and
// retransmitted (§3.5); the listener accepts each client, told apart by its
// fixed client port, and every byte arrives at the right connection.
TEST(SimStackNode, SharedListenerAcceptsEveryClientBeyondItsBacklog) {
  Scenario s = two_node_scenario(6, path(10ms), path(10ms));
  for (std::uint32_t i = 0; i < 4; ++i) {
    ConnSpec c;
    c.client = 0;
    c.server_port = 5000;
    c.client_port = static_cast<std::uint16_t>(41000 + i);
    c.backlog = 1;
    c.start = 1ms + i * 100us;
    c.bytes_c2s = 20'000 + i * 1000;
    c.bytes_s2c = 10'000 + i;
    s.conn.push_back(c);
  }
  const StackRun r = run_stack(s);
  ASSERT_EQ(r.result.verdict, Verdict::ok) << first_violation(r.result);
  EXPECT_EQ(r.a.tcp_bytes_sent, 86'000u);
  EXPECT_EQ(r.b.tcp_bytes_received, 86'000u);
  EXPECT_EQ(r.b.tcp_bytes_sent, 40'006u);
  EXPECT_EQ(r.a.tcp_bytes_received, 40'006u);
  EXPECT_EQ(r.a.tcp_errors + r.b.tcp_errors, 0u);
}

}  // namespace
}  // namespace utcp::sim
