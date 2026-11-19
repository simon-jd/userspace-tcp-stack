// Scenario generation, key=value round trip, stream independence and the
// seeded start time (m1-sim acceptance test 5, generator part).
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "utcp/random.hpp"
#include "utcp/sim/link.hpp"
#include "utcp/sim/scenario.hpp"

namespace utcp::sim {
namespace {

using namespace std::chrono_literals;

constexpr std::int64_t wrap_ns = (std::int64_t{1} << 32) * 1'000'000;  // 2^32 ms

TEST(SimScenario, RoundTripTenThousandSeeds) {
  for (std::uint64_t seed = 0; seed < 10'000; ++seed) {
    const Scenario s = generate_scenario(seed);
    const std::string text = to_kv(s);
    ASSERT_NE(text.find("gen_version=" + std::to_string(gen_version) + "\n"), std::string::npos);
    const auto back = parse_kv(text);
    ASSERT_TRUE(back.has_value()) << "seed " << seed << ": " << back.error();
    ASSERT_EQ(back->gen_version, gen_version);
    ASSERT_EQ(*back, s) << "seed " << seed;
    ASSERT_EQ(to_kv(*back), text);
  }
}

TEST(SimScenario, CongestionVersionsRoundTripAndDrawValidConfigurations) {
  bool cubic = false, gap = false, immediate = false, burst = false, bernoulli = false, clean = false;
  std::set<Pacing> pacing;
  std::set<RecoveryReduction> reduction;
  std::set<Hystart> hystart;
  for (unsigned seed = 0; seed < 512; ++seed) {
    const auto v4 = generate_scenario(seed, NodeKind::stack, {.version = 4});
    auto v5 = generate_scenario(seed, NodeKind::stack, {.version = 5});
    for (const Scenario* s : {&v4, static_cast<const Scenario*>(&v5)}) {
      const auto parsed = parse_kv(to_kv(*s));
      ASSERT_TRUE(parsed.has_value()) << parsed.error();
      ASSERT_EQ(*parsed, *s);
      for (const auto& n : s->node) {
        EXPECT_FALSE(n.rack_tlp && n.recovery_reduction == RecoveryReduction::rfc6675);
        pacing.insert(n.pacing);
        hystart.insert(n.hystart);
        reduction.insert(n.recovery_reduction);
      }
      for (const auto& l : s->link) {
        const auto& p = l.params;
        EXPECT_GE(p.rate_bps, 1'000'000u);
        EXPECT_LE(p.rate_bps, 100'000'000u);
        EXPECT_GE(p.delay, 500us);
        EXPECT_LE(p.delay, 100ms);
        const auto bdp = p.rate_bps * static_cast<std::uint64_t>(p.delay.count()) / 4'000'000'000;
        EXPECT_GE(std::uint64_t{p.queue_bytes} * 4 + 3, bdp);
        EXPECT_LE(p.queue_bytes, bdp * 4);
        EXPECT_GE(p.queue_bytes, 1500u);
        EXPECT_LE(p.loss_ppm, 50'000u);
        EXPECT_LE(std::uint64_t{p.burst.p_ppm} * 19, p.burst.r_ppm);
        EXPECT_FALSE(p.loss_ppm && p.burst.p_ppm);
        burst |= p.burst.p_ppm != 0;
        bernoulli |= p.loss_ppm != 0;
        clean |= !p.loss_ppm && !p.burst.p_ppm;
      }
      gap |= s->conn.front().write_interval > Duration::zero();
      immediate |= s->conn.front().write_interval == Duration::zero();
    }
    // Introducing CUBIC changes exactly the separate gen-5 CC draw.
    for (auto& n : v5.node) {
      cubic |= n.cc == CcAlgo::cubic;
      n.cc = CcAlgo::newreno;
    }
    v5.gen_version = 4;
    ASSERT_EQ(v4, v5);
  }
  EXPECT_TRUE(cubic && gap && immediate && burst && bernoulli && clean);
  EXPECT_EQ(pacing.size(), 3u);
  EXPECT_EQ(reduction.size(), 2u);
  EXPECT_EQ(hystart.size(), 2u);
}

TEST(SimScenario, FaultNamesRoundTripAndInvalidRackPairIsRejected) {
  auto s = generate_scenario(12, NodeKind::stack, {.version = 4});
  for (const auto name : {"prr_skip_force", "double_tlp", "ignore_pacing_gate"}) {
    auto fault = test_fault_from_string(name);
    ASSERT_TRUE(fault);
    s.node[0].test_fault = *fault;
    const auto text = to_kv(s);
    EXPECT_NE(text.find(std::string("node.0.test_fault=") + name), std::string::npos);
    EXPECT_EQ(parse_kv(text).value(), s);
  }
  s.node[0].rack_tlp = true;
  s.node[0].recovery_reduction = RecoveryReduction::rfc6675;
  EXPECT_FALSE(parse_kv(to_kv(s)).has_value());
}

TEST(SimScenario, RoundTripSyntheticAndPlanted) {
  Scenario s = generate_scenario(77, NodeKind::synthetic);
  s.plant = Plant::hang;
  s.plant_after_events = 12345;
  s.udp.push_back(UdpSpec{0, 7, 0, false, 3, 10, 20, 1ms, 2ms});
  s.ping.push_back(PingSpec{1, 9, 4, 100, 1s, 5ms});
  const auto back = parse_kv(to_kv(s));
  ASSERT_TRUE(back.has_value()) << back.error();
  EXPECT_EQ(*back, s);
}

TEST(SimScenario, GenerationIsDeterministic) {
  for (std::uint64_t seed : {0ull, 1ull, 99ull, 0xffff'ffff'ffff'ffffull}) {
    EXPECT_EQ(generate_scenario(seed), generate_scenario(seed));
  }
  EXPECT_NE(generate_scenario(1), generate_scenario(2));
}

TEST(SimScenario, ParseRejectsBadInput) {
  const std::string good = to_kv(generate_scenario(5));
  EXPECT_TRUE(parse_kv(good).has_value());
  EXPECT_TRUE(parse_kv("# comment\n\n" + good).has_value());
  // A newer generator's scenario.
  std::string newer = good;
  const std::string ours = "gen_version=" + std::to_string(gen_version);
  newer.replace(newer.find(ours), ours.size(), "gen_version=" + std::to_string(max_gen_version + 1));
  EXPECT_FALSE(parse_kv(newer).has_value());
  EXPECT_FALSE(parse_kv(good + "no_such_key=1\n").has_value());
  EXPECT_FALSE(parse_kv(good + "seed=1\n").has_value());  // duplicate
  EXPECT_FALSE(parse_kv("seed=abc\n").has_value());
  EXPECT_FALSE(parse_kv("garbage line\n").has_value());
}

TEST(SimScenario, GeneratorDefaultAndUnversionedFileAreIndependent) {
  EXPECT_EQ(generate_scenario(42), generate_scenario(42, NodeKind::stack, {.version = 5}));
  const auto old = generate_scenario(42, NodeKind::stack, {.version = 3});
  std::string text = to_kv(old);
  text.erase(0, text.find('\n') + 1);
  const auto parsed = parse_kv(text);
  ASSERT_TRUE(parsed.has_value()) << parsed.error();
  EXPECT_EQ(*parsed, old);
}

TEST(SimScenario, ParseFillsDefaults) {
  // A hand-written scenario: two nodes and the two paths.
  const std::string text =
      "gen_version=1\nseed=3\nnode.count=2\nlink.count=2\nlink.0.name=a>b\nlink.1.name=b>a\n"
      "path.count=2\npath.0.from=0\npath.0.to=1\npath.0.links=0\npath.1.from=1\npath.1.to=0\n"
      "path.1.links=1\n";
  const auto s = parse_kv(text);
  ASSERT_TRUE(s.has_value()) << s.error();
  EXPECT_EQ(s->seed, 3u);
  EXPECT_EQ(s->node.size(), 2u);
  EXPECT_EQ(s->link[0].params.mtu, 1500);
  EXPECT_EQ(s->start, Time{1'000'000'000});
}

TEST(SimScenario, NewLabelDoesNotShiftOtherStreams) {
  GenOptions probe;
  probe.probe_extra_label = true;
  for (std::uint64_t seed = 0; seed < 2000; ++seed) {
    ASSERT_EQ(generate_scenario(seed, NodeKind::stack, probe), generate_scenario(seed)) << seed;
  }
  // Rng::derive: a stream is a function of (master, label) only.
  const Seed m = Seed::from_u64(9);
  Rng a1 = Rng::derive(m, "link/a>b/loss");
  Rng other = Rng::derive(m, "link/a>b/new-decision");
  static_cast<void>(other.next());
  Rng a2 = Rng::derive(m, "link/a>b/loss");
  for (int i = 0; i < 100; ++i) {
    ASSERT_EQ(a1.next(), a2.next());
  }
}

// A link decision added to a segment (duplication, corruption, spoofing)
// draws from its own stream, so the loss pattern stays the same.
TEST(SimScenario, LinkDecisionsUseOwnStreams) {
  class Seq final : public LinkSink {
  public:
    void deliver(Time, std::span<const std::byte>, const DeliveryInfo& info) override {
      if (!info.duplicate && !info.replay) {
        got = true;
      }
    }
    void reply(Time, std::span<const std::byte>) override {}
    bool got = false;
  };
  const Seed m = Seed::from_u64(11);
  LinkParams base;
  base.loss_ppm = 50'000;
  LinkParams more = base;
  more.dup_ppm = 100'000;
  more.bitflip_ppm = 1000;
  more.jitter = 1ms;
  Link l1(base, m, "a>b");
  Link l2(more, m, "a>b");
  const std::vector<std::byte> d(60);
  Time t{1'000'000'000};
  for (int i = 0; i < 100'000; ++i) {
    Seq s1, s2;
    l1.send(t, d, s1);
    l2.send(t, d, s2);
    ASSERT_EQ(s1.got, s2.got) << i;
    t += 10us;
  }
}

TEST(SimScenario, StartTimeIsSeededOffset) {
  std::uint64_t near_wrap = 0;
  for (std::uint64_t seed = 0; seed < 10'000; ++seed) {
    const Scenario s = generate_scenario(seed);
    ASSERT_GE(s.start, Time{1'000'000'000}) << seed;
    if (s.start.ns >= wrap_ns - 600'000'000'000 && s.start.ns < wrap_ns) {
      ++near_wrap;
    }
  }
  // About 10 % of seeds start within 10 minutes before 2^32 ms.
  EXPECT_GE(near_wrap, 800u);
  EXPECT_LE(near_wrap, 1200u);
  EXPECT_NE(generate_scenario(1).start, generate_scenario(2).start);
}

TEST(SimScenario, GeneratedRangesMatchDesign) {
  std::uint64_t router = 0, garbage = 0, renege = 0, isn = 0;
  for (std::uint64_t seed = 0; seed < 5000; ++seed) {
    const Scenario s = generate_scenario(seed, NodeKind::stack, {.version = 3});
    ASSERT_EQ(s.node.size(), 2u);
    ASSERT_GE(s.conn.size(), 1u);
    ASSERT_LE(s.conn.size(), 8u);
    router += s.link.size() == 4 ? 1u : 0u;
    garbage += s.has_garbage() ? 1u : 0u;
    for (const NodeSpec& n : s.node) {
      renege += n.renege_ppm > 0 ? 1u : 0u;
      isn += n.test_isn ? 1u : 0u;
    }
    for (const LinkSpec& l : s.link) {
      ASSERT_GE(l.params.mtu, 576);
      ASSERT_LE(l.params.mtu, 1500);
      ASSERT_LE(l.params.loss_ppm, 300'000u);
      ASSERT_LE(l.params.dup_ppm, 50'000u);
      ASSERT_LE(l.params.bitflip_ppm, 20'000u);
      ASSERT_LE(l.params.rate_bps, 10'000'000'000u);
    }
    for (const ConnSpec& c : s.conn) {
      ASSERT_LE(c.bytes_c2s, 4u << 20);
      ASSERT_LE(c.bytes_s2c, 4u << 20);
      ASSERT_GE(c.write_max_c, 1u);
      ASSERT_LE(c.write_max_c, 65536u);
    }
  }
  EXPECT_GT(router, 1000u);   // MTU < 1500 in 30 %
  EXPECT_GT(garbage, 100u);   // 5 %
  EXPECT_GT(renege, 250u);    // 5 % per node
  EXPECT_GT(isn, 700u);       // 10 % per node
}

bool listener_mode(const ConnSpec& c) {
  return c.mode == CloseMode::close || c.mode == CloseMode::half_close ||
         c.mode == CloseMode::abort;
}

TEST(SimScenario, SomeSeedsShareAListenerBeyondItsBacklog) {
  // Backlog limits (§7.2): several clients start within 10 ms against one
  // listener whose backlog is smaller than their number.
  std::uint64_t shared = 0;
  for (std::uint64_t seed = 0; seed < 5000; ++seed) {
    const Scenario s = generate_scenario(seed, NodeKind::stack, {.version = 3});
    std::map<std::pair<std::uint32_t, std::uint16_t>, std::vector<const ConnSpec*>> listeners;
    for (const ConnSpec& c : s.conn) {
      if (listener_mode(c)) {
        listeners[{1 - c.client, c.server_port}].push_back(&c);
      }
    }
    for (const auto& [key, group] : listeners) {
      if (group.size() < 2) {
        continue;
      }
      ++shared;
      std::set<std::uint16_t> ports;
      Duration lo = group[0]->start, hi = group[0]->start;
      for (const ConnSpec* c : group) {
        ASSERT_NE(c->client_port, 0u) << seed;
        ports.insert(c->client_port);
        ASSERT_EQ(c->backlog, group[0]->backlog) << seed;
        lo = std::min(lo, c->start);
        hi = std::max(hi, c->start);
      }
      ASSERT_EQ(ports.size(), group.size()) << seed;
      ASSERT_GE(group[0]->backlog, 1u) << seed;
      ASSERT_LT(group[0]->backlog, group.size()) << seed;
      ASSERT_LT(hi - lo, 10ms) << seed;
    }
  }
  // 10 % of seeds, of which about 83 % have two or more listener-mode
  // connections.
  EXPECT_GT(shared, 300u);
  EXPECT_LT(shared, 550u);
}

TEST(SimScenario, ParseRejectsAmbiguousSharedListener) {
  Scenario s = two_node_scenario(1, LinkParams{}, LinkParams{});
  s.conn.resize(2);
  s.conn[0].server_port = s.conn[1].server_port = 5000;
  s.conn[0].client_port = 41000;
  s.conn[1].client_port = 41001;
  ASSERT_TRUE(parse_kv(to_kv(s)).has_value());
  Scenario bad = s;
  bad.conn[1].client_port = 0;  // the server cannot tell the two apart
  EXPECT_FALSE(parse_kv(to_kv(bad)).has_value());
  bad = s;
  bad.conn[1].client_port = 41000;
  EXPECT_FALSE(parse_kv(to_kv(bad)).has_value());
  bad = s;
  bad.conn[1].backlog = 2;
  EXPECT_FALSE(parse_kv(to_kv(bad)).has_value());
  bad = s;
  bad.conn[1].mode = CloseMode::refused;  // would not be refused
  EXPECT_FALSE(parse_kv(to_kv(bad)).has_value());
  bad = s;
  bad.conn[1].client = 1;  // the other node's port 5000: no conflict
  EXPECT_TRUE(parse_kv(to_kv(bad)).has_value());
}

}  // namespace
}  // namespace utcp::sim
