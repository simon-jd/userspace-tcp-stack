// Scenario generation, key=value round trip, stream independence and the
// seeded start time (m1-sim acceptance test 5, generator part).
#include <gtest/gtest.h>

#include <cstdint>
#include <string>

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
  newer.replace(newer.find("gen_version=1"), 13, "gen_version=" + std::to_string(gen_version + 1));
  EXPECT_FALSE(parse_kv(newer).has_value());
  EXPECT_FALSE(parse_kv(good + "no_such_key=1\n").has_value());
  EXPECT_FALSE(parse_kv(good + "seed=1\n").has_value());  // duplicate
  EXPECT_FALSE(parse_kv("seed=abc\n").has_value());
  EXPECT_FALSE(parse_kv("garbage line\n").has_value());
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
    const Scenario s = generate_scenario(seed);
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

}  // namespace
}  // namespace utcp::sim
