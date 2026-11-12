#include "utcp/random.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <set>
#include <vector>

namespace {

using utcp::Rng;
using utcp::Seed;

// next() of the reference xoshiro256** (prng.di.unimi.it/xoshiro256starstar.c),
// compiled from the reference source, for two fixed states.
TEST(Rng, MatchesReferenceImplementation) {
  struct Case {
    std::array<std::uint64_t, 4> state;
    std::array<std::uint64_t, 6> outputs;
  };
  const Case cases[] = {
      {{1, 2, 3, 4},
       {0x0000000000002d00ULL, 0x0000000000000000ULL, 0x000000005a007080ULL, 0x10e0000000009d80ULL,
        0x10e0b61ce1009d80ULL, 0x0870021ce143ad00ULL}},
      {{0x0123456789abcdefULL, 0xfedcba9876543210ULL, 0x0f1e2d3c4b5a6978ULL, 0x8796a5b4c3d2e1f0ULL},
       {0x6666666666666c65ULL, 0xd90633608dbae0aaULL, 0x3198d392d660bce0ULL, 0x5a49a1c67304ca22ULL,
        0x5f78a398f0b24a01ULL, 0x5432b677801d1eaaULL}},
  };
  for (const Case& c : cases) {
    Rng r = Rng::from_state(c.state);
    for (const std::uint64_t want : c.outputs) {
      EXPECT_EQ(r.next(), want);
    }
  }
}

TEST(Rng, SeedFromU64IsSplitmix64) {
  // splitmix64 outputs for seed 0 (Vigna's splitmix64.c).
  const Seed s = Seed::from_u64(0);
  EXPECT_EQ(s.w[0], 0xe220a8397b1dcdafULL);
  EXPECT_EQ(s.w[1], 0x6e789e6aa1b965f4ULL);
  EXPECT_EQ(s.w[2], 0x06c45d188009454fULL);
  EXPECT_EQ(s.w[3], 0xf88bb8a8724c81ecULL);
  EXPECT_NE(Seed::from_u64(1), s);
}

TEST(Rng, SameSeedSameStream) {
  const Seed s = Seed::from_u64(42);
  Rng a(s), b(s);
  for (int i = 0; i < 1000; ++i) {
    ASSERT_EQ(a.next(), b.next());
  }
  Rng c(Seed::from_u64(43));
  Rng d(s);
  int equal = 0;
  for (int i = 0; i < 1000; ++i) {
    equal += c.next() == d.next() ? 1 : 0;
  }
  EXPECT_EQ(equal, 0);
}

TEST(Rng, ZeroSeedIsUsable) {
  Rng r(Seed{});
  std::set<std::uint64_t> seen;
  for (int i = 0; i < 100; ++i) {
    seen.insert(r.next());
  }
  EXPECT_EQ(seen.size(), 100u);
}

TEST(Rng, BelowStaysInRange) {
  Rng r(Seed::from_u64(1));
  for (const std::uint32_t n : {1u, 2u, 3u, 7u, 1'000'000u, 0x8000'0001u, 0xffff'ffffu}) {
    for (int i = 0; i < 100'000; ++i) {
      ASSERT_LT(r.below(n), n) << n;
    }
  }
  for (int i = 0; i < 1000; ++i) {
    ASSERT_EQ(r.below(1), 0u);
  }
}

TEST(Rng, BelowIsUnbiasedForLargeN) {
  // With n = 2^31 + 1 a plain "x mod n" of 32-bit draws almost never returns a
  // value >= 2^31; Lemire's method returns one about half the time.
  Rng r(Seed::from_u64(2));
  const std::uint32_t n = 0x8000'0001u;
  int high = 0;
  const int draws = 200'000;
  for (int i = 0; i < draws; ++i) {
    high += r.below(n) >= 0x8000'0000u ? 1 : 0;
  }
  EXPECT_NEAR(static_cast<double>(high) / draws, 0.5, 0.01);
}

TEST(Rng, BelowIsUniformForSmallN) {
  Rng r(Seed::from_u64(3));
  std::array<int, 3> counts{};
  const int draws = 300'000;
  for (int i = 0; i < draws; ++i) {
    ++counts[r.below(3)];
  }
  for (const int c : counts) {
    EXPECT_NEAR(c, draws / 3, draws / 100);
  }
}

TEST(Rng, Below64StaysInRange) {
  Rng r(Seed::from_u64(4));
  for (const std::uint64_t n :
       {std::uint64_t{1}, std::uint64_t{2}, std::uint64_t{3}, std::uint64_t{10'000'000'000},
        (std::uint64_t{1} << 63) + 1, ~std::uint64_t{0}}) {
    for (int i = 0; i < 10'000; ++i) {
      ASSERT_LT(r.below64(n), n) << n;
    }
  }
}

TEST(Rng, ChancePpm) {
  Rng r(Seed::from_u64(5));
  int hits = 0;
  for (int i = 0; i < 100'000; ++i) {
    ASSERT_FALSE(r.chance_ppm(0));
    ASSERT_TRUE(r.chance_ppm(1'000'000));
    hits += r.chance_ppm(10'000) ? 1 : 0;  // 1 %
  }
  EXPECT_NEAR(hits, 1000, 150);
}

TEST(Rng, DeriveIsReproducibleAndLabelled) {
  const Seed master = Seed::from_u64(99);
  Rng a1 = Rng::derive(master, "a");
  Rng a2 = Rng::derive(master, "a");
  Rng b = Rng::derive(master, "b");
  Rng m(master);
  for (int i = 0; i < 100; ++i) {
    const std::uint64_t x = a1.next();
    ASSERT_EQ(x, a2.next());
    ASSERT_NE(x, b.next());
    ASSERT_NE(x, m.next());
  }
  EXPECT_EQ(Rng::derive_seed(master, "link/a>b/loss"), Rng::derive_seed(master, "link/a>b/loss"));
  EXPECT_NE(Rng::derive_seed(master, "link/a>b/loss"), Rng::derive_seed(master, "link/b>a/loss"));
  EXPECT_NE(Rng::derive_seed(master, ""), Rng::derive_seed(master, std::string_view("\0", 1)));
  EXPECT_NE(Rng::derive_seed(master, "x"), Rng::derive_seed(Seed::from_u64(98), "x"));
}

TEST(Rng, DeriveUsesAllSeedWords) {
  Seed base = Seed::from_u64(7);
  const Seed derived = Rng::derive_seed(base, "label");
  for (std::size_t i = 0; i < 4; ++i) {
    Seed changed = base;
    changed.w[i] ^= 1;
    EXPECT_NE(Rng::derive_seed(changed, "label"), derived) << i;
  }
}

// Pinned values: derived streams feed the simulator's scenarios and recorded
// corpus entries, so their values must not change silently.
TEST(Rng, DerivedStreamIsPinned) {
  Rng r = Rng::derive(Seed::from_u64(2026), "node/a/stack");
  const std::array<std::uint64_t, 3> got{r.next(), r.next(), r.next()};
  const std::array<std::uint64_t, 3> pinned{PINNED_0, PINNED_1, PINNED_2};
  EXPECT_EQ(got, pinned);
}

}  // namespace
