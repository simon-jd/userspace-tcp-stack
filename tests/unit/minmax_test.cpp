#include "core/tcp/minmax.hpp"

#include <gtest/gtest.h>

#include <cstdint>

namespace utcp {
namespace {
TEST(Minmax, QuarterAndHalfWindowCandidatesOutliveThePeak) {
  WindowMax maximum;
  WindowMin minimum;
  maximum.reset(0, 100);
  minimum.reset(0, 20);
  for (std::uint32_t round = 1; round <= 17; ++round) {
    const auto age = round <= 10 ? 0u : round <= 13 ? 3u : round <= 16 ? 6u : 11u;
    EXPECT_EQ(maximum.update(10, round, 100 - round), 100 - age) << round;
    EXPECT_EQ(minimum.update(10, round, 20 + round), 20 + age) << round;
  }
}

TEST(Minmax, TiesRefreshAndAJumpDiscardsEveryOldCandidate) {
  WindowMax maximum;
  maximum.reset(0xffff'fff8u, 50);
  EXPECT_EQ(maximum.update(10, 0xffff'fffcu, 50), 50u);
  EXPECT_EQ(maximum.update(10, 6, 20), 50u);
  EXPECT_EQ(maximum.update(10, 7, 25), 25u);
  EXPECT_EQ(maximum.update(10, 99, 1), 1u);
}
}  // namespace
}  // namespace utcp
