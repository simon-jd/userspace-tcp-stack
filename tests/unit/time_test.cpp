#include "utcp/time.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <limits>

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::Time;

constexpr std::int64_t max64 = std::numeric_limits<std::int64_t>::max();
constexpr std::int64_t min64 = std::numeric_limits<std::int64_t>::min();

TEST(Time, NeverPlusAnythingIsNever) {
  EXPECT_EQ(Time::never() + 1s, Time::never());
  EXPECT_EQ(Time::never() + Duration{1}, Time::never());
  EXPECT_EQ(Time::never() + Duration{-1}, Time::never());
  EXPECT_EQ(Time::never() + -1000s, Time::never());
  EXPECT_EQ(1s + Time::never(), Time::never());
  EXPECT_EQ(Time::never() - 1s, Time::never());
  EXPECT_TRUE(Time::never().is_never());
  EXPECT_FALSE(Time{max64 - 1}.is_never());
}

TEST(Time, AdditionSaturates) {
  EXPECT_EQ(Time{max64 - 10} + Duration{9}, Time{max64 - 1});
  EXPECT_EQ(Time{max64 - 10} + Duration{10}, Time::never());
  EXPECT_EQ(Time{max64 - 10} + Duration{11}, Time::never());
  EXPECT_EQ(Time{max64 - 10} + Duration{max64}, Time::never());
  EXPECT_EQ(Time{min64 + 5} + Duration{-5}, Time{min64});
  EXPECT_EQ(Time{min64 + 5} + Duration{-6}, Time{min64});
  EXPECT_EQ(Time{min64 + 5} - Duration{6}, Time{min64});
  EXPECT_EQ(Time{max64 - 3} - Duration{-5}, Time::never());
}

TEST(Time, AdditionAndSubtraction) {
  const Time t{1'000'000'000};
  EXPECT_EQ(t + 1ms, Time{1'001'000'000});
  EXPECT_EQ(t + -1ms, Time{999'000'000});
  EXPECT_EQ(t - 1us, Time{999'999'000});
  EXPECT_EQ((t + 250ms) - 250ms, t);
  Time u = t;
  u += 2s;
  EXPECT_EQ(u, Time{3'000'000'000});
  u -= 3s;
  EXPECT_EQ(u, Time{0});
}

TEST(Time, Difference) {
  EXPECT_EQ(Time{5'000} - Time{2'000}, 3us);
  EXPECT_EQ(Time{2'000} - Time{5'000}, -3us);
  EXPECT_EQ(Time{7} - Time{7}, Duration::zero());
  EXPECT_EQ(Time::never() - Time{0}, Duration{max64});
  // Saturates instead of overflowing.
  EXPECT_EQ(Time::never() - Time{-1}, Duration{max64});
  EXPECT_EQ(Time{min64} - Time{1}, Duration{min64});
}

TEST(Time, Comparison) {
  const Time a{10}, b{20};
  EXPECT_LT(a, b);
  EXPECT_LE(a, b);
  EXPECT_LE(a, a);
  EXPECT_GT(b, a);
  EXPECT_GE(b, b);
  EXPECT_EQ(a, Time{10});
  EXPECT_NE(a, b);
  EXPECT_LT(b, Time::never());
  EXPECT_EQ(Time{}, Time{0});
  EXPECT_EQ(std::min(a, b), a);
}

TEST(Time, Constexpr) {
  static_assert(Time::never() + 1s == Time::never());
  static_assert(Time{1} + 1ns == Time{2});
  static_assert(Time{3} - Time{1} == Duration{2});
  static_assert(Time{1} < Time{2});
  SUCCEED();
}

}  // namespace
