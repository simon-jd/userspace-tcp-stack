#include "utcp/retry_model.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::retry_abort_time;

// The model values of DESIGN §3.9 and §4.8 (m1-tx acceptance test 4),
// computed by hand from Linux tcp_model_timeout().
TEST(RetryModel, LinuxModelValues) {
  EXPECT_EQ(retry_abort_time(15, 200ms, 120s), 924'600ms);  // t = 9: 1023 * 0.2 s + 6 * 120 s
  EXPECT_EQ(retry_abort_time(6, 1s, 120s), 127s);           // t = 6: 127 * 1 s
  EXPECT_EQ(retry_abort_time(7, 1s, 60s), 183s);            // t = 5: 63 s + 2 * 60 s
  EXPECT_EQ(retry_abort_time(15, 1s, 60s), 663s);           // t = 5: 63 s + 10 * 60 s
}

TEST(RetryModel, EdgeCases) {
  EXPECT_EQ(retry_abort_time(0, 1s, 60s), 1s);       // one expiry
  EXPECT_EQ(retry_abort_time(5, 1s, 60s), 63s);      // last doubling step
  EXPECT_EQ(retry_abort_time(3, 60s, 60s), 4 * 60s);  // t = 0: 1 * base + 3 * max
  EXPECT_EQ(retry_abort_time(2, 90s, 60s), 60s * 2 + 90s);  // base above max: t = 0
  // Saturates instead of overflowing.
  EXPECT_EQ(retry_abort_time(255, Duration{Duration::max().count() / 2}, Duration::max()),
            Duration::max());
  EXPECT_EQ(retry_abort_time(255, Duration{1}, Duration::max()), Duration::max());
}

}  // namespace
