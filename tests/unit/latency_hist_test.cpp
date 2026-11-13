#include "common/latency_hist.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <random>
#include <vector>

namespace utcp::app {
namespace {

using H = LatencyHistogram;

TEST(LatencyHist, BucketsAreContiguousAndCoverEveryValue) {
  EXPECT_EQ(H::bucket_low(0), 0u);
  for (std::size_t i = 1; i < H::bucket_count; ++i) {
    ASSERT_EQ(H::bucket_low(i), H::bucket_high(i - 1) + 1) << i;
    ASSERT_GE(H::bucket_high(i), H::bucket_low(i));
  }
  EXPECT_EQ(H::bucket_high(H::bucket_count - 1), std::numeric_limits<std::uint64_t>::max());
  // Exact below 2^sub_bits.
  for (std::uint64_t v = 0; v < H::sub_count; ++v) {
    EXPECT_EQ(H::bucket_low(H::bucket_of(v)), v);
    EXPECT_EQ(H::bucket_high(H::bucket_of(v)), v);
  }
  // Every value lies in its bucket and the bucket width is at most v >> sub_bits.
  std::mt19937_64 rng(7);
  for (int i = 0; i < 100'000; ++i) {
    const std::uint64_t v = rng() >> (rng() % 64);
    const std::size_t b = H::bucket_of(v);
    ASSERT_LT(b, H::bucket_count);
    ASSERT_LE(H::bucket_low(b), v);
    ASSERT_GE(H::bucket_high(b), v);
    ASSERT_LE(H::bucket_high(b) - H::bucket_low(b), v >> H::sub_bits);
  }
  for (unsigned e = 0; e < 64; ++e) {
    const std::uint64_t v = std::uint64_t{1} << e;
    EXPECT_EQ(H::bucket_low(H::bucket_of(v)), v) << e;
    EXPECT_EQ(H::bucket_high(H::bucket_of(v - 1)), v - 1) << e;
  }
}

TEST(LatencyHist, EmptyHistogram) {
  H h;
  EXPECT_EQ(h.count(), 0u);
  EXPECT_EQ(h.percentile(0.5), Duration{0});
  EXPECT_EQ(h.min(), Duration{0});
  EXPECT_EQ(h.max(), Duration{0});
  EXPECT_EQ(h.mean(), Duration{0});
}

// The reported quantile is the sample of rank ceil(q n) in sorted order, to
// within its bucket.
void check_against_sorted(const std::vector<std::uint64_t>& values) {
  H h;
  for (const std::uint64_t v : values) {
    h.record_ns(v);
  }
  std::vector<std::uint64_t> sorted = values;
  std::ranges::sort(sorted);
  ASSERT_EQ(h.count(), sorted.size());
  EXPECT_EQ(static_cast<std::uint64_t>(h.min().count()), sorted.front());
  EXPECT_EQ(static_cast<std::uint64_t>(h.max().count()), sorted.back());
  for (const double q : {0.0, 0.001, 0.1, 0.5, 0.9, 0.99, 0.999, 0.9999, 1.0}) {
    auto rank = static_cast<std::size_t>(std::ceil(q * static_cast<double>(sorted.size())));
    rank = std::clamp<std::size_t>(rank, 1, sorted.size());
    const std::uint64_t ref = sorted[rank - 1];
    const auto got = static_cast<std::uint64_t>(h.percentile(q).count());
    EXPECT_EQ(H::bucket_of(got), H::bucket_of(ref)) << "q " << q << " ref " << ref << " got " << got;
    EXPECT_GE(got, ref) << q;
    EXPECT_LE(got - ref, ref >> H::sub_bits) << q;
    EXPECT_LE(got, sorted.back());
  }
}

TEST(LatencyHist, PercentilesMatchASortedReference) {
  std::mt19937_64 rng(42);
  // Log-uniform latencies from 1 us to 1 s.
  std::vector<std::uint64_t> logu;
  std::uniform_real_distribution<double> u(3.0, 9.0);
  for (int i = 0; i < 200'000; ++i) {
    logu.push_back(static_cast<std::uint64_t>(std::pow(10.0, u(rng))));
  }
  check_against_sorted(logu);

  // Small exact values, many ties.
  std::vector<std::uint64_t> small;
  for (int i = 0; i < 10'000; ++i) {
    small.push_back(rng() % 100);
  }
  check_against_sorted(small);

  // One value, two values, a long tail.
  check_against_sorted({12345});
  check_against_sorted({5, 5'000'000});
  std::vector<std::uint64_t> tail(1000, 20'000);
  tail.push_back(900'000'000);
  check_against_sorted(tail);
}

TEST(LatencyHist, MergeEqualsRecordingEverything) {
  std::mt19937_64 rng(3);
  H a, b, all;
  for (int i = 0; i < 5000; ++i) {
    const std::uint64_t v = rng() % 10'000'000;
    (i % 2 ? a : b).record_ns(v);
    all.record_ns(v);
  }
  a.merge(b);
  EXPECT_EQ(a.count(), all.count());
  EXPECT_EQ(a.min(), all.min());
  EXPECT_EQ(a.max(), all.max());
  EXPECT_EQ(a.mean(), all.mean());
  for (const double q : {0.5, 0.99, 0.999}) {
    EXPECT_EQ(a.percentile(q), all.percentile(q));
  }
  a.clear();
  EXPECT_EQ(a.count(), 0u);
  EXPECT_EQ(a.percentile(0.5), Duration{0});
}

TEST(LatencyHist, NegativeDurationsCountAsZeroAndMeanIsExact) {
  H h;
  h.record(Duration{-5});
  h.record(Duration{10});
  h.record(Duration{20});
  EXPECT_EQ(h.count(), 3u);
  EXPECT_EQ(h.min(), Duration{0});
  EXPECT_EQ(h.mean(), Duration{10});
  EXPECT_EQ(h.percentile(1.0), Duration{20});
}

}  // namespace
}  // namespace utcp::app
