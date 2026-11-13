// Log-linear latency histogram (DESIGN §9: utcp-echo's p50/p99/p999).
//
// Values are non-negative nanoseconds. Values below 2^sub_bits are counted
// exactly; above, each power-of-two range [2^e, 2^(e+1)) is split into
// 2^sub_bits equal buckets, so a value is known to within a relative error of
// 2^-sub_bits (0.8 %). Recording is O(1) and allocation-free after
// construction.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "utcp/time.hpp"

namespace utcp::app {

class LatencyHistogram {
public:
  static constexpr unsigned sub_bits = 7;
  static constexpr std::size_t sub_count = std::size_t{1} << sub_bits;
  static constexpr std::size_t bucket_count = (65 - sub_bits) * sub_count;

  LatencyHistogram();

  // A negative duration counts as 0.
  void record(Duration d) noexcept;
  void record_ns(std::uint64_t ns) noexcept;
  void merge(const LatencyHistogram& other) noexcept;
  void clear() noexcept;

  [[nodiscard]] std::uint64_t count() const noexcept { return count_; }
  [[nodiscard]] Duration min() const noexcept;  // 0 when empty
  [[nodiscard]] Duration max() const noexcept;  // 0 when empty
  [[nodiscard]] Duration mean() const noexcept;  // rounded down; 0 when empty
  // The q-quantile for q in [0, 1]: the sample of rank max(1, ceil(q *
  // count())) in sorted order, reported as the highest value of its bucket,
  // clamped to [min(), max()]. 0 when empty.
  [[nodiscard]] Duration percentile(double q) const noexcept;

  // Bucket arithmetic (exposed for tests).
  [[nodiscard]] static std::size_t bucket_of(std::uint64_t v) noexcept;
  [[nodiscard]] static std::uint64_t bucket_low(std::size_t i) noexcept;
  [[nodiscard]] static std::uint64_t bucket_high(std::size_t i) noexcept;

private:
  std::vector<std::uint64_t> counts_;
  std::uint64_t count_ = 0;
  std::uint64_t sum_ = 0;  // saturating
  std::uint64_t min_ = 0, max_ = 0;
};

}  // namespace utcp::app
