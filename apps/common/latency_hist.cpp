#include "common/latency_hist.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <limits>

namespace utcp::app {

LatencyHistogram::LatencyHistogram() : counts_(bucket_count, 0) {}

std::size_t LatencyHistogram::bucket_of(std::uint64_t v) noexcept {
  if (v < sub_count) {
    return static_cast<std::size_t>(v);
  }
  const auto e = static_cast<unsigned>(std::bit_width(v) - 1);  // >= sub_bits
  const unsigned shift = e - sub_bits;
  return (shift + 1) * sub_count + static_cast<std::size_t>((v >> shift) - sub_count);
}

std::uint64_t LatencyHistogram::bucket_low(std::size_t i) noexcept {
  if (i < sub_count) {
    return i;
  }
  const std::size_t shift = i / sub_count - 1;
  const std::uint64_t sub = i % sub_count;
  return (sub_count + sub) << shift;
}

std::uint64_t LatencyHistogram::bucket_high(std::size_t i) noexcept {
  if (i < sub_count) {
    return i;
  }
  const std::size_t shift = i / sub_count - 1;
  return bucket_low(i) + ((std::uint64_t{1} << shift) - 1);
}

void LatencyHistogram::record(Duration d) noexcept {
  record_ns(d.count() > 0 ? static_cast<std::uint64_t>(d.count()) : 0);
}

void LatencyHistogram::record_ns(std::uint64_t ns) noexcept {
  ++counts_[bucket_of(ns)];
  if (count_ == 0) {
    min_ = max_ = ns;
  } else {
    min_ = std::min(min_, ns);
    max_ = std::max(max_, ns);
  }
  ++count_;
  if (__builtin_add_overflow(sum_, ns, &sum_)) {
    sum_ = std::numeric_limits<std::uint64_t>::max();
  }
}

void LatencyHistogram::merge(const LatencyHistogram& other) noexcept {
  if (other.count_ == 0) {
    return;
  }
  for (std::size_t i = 0; i < bucket_count; ++i) {
    counts_[i] += other.counts_[i];
  }
  if (count_ == 0) {
    min_ = other.min_;
    max_ = other.max_;
  } else {
    min_ = std::min(min_, other.min_);
    max_ = std::max(max_, other.max_);
  }
  count_ += other.count_;
  if (__builtin_add_overflow(sum_, other.sum_, &sum_)) {
    sum_ = std::numeric_limits<std::uint64_t>::max();
  }
}

void LatencyHistogram::clear() noexcept {
  std::fill(counts_.begin(), counts_.end(), 0);
  count_ = sum_ = min_ = max_ = 0;
}

Duration LatencyHistogram::min() const noexcept {
  return Duration{static_cast<std::int64_t>(min_)};
}

Duration LatencyHistogram::max() const noexcept {
  return Duration{static_cast<std::int64_t>(max_)};
}

Duration LatencyHistogram::mean() const noexcept {
  return count_ == 0 ? Duration{0} : Duration{static_cast<std::int64_t>(sum_ / count_)};
}

Duration LatencyHistogram::percentile(double q) const noexcept {
  if (count_ == 0) {
    return Duration{0};
  }
  q = std::clamp(q, 0.0, 1.0);
  auto rank = static_cast<std::uint64_t>(std::ceil(q * static_cast<double>(count_)));
  rank = std::clamp<std::uint64_t>(rank, 1, count_);
  std::uint64_t seen = 0;
  for (std::size_t i = 0; i < bucket_count; ++i) {
    seen += counts_[i];
    if (seen >= rank) {
      const std::uint64_t v = std::clamp(bucket_high(i), min_, max_);
      return Duration{static_cast<std::int64_t>(v)};
    }
  }
  return max();
}

}  // namespace utcp::app
