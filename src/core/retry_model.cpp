#include "utcp/retry_model.hpp"

#include <bit>
#include <cstdint>

#include "utcp/check.hpp"

namespace utcp {

// As Linux tcp_model_timeout() (net/ipv4/tcp_timer.c), in nanoseconds
// instead of jiffies.
Duration retry_abort_time(std::uint8_t retries, Duration rto_base, Duration rto_max) noexcept {
  UTCP_CHECK(rto_base.count() > 0 && rto_max.count() > 0);
  const auto base = static_cast<std::uint64_t>(rto_base.count());
  const auto max = static_cast<std::uint64_t>(rto_max.count());
  const std::uint64_t ratio = max / base;
  // ilog2(ratio); a base above the maximum doubles nothing (Linux would take
  // ilog2(0), which is undefined).
  const unsigned thresh = ratio == 0 ? 0u : static_cast<unsigned>(std::bit_width(ratio) - 1);
  const unsigned doublings = retries <= thresh ? retries : thresh;
  // (2 << doublings) - 1 fits: doublings <= 62 because ratio < 2^63.
  const std::uint64_t factor = (std::uint64_t{2} << doublings) - 1;
  std::uint64_t total = 0;
  bool overflow = __builtin_mul_overflow(factor, base, &total);
  if (retries > thresh) {
    std::uint64_t linear = 0;
    overflow = overflow || __builtin_mul_overflow(std::uint64_t{retries - thresh}, max, &linear) ||
               __builtin_add_overflow(total, linear, &total);
  }
  const auto limit = static_cast<std::uint64_t>(Duration::max().count());
  if (overflow || total > limit) {
    return Duration::max();
  }
  return Duration{static_cast<Duration::rep>(total)};
}

}  // namespace utcp
