// Time and durations (DESIGN §3.1).
//
// The core has no clock: every entry point takes the current Time from the
// host. The backend passes CLOCK_MONOTONIC nanoseconds, the simulator its
// virtual time. Protocol clocks are derived from Time (TCP timestamps tick in
// milliseconds, the RFC 6528 ISN clock in 4 microseconds).
#pragma once

#include <chrono>
#include <compare>
#include <cstdint>
#include <limits>

namespace utcp {

// Signed 64-bit nanoseconds.
using Duration = std::chrono::nanoseconds;

// A point in time: nanoseconds since an epoch chosen by the host.
struct Time {
  std::int64_t ns = 0;

  // Later than every other time; "no deadline".
  [[nodiscard]] static constexpr Time never() noexcept {
    return Time{std::numeric_limits<std::int64_t>::max()};
  }
  [[nodiscard]] constexpr bool is_never() const noexcept { return ns == never().ns; }

  constexpr auto operator<=>(const Time&) const = default;

  // Saturating: never() + d == never() for every d, a sum past the largest
  // value is never(), a sum below the smallest value is the smallest value.
  friend constexpr Time operator+(Time t, Duration d) noexcept {
    if (t.is_never()) {
      return never();
    }
    std::int64_t r = 0;
    if (__builtin_add_overflow(t.ns, d.count(), &r)) {
      return d.count() > 0 ? never() : Time{std::numeric_limits<std::int64_t>::min()};
    }
    return Time{r};
  }
  friend constexpr Time operator+(Duration d, Time t) noexcept { return t + d; }

  // Saturating like operator+; never() - d == never().
  friend constexpr Time operator-(Time t, Duration d) noexcept {
    if (t.is_never()) {
      return never();
    }
    std::int64_t r = 0;
    if (__builtin_sub_overflow(t.ns, d.count(), &r)) {
      return d.count() < 0 ? never() : Time{std::numeric_limits<std::int64_t>::min()};
    }
    return Time{r};
  }

  // a - b, saturating at the Duration range.
  friend constexpr Duration operator-(Time a, Time b) noexcept {
    std::int64_t r = 0;
    if (__builtin_sub_overflow(a.ns, b.ns, &r)) {
      return Duration{a.ns > b.ns ? std::numeric_limits<std::int64_t>::max()
                                  : std::numeric_limits<std::int64_t>::min()};
    }
    return Duration{r};
  }

  constexpr Time& operator+=(Duration d) noexcept { return *this = *this + d; }
  constexpr Time& operator-=(Duration d) noexcept { return *this = *this - d; }
};

}  // namespace utcp
