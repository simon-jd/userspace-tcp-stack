#pragma once

#include <array>
#include <cstdint>
#include <functional>

namespace utcp {

// Nichols' three-candidate window filter (Linux v7.0 lib/win_minmax.c).
// Times advance modulo 2^32; a candidate remains live at age == window.
template <typename AtLeastAsGood>
class WindowExtremum {
 public:
  void reset(std::uint32_t now, std::uint32_t value) { samples_.fill({now, value}); }
  [[nodiscard]] std::uint32_t get() const { return samples_.front().value; }

  std::uint32_t update(std::uint32_t window, std::uint32_t now, std::uint32_t value) {
    auto& [best, middle, recent] = samples_;
    const Sample current{now, value};
    constexpr AtLeastAsGood better{};
    if (better(value, best.value) || now - recent.time > window) {
      reset(now, value);
      return get();
    }
    if (better(value, middle.value)) {
      middle = recent = current;
    } else if (better(value, recent.value)) {
      recent = current;
    }

    const auto age = now - best.time;
    if (age > window) {
      // The newest candidate is live, so at most two promotions are needed.
      do {
        best = middle;
        middle = recent;
        recent = current;
      } while (now - best.time > window);
    } else if (best.time == middle.time && age > window / 4) {
      middle = recent = current;
    } else if (middle.time == recent.time && age > window / 2) {
      recent = current;
    }
    return get();
  }

 private:
  struct Sample {
    std::uint32_t time, value;
  };
  std::array<Sample, 3> samples_{};
};

using WindowMax = WindowExtremum<std::greater_equal<std::uint32_t>>;
using WindowMin = WindowExtremum<std::less_equal<std::uint32_t>>;
}  // namespace utcp
