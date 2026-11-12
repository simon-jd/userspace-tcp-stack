// 32-bit TCP sequence numbers and their conversion to 64-bit stream offsets
// (DESIGN §3.2).
//
// Wire-facing TCB fields are Seq32. Buffers address bytes by 64-bit stream
// offset; offset 0 is the byte at ISN + 1. SYN and FIN occupy sequence space
// but have no offset; the engine converts between the two at one place with
// unwrap() and seq_at().
#pragma once

#include <cstdint>

namespace utcp {

// Modular sequence arithmetic, RFC 9293 §3.4. There is deliberately no
// operator<: sequence numbers have no total order, so a Seq32 cannot key an
// ordered container. Compare with before()/after().
class Seq32 {
public:
  constexpr Seq32() noexcept = default;
  constexpr explicit Seq32(std::uint32_t v) noexcept : v_(v) {}

  [[nodiscard]] constexpr std::uint32_t raw() const noexcept { return v_; }

  constexpr Seq32 operator+(std::uint32_t d) const noexcept { return Seq32(v_ + d); }
  constexpr Seq32 operator-(std::uint32_t d) const noexcept { return Seq32(v_ - d); }
  constexpr Seq32& operator+=(std::uint32_t d) noexcept {
    v_ += d;
    return *this;
  }
  constexpr Seq32& operator-=(std::uint32_t d) noexcept {
    v_ -= d;
    return *this;
  }
  // Distance from o to *this, modulo 2^32.
  constexpr std::uint32_t operator-(Seq32 o) const noexcept { return v_ - o.v_; }

  constexpr bool operator==(const Seq32&) const noexcept = default;

  // a precedes b: 0 < b - a < 2^31 as a signed 32-bit difference. At a
  // distance of exactly 2^31 both before(a, b) and before(b, a) hold; RFC 9293
  // never compares numbers that far apart.
  friend constexpr bool before(Seq32 a, Seq32 b) noexcept {
    return static_cast<std::int32_t>(a.v_ - b.v_) < 0;
  }
  friend constexpr bool after(Seq32 a, Seq32 b) noexcept { return before(b, a); }
  friend constexpr bool before_eq(Seq32 a, Seq32 b) noexcept { return !after(a, b); }
  friend constexpr bool after_eq(Seq32 a, Seq32 b) noexcept { return !before(a, b); }

private:
  std::uint32_t v_ = 0;
};

// Sequence number of stream offset `off`, where `base` is the sequence number
// of offset 0 (ISN + 1).
[[nodiscard]] constexpr Seq32 seq_at(Seq32 base, std::uint64_t off) noexcept {
  return base + static_cast<std::uint32_t>(off);
}

// Stream offset of `s`, where `base` is the sequence number of offset 0. Of
// the offsets congruent to s - base modulo 2^32, returns the one in
// [ref - 2^31, ref + 2^31), with `ref` a nearby known offset (RCV.NXT or
// SND.UNA as an offset). The result is negative for sequence numbers before
// `base` (a SYN at ISN gives -1).
[[nodiscard]] constexpr std::int64_t unwrap(Seq32 s, Seq32 base, std::uint64_t ref) noexcept {
  const auto delta = static_cast<std::int32_t>(s - seq_at(base, ref));
  return static_cast<std::int64_t>(ref) + delta;
}

}  // namespace utcp
