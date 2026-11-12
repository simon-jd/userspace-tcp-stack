// SipHash-c-d with incremental input (Aumasson and Bernstein, "SipHash: a fast
// short-input PRF"; reference implementation github.com/veorq/SipHash).
//
// The message is read as little-endian 64-bit words, as the reference does.
// The update_u16/u32/u64 helpers append integers most significant byte first
// (network order), so hashing a 4-tuple field by field gives the same value on
// every host. SipHash-2-4 (utcp/random.hpp) is the PRF for key derivation,
// ISNs and timestamp offsets; SipHash-1-3 keys the connection and TIME_WAIT
// hash tables (DESIGN §4.3).
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "utcp/random.hpp"

namespace utcp {

template <int CRounds, int DRounds>
class SipHasher {
public:
  explicit constexpr SipHasher(const SipKey& key) noexcept
      : v0_(0x736f6d6570736575ULL ^ key.k0),
        v1_(0x646f72616e646f6dULL ^ key.k1),
        v2_(0x6c7967656e657261ULL ^ key.k0),
        v3_(0x7465646279746573ULL ^ key.k1) {}

  constexpr void update(std::span<const std::byte> data) noexcept {
    std::size_t i = 0;
    // Fill a partial word first.
    while (i < data.size() && fill_ != 0) {
      push_byte(std::to_integer<std::uint8_t>(data[i++]));
    }
    // Whole words.
    while (data.size() - i >= 8) {
      std::uint64_t m = 0;
      for (int b = 7; b >= 0; --b) {
        m = (m << 8) | std::to_integer<std::uint64_t>(data[i + static_cast<std::size_t>(b)]);
      }
      compress(m);
      len_ = static_cast<std::uint8_t>(len_ + 8);
      i += 8;
    }
    while (i < data.size()) {
      push_byte(std::to_integer<std::uint8_t>(data[i++]));
    }
  }

  constexpr void update_u8(std::uint8_t v) noexcept { push_byte(v); }
  constexpr void update_u16(std::uint16_t v) noexcept {
    push_byte(static_cast<std::uint8_t>(v >> 8));
    push_byte(static_cast<std::uint8_t>(v));
  }
  constexpr void update_u32(std::uint32_t v) noexcept {
    update_u16(static_cast<std::uint16_t>(v >> 16));
    update_u16(static_cast<std::uint16_t>(v));
  }
  constexpr void update_u64(std::uint64_t v) noexcept {
    update_u32(static_cast<std::uint32_t>(v >> 32));
    update_u32(static_cast<std::uint32_t>(v));
  }

  // The 64-bit hash of everything appended so far. The hasher is unchanged.
  [[nodiscard]] constexpr std::uint64_t finish() const noexcept {
    SipHasher h = *this;
    const std::uint64_t b = (static_cast<std::uint64_t>(h.len_) << 56) | h.tail_;
    h.compress(b);
    h.v2_ ^= 0xff;
    for (int r = 0; r < DRounds; ++r) {
      h.round();
    }
    return h.v0_ ^ h.v1_ ^ h.v2_ ^ h.v3_;
  }

private:
  static constexpr std::uint64_t rotl(std::uint64_t x, int b) noexcept {
    return (x << b) | (x >> (64 - b));
  }

  constexpr void round() noexcept {
    v0_ += v1_;
    v1_ = rotl(v1_, 13);
    v1_ ^= v0_;
    v0_ = rotl(v0_, 32);
    v2_ += v3_;
    v3_ = rotl(v3_, 16);
    v3_ ^= v2_;
    v0_ += v3_;
    v3_ = rotl(v3_, 21);
    v3_ ^= v0_;
    v2_ += v1_;
    v1_ = rotl(v1_, 17);
    v1_ ^= v2_;
    v2_ = rotl(v2_, 32);
  }

  constexpr void compress(std::uint64_t m) noexcept {
    v3_ ^= m;
    for (int r = 0; r < CRounds; ++r) {
      round();
    }
    v0_ ^= m;
  }

  constexpr void push_byte(std::uint8_t byte) noexcept {
    tail_ |= static_cast<std::uint64_t>(byte) << (8 * fill_);
    ++len_;
    if (++fill_ == 8) {
      compress(tail_);
      tail_ = 0;
      fill_ = 0;
    }
  }

  std::uint64_t v0_, v1_, v2_, v3_;
  std::uint64_t tail_ = 0;  // bytes of the current partial word, little-endian
  unsigned fill_ = 0;       // bytes in tail_
  std::uint8_t len_ = 0;    // message length mod 256
};

using SipHasher24 = SipHasher<2, 4>;
using SipHasher13 = SipHasher<1, 3>;

// SipHash-1-3 (connection-table hashing).
[[nodiscard]] std::uint64_t siphash13(const SipKey& key, std::span<const std::byte> data) noexcept;

}  // namespace utcp
