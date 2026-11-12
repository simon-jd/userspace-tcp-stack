#include <bit>

#include "core/util/siphash.hpp"
#include "utcp/check.hpp"
#include "utcp/random.hpp"

namespace utcp {
namespace {

constexpr std::uint64_t golden_gamma = 0x9e37'79b9'7f4a'7c15ULL;

// The splitmix64 output function (Steele, Lea and Flood; as in Vigna's
// splitmix64.c), a bijection on 64-bit values.
constexpr std::uint64_t mix64(std::uint64_t z) noexcept {
  z = (z ^ (z >> 30)) * 0xbf58'476d'1ce4'e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d0'49bb'1331'11ebULL;
  return z ^ (z >> 31);
}

}  // namespace

Seed Seed::from_u64(std::uint64_t s) noexcept {
  Seed seed;
  for (auto& w : seed.w) {
    s += golden_gamma;
    w = mix64(s);
  }
  return seed;
}

Rng::Rng(const Seed& seed) noexcept {
  std::uint64_t any = 0;
  for (std::size_t i = 0; i < s_.size(); ++i) {
    s_[i] = mix64(seed.w[i] + golden_gamma * (i + 1));
    any |= s_[i];
  }
  if (any == 0) {
    // mix64 is a bijection, so only four specific seeds get here.
    s_[0] = golden_gamma;
  }
}

Rng Rng::from_state(const std::array<std::uint64_t, 4>& state) noexcept {
  UTCP_CHECK((state[0] | state[1] | state[2] | state[3]) != 0);
  Rng r;
  r.s_ = state;
  return r;
}

// xoshiro256** 1.0, next() of the reference implementation.
std::uint64_t Rng::next() noexcept {
  const std::uint64_t result = std::rotl(s_[1] * 5, 7) * 9;
  const std::uint64_t t = s_[1] << 17;
  s_[2] ^= s_[0];
  s_[3] ^= s_[1];
  s_[1] ^= s_[2];
  s_[0] ^= s_[3];
  s_[2] ^= t;
  s_[3] = std::rotl(s_[3], 45);
  return result;
}

// Lemire, "Fast random integer generation in an interval" (2019): the high
// 32 bits of a 32x32-bit product, rejecting the low part below 2^32 mod n.
std::uint32_t Rng::below(std::uint32_t n) noexcept {
  UTCP_CHECK(n > 0);
  std::uint64_t m = (next() >> 32) * n;
  auto low = static_cast<std::uint32_t>(m);
  if (low < n) {
    const std::uint32_t threshold = (0u - n) % n;
    while (low < threshold) {
      m = (next() >> 32) * n;
      low = static_cast<std::uint32_t>(m);
    }
  }
  return static_cast<std::uint32_t>(m >> 32);
}

std::uint64_t Rng::below64(std::uint64_t n) noexcept {
  UTCP_CHECK(n > 0);
  // The smallest all-ones mask covering n - 1; values >= n are rejected, so
  // fewer than two draws are needed on average.
  const std::uint64_t mask = n == 1 ? 0 : ~std::uint64_t{0} >> std::countl_zero(n - 1);
  for (;;) {
    const std::uint64_t x = next() & mask;
    if (x < n) {
      return x;
    }
  }
}

bool Rng::chance_ppm(std::uint32_t ppm) noexcept {
  if (ppm >= 1'000'000) {
    return true;
  }
  return below(1'000'000) < ppm;
}

Seed Rng::derive_seed(const Seed& master, std::string_view label) noexcept {
  const SipKey ka{master.w[0], master.w[1]};
  const SipKey kb{master.w[2], master.w[3]};
  const auto bytes = std::as_bytes(std::span<const char>(label.data(), label.size()));
  Seed out;
  for (std::size_t i = 0; i < out.w.size(); ++i) {
    SipHasher24 ha(ka);
    SipHasher24 hb(kb);
    ha.update_u8(static_cast<std::uint8_t>(i));
    hb.update_u8(static_cast<std::uint8_t>(i));
    ha.update(bytes);
    hb.update(bytes);
    out.w[i] = ha.finish() ^ hb.finish();
  }
  return out;
}

Rng Rng::derive(const Seed& master, std::string_view label) noexcept {
  return Rng(derive_seed(master, label));
}

}  // namespace utcp
