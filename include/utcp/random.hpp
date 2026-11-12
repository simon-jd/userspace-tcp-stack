// Seeds, the deterministic random source and keyed hashing (DESIGN §3.8).
//
// StackConfig::seed is the only source of randomness in the core. The
// backend fills it from getrandom(2); the simulator derives it from the
// scenario seed. Every consumer takes its own named stream (Rng::derive), so
// adding a consumer does not shift the others.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace utcp {

struct Seed {
  std::array<std::uint64_t, 4> w{};

  // Expands a 64-bit seed with splitmix64 (the simulator's scenario seeds).
  [[nodiscard]] static Seed from_u64(std::uint64_t s) noexcept;

  bool operator==(const Seed&) const = default;
};

// xoshiro256** (Blackman and Vigna). Not cryptographic. The state comes from
// the seed through the splitmix64 finalizer, so similar seeds give unrelated
// streams and the state is never all zero.
class Rng {
public:
  explicit Rng(const Seed& seed) noexcept;
  // Uses `state` as the xoshiro256** state directly (reference-vector tests).
  // Precondition: not all zero.
  [[nodiscard]] static Rng from_state(const std::array<std::uint64_t, 4>& state) noexcept;

  // Next 64 output bits.
  std::uint64_t next() noexcept;
  // Uniform in [0, n), without bias (Lemire's multiply-and-reject). n > 0.
  std::uint32_t below(std::uint32_t n) noexcept;
  // Uniform in [0, n), without bias (masked rejection). n > 0.
  std::uint64_t below64(std::uint64_t n) noexcept;
  // True with probability ppm / 1'000'000 (ppm >= 1'000'000 is always true).
  bool chance_ppm(std::uint32_t ppm) noexcept;

  // An independent stream for `label` (e.g. "link/a>b/loss"): Rng(derive_seed(master, label)).
  [[nodiscard]] static Rng derive(const Seed& master, std::string_view label) noexcept;
  // Word i is SipHash-2-4(master.w[0..1], i || label) xor SipHash-2-4(master.w[2..3], i || label).
  [[nodiscard]] static Seed derive_seed(const Seed& master, std::string_view label) noexcept;

  [[nodiscard]] const std::array<std::uint64_t, 4>& state() const noexcept { return s_; }

private:
  Rng() noexcept = default;
  std::array<std::uint64_t, 4> s_{};
};

// 128-bit SipHash key. k0 holds key bytes 0..7 read little-endian, k1 bytes
// 8..15 (the reference implementation's convention).
struct SipKey {
  std::uint64_t k0 = 0, k1 = 0;

  bool operator==(const SipKey&) const = default;
};

// SipHash-2-4 (Aumasson and Bernstein), used as a PRF for key derivation,
// RFC 6528 ISNs and timestamp offsets.
[[nodiscard]] std::uint64_t siphash24(const SipKey& key, std::span<const std::byte> data) noexcept;

}  // namespace utcp
