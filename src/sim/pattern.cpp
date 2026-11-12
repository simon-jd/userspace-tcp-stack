#include "utcp/sim/pattern.hpp"

#include "core/util/siphash.hpp"

namespace utcp::sim {
namespace {

// The splitmix64 output function (a bijection on 64-bit values).
constexpr std::uint64_t mix64(std::uint64_t z) noexcept {
  z = (z ^ (z >> 30)) * 0xbf58'476d'1ce4'e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d0'49bb'1331'11ebULL;
  return z ^ (z >> 31);
}

}  // namespace

Pattern::Pattern(const Seed& master, std::string_view kind, std::uint32_t flow,
                 std::uint8_t dir) noexcept {
  const Seed s = Rng::derive_seed(master, "data");
  SipHasher24 h(SipKey{s.w[0], s.w[1]});
  h.update(std::as_bytes(std::span<const char>(kind.data(), kind.size())));
  h.update_u8(0);
  h.update_u32(flow);
  h.update_u8(dir);
  key_ = h.finish();
}

std::uint64_t Pattern::block(std::uint64_t index) const noexcept {
  return mix64(key_ ^ (index * 0x9e37'79b9'7f4a'7c15ULL));
}

std::byte Pattern::at(std::uint64_t offset) const noexcept {
  return static_cast<std::byte>(block(offset >> 3) >> (8 * (offset & 7)));
}

void Pattern::fill(std::uint64_t offset, std::span<std::byte> out) const noexcept {
  std::size_t i = 0;
  while (i < out.size()) {
    const std::uint64_t off = offset + i;
    std::uint64_t b = block(off >> 3) >> (8 * (off & 7));
    for (std::uint64_t k = off & 7; k < 8 && i < out.size(); ++k, ++i) {
      out[i] = static_cast<std::byte>(b);
      b >>= 8;
    }
  }
}

std::optional<std::uint64_t> Pattern::mismatch(std::uint64_t offset,
                                                std::span<const std::byte> data) const noexcept {
  std::size_t i = 0;
  while (i < data.size()) {
    const std::uint64_t off = offset + i;
    std::uint64_t b = block(off >> 3) >> (8 * (off & 7));
    for (std::uint64_t k = off & 7; k < 8 && i < data.size(); ++k, ++i) {
      if (data[i] != static_cast<std::byte>(b)) {
        return offset + i;
      }
      b >>= 8;
    }
  }
  return std::nullopt;
}

}  // namespace utcp::sim
