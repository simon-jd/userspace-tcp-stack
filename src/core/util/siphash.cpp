#include "core/util/siphash.hpp"

namespace utcp {

std::uint64_t siphash24(const SipKey& key, std::span<const std::byte> data) noexcept {
  SipHasher24 h(key);
  h.update(data);
  return h.finish();
}

std::uint64_t siphash13(const SipKey& key, std::span<const std::byte> data) noexcept {
  SipHasher13 h(key);
  h.update(data);
  return h.finish();
}

}  // namespace utcp
