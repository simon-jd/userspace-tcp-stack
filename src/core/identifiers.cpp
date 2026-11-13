#include "core/identifiers.hpp"

#include <string_view>

#include "core/util/siphash.hpp"

namespace utcp {
namespace {

SipKey key_for(const Seed& seed, std::string_view label) noexcept {
  const Seed s = Rng::derive_seed(seed, label);
  return SipKey{s.w[0], s.w[1]};
}

std::uint64_t tuple_hash24(const SipKey& key, const FourTuple& t) noexcept {
  SipHasher24 h(key);
  h.update_u32(t.local.addr.v);
  h.update_u16(t.local.port);
  h.update_u32(t.remote.addr.v);
  h.update_u16(t.remote.port);
  return h.finish();
}

}  // namespace

StackKeys StackKeys::derive(const Seed& seed) noexcept {
  StackKeys k;
  k.isn = key_for(seed, "key/isn");
  k.ts_offset = key_for(seed, "key/ts_offset");
  k.port_offset = key_for(seed, "key/port_offset");
  k.port_table = key_for(seed, "key/port_table");
  k.hash = key_for(seed, "key/hash");
  k.ip_id = key_for(seed, "key/ip_id");
  return k;
}

std::uint32_t isn_clock(Time now) noexcept {
  // RFC 6528 §3: M is a timer that ticks every 4 microseconds.
  constexpr std::int64_t tick_ns = 4000;
  std::int64_t q = now.ns / tick_ns;
  if (now.ns % tick_ns < 0) {
    --q;  // floor
  }
  return static_cast<std::uint32_t>(static_cast<std::uint64_t>(q));
}

Seq32 isn_for(const SipKey& key, const FourTuple& tuple, Time now) noexcept {
  const auto f = static_cast<std::uint32_t>(tuple_hash24(key, tuple));
  return Seq32(isn_clock(now)) + f;
}

std::uint32_t ts_offset_for(const SipKey& key, const FourTuple& tuple) noexcept {
  return static_cast<std::uint32_t>(tuple_hash24(key, tuple));
}

std::uint16_t ip_id_start_for(const SipKey& key, const FourTuple& tuple) noexcept {
  return static_cast<std::uint16_t>(tuple_hash24(key, tuple));
}

}  // namespace utcp
