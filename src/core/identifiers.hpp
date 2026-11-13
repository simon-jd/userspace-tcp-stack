// Keys derived from the stack seed and the identifiers computed from them
// (DESIGN §3.8, §4.6).
//
// At construction the stack derives one SipHash key per purpose from
// StackConfig::seed (SipHash-2-4 as a PRF, Rng::derive_seed with a label per
// key), so every identifier is a function of the seed and its inputs only.
#pragma once

#include <cstdint>

#include "utcp/random.hpp"
#include "utcp/seq.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

struct StackKeys {
  SipKey isn;          // RFC 6528 §3 F()
  SipKey ts_offset;    // RFC 7323 §5.4 per-connection timestamp offset
  SipKey port_offset;  // RFC 6056 §3.3.4 F() (offset)
  SipKey port_table;   // RFC 6056 §3.3.4 G() (table index)
  SipKey hash;         // connection and TIME_WAIT tables (SipHash-1-3, §4.3)
  SipKey ip_id;        // first IP ID of a connection (RFC 6864 §4.1)

  // Label "key/<name>" per key: Rng::derive_seed(seed, label), words 0 and 1.
  [[nodiscard]] static StackKeys derive(const Seed& seed) noexcept;

  bool operator==(const StackKeys&) const = default;
};

// RFC 6528 §3: the clock M, a 32-bit counter of 4-microsecond ticks of `now`
// (floor division, so it also counts up across negative times).
[[nodiscard]] std::uint32_t isn_clock(Time now) noexcept;

// RFC 6528 §3: ISN = M + F(localip, localport, remoteip, remoteport,
// secretkey), F = the low 32 bits of SipHash-2-4 over the four fields in
// network byte order.
[[nodiscard]] Seq32 isn_for(const SipKey& key, const FourTuple& tuple, Time now) noexcept;

// RFC 7323 §5.4: a per-connection offset added to the timestamp clock, the low
// 32 bits of SipHash-2-4 over the 4-tuple.
[[nodiscard]] std::uint32_t ts_offset_for(const SipKey& key, const FourTuple& tuple) noexcept;

// RFC 6864 §4.1: atomic datagrams may carry any ID; a connection counts up
// from this hash-derived start, which keeps captures readable.
[[nodiscard]] std::uint16_t ip_id_start_for(const SipKey& key, const FourTuple& tuple) noexcept;

}  // namespace utcp
