// Ephemeral port selection, RFC 6056 §3.3.4 Algorithm 4 "Double-Hash Port
// Selection" (DESIGN §4.6). TCP and UDP share one allocator; each caller
// passes its own range and its own test for ports that cannot be used.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>

#include "core/util/function_ref.hpp"
#include "utcp/config.hpp"
#include "utcp/error.hpp"
#include "utcp/random.hpp"
#include "utcp/types.hpp"

namespace utcp {

class PortAllocator {
public:
  static constexpr std::size_t table_size = 256;  // DESIGN §4.6: index = G(...) mod 256

  // `offset_key` keys F, `table_key` keys G; the table starts with values
  // below 65536 drawn from `table_init` (RFC 6056: table[i] = random() % 65536).
  PortAllocator(const SipKey& offset_key, const SipKey& table_key, Rng table_init) noexcept;

  // RFC 6056 §3.3.4:
  //   offset = F(local, remote addr, remote port), index = G(same) mod 256;
  //   repeat n = range.size() times:
  //     port = range.lo + (offset + table[index]) mod n; table[index]++;
  //     if !unusable(port) return port;
  // F and G are SipHash-2-4 under the two keys (F: the low 32 bits). The n
  // candidates of one call are distinct, so the whole range is tried before
  // the call fails with addr_not_available (also for an empty range).
  std::expected<std::uint16_t, Error> pick(PortRange range, Ipv4Addr local, Endpoint remote,
                                           FunctionRef<bool(std::uint16_t)> unusable) noexcept;

  // The two hashes, for tests.
  [[nodiscard]] std::uint32_t offset(Ipv4Addr local, Endpoint remote) const noexcept;
  [[nodiscard]] std::size_t index(Ipv4Addr local, Endpoint remote) const noexcept;
  [[nodiscard]] const std::array<std::uint32_t, table_size>& table() const noexcept {
    return table_;
  }

private:
  SipKey offset_key_, table_key_;
  // 32-bit counters (RFC 6056 uses 16 bits): a counter that wrapped at 65536
  // would repeat candidates within one walk when n does not divide 65536.
  std::array<std::uint32_t, table_size> table_{};
};

}  // namespace utcp
