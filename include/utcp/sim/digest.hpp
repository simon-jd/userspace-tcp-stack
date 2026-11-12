// The run digest (DESIGN §7.2): a rolling SipHash-2-4 over every transmitted
// datagram and its time, socket events, errors and checker verdicts. Two runs
// of the same binary and scenario give the same digest; CI also compares the
// g++ and clang builds (§13.1).
//
// value() and hex() allocate nothing and call nothing but arithmetic, so
// utcp-sim's SIGABRT handler may use them on the live digest of a crashing run.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "core/util/siphash.hpp"
#include "utcp/time.hpp"

namespace utcp::sim {

class RunDigest {
public:
  RunDigest() noexcept;

  // A datagram a node handed to the host (pop_transmit), at time t.
  void packet(std::uint32_t node, Time t, std::span<const std::byte> datagram) noexcept;
  // A socket event an application took from poll_event.
  void socket_event(std::uint32_t node, Time t, std::uint32_t slot, std::uint32_t gen,
                    std::uint8_t proto, std::uint16_t events) noexcept;
  // An API error, a violation or the verdict: a tag and text.
  void text(std::uint32_t node, Time t, std::string_view tag, std::string_view what) noexcept;

  [[nodiscard]] std::uint64_t value() const noexcept { return h_.finish(); }

  // 16 lowercase hex digits.
  [[nodiscard]] static std::array<char, 16> hex(std::uint64_t v) noexcept;

private:
  SipHasher24 h_;
};

}  // namespace utcp::sim
