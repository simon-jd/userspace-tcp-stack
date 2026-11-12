// UDP header (RFC 768; DESIGN §3.6, §3.10).
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include "core/wire/ipv4.hpp"
#include "utcp/types.hpp"

namespace utcp::wire {

inline constexpr std::size_t udp_header_len = 8;

struct UdpHeader {
  std::uint16_t sport = 0, dport = 0;
  std::uint16_t len = 0;    // header plus payload, bytes
  std::uint16_t csum = 0;   // as received; 0 = the sender computed none (RFC 768)

  constexpr bool operator==(const UdpHeader&) const = default;
};

struct UdpView {
  UdpHeader h;
  std::span<const std::byte> payload;  // bytes [8, len); bytes after `len` are ignored
};

// Parses one datagram (the IPv4 payload). truncated if shorter than 8 bytes;
// bad_length if the length field is below 8 or exceeds the buffer;
// bad_checksum if verify_csum, the checksum field is non-zero and the
// checksum over the pseudo-header of (src, dst) and `len` bytes fails. A zero
// field means no checksum and is accepted (RFC 768).
// Precondition (checked): datagram.size() <= 65535.
[[nodiscard]] std::expected<UdpView, ParseError> parse_udp(std::span<const std::byte> datagram,
                                                           Ipv4Addr src, Ipv4Addr dst,
                                                           bool verify_csum) noexcept;

// Writes the 8-byte header with h.sport, h.dport and h.len, checksum field
// zero; set_l4_checksum (core/wire/ipv4.hpp) then fills it in. h.csum is
// ignored. Precondition (checked): out8.size() >= 8.
void write_udp_header(std::span<std::byte> out8, const UdpHeader& h) noexcept;

}  // namespace utcp::wire
