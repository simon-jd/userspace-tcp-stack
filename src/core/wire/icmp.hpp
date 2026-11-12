// ICMP messages (RFC 792; DESIGN §3.7, §3.10): echo request and reply, and
// error messages that quote the offending datagram.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>

#include "core/wire/ipv4.hpp"

namespace utcp::wire {

inline constexpr std::size_t icmp_header_len = 8;

// Types (RFC 792).
inline constexpr std::uint8_t icmp_echo_reply = 0;
inline constexpr std::uint8_t icmp_dest_unreach = 3;
inline constexpr std::uint8_t icmp_source_quench = 4;
inline constexpr std::uint8_t icmp_redirect = 5;
inline constexpr std::uint8_t icmp_echo_request = 8;
inline constexpr std::uint8_t icmp_time_exceeded = 11;

// Destination unreachable codes (RFC 792; code 4 with the next-hop MTU of
// RFC 1191 §4).
inline constexpr std::uint8_t icmp_net_unreach = 0;
inline constexpr std::uint8_t icmp_host_unreach = 1;
inline constexpr std::uint8_t icmp_proto_unreach = 2;
inline constexpr std::uint8_t icmp_port_unreach = 3;
inline constexpr std::uint8_t icmp_frag_needed = 4;

// Most bytes of the offending datagram a generated error quotes: the error
// datagram stays within 576 bytes (RFC 1812 §4.3.2.3; Linux icmp_send).
inline constexpr std::size_t icmp_max_quote = 576 - ipv4_header_len - icmp_header_len;

struct IcmpHeader {
  std::uint8_t type = 0, code = 0;
  std::uint16_t csum = 0;  // as received; write_icmp computes it
  std::uint32_t rest = 0;  // bytes 4-7: echo id and sequence, next-hop MTU, or unused

  [[nodiscard]] constexpr std::uint16_t echo_id() const noexcept {
    return static_cast<std::uint16_t>(rest >> 16);
  }
  [[nodiscard]] constexpr std::uint16_t echo_seq() const noexcept {
    return static_cast<std::uint16_t>(rest & 0xffffu);
  }
  // Type 3 code 4 (RFC 1191 §4): low 16 bits; 0 from routers that predate it.
  [[nodiscard]] constexpr std::uint16_t next_hop_mtu() const noexcept {
    return static_cast<std::uint16_t>(rest & 0xffffu);
  }

  constexpr bool operator==(const IcmpHeader&) const = default;
};

[[nodiscard]] constexpr IcmpHeader icmp_echo_header(std::uint8_t type, std::uint16_t id,
                                                    std::uint16_t seq) noexcept {
  return IcmpHeader{type, 0, 0, (std::uint32_t{id} << 16) | seq};
}
[[nodiscard]] constexpr IcmpHeader icmp_unreach_header(std::uint8_t code,
                                                       std::uint16_t next_hop_mtu = 0) noexcept {
  return IcmpHeader{icmp_dest_unreach, code, 0, next_hop_mtu};
}

struct IcmpView {
  IcmpHeader h;
  std::span<const std::byte> body;  // echo payload, or the quoted datagram of an error
};

// Parses one message (the IPv4 payload). truncated if shorter than 8 bytes;
// bad_checksum if verify_csum and the checksum over the whole message fails.
[[nodiscard]] std::expected<IcmpView, ParseError> parse_icmp(std::span<const std::byte> message,
                                                             bool verify_csum) noexcept;

// Writes the 8-byte header at the front of `message` (header followed by the
// body, already in place) and sets the checksum over the whole message.
// h.csum is ignored. Precondition (checked): message.size() >= 8.
void write_icmp(std::span<std::byte> message, const IcmpHeader& h) noexcept;

// The datagram quoted in an error body: its IPv4 header and the first bytes
// of its transport header.
struct IcmpQuote {
  Ipv4Header ip;
  std::uint8_t ihl = 5;
  std::span<const std::byte> l4;  // everything after the quoted IPv4 header (>= 8 bytes)
};

// Parses the quoted datagram of an error (DESIGN §3.7: the IPv4 header plus at
// least 8 bytes of the transport header are required). truncated if the body
// is shorter than 20 bytes or than IHL*4 + 8; bad_version; bad_ihl. The
// quoted header's checksum and total length are not checked: the quote is
// cut short by design and routers may have changed fields.
[[nodiscard]] std::expected<IcmpQuote, ParseError> parse_icmp_quote(
    std::span<const std::byte> body) noexcept;

}  // namespace utcp::wire
