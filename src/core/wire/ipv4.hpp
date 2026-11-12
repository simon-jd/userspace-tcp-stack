// IPv4 header parsing and serialisation (DESIGN §3.10), plus what all wire
// formats share: the parse error type, big-endian load/store helpers and the
// TCP/UDP checksum setter.
//
// Parsers return views into the input; nothing is copied. Writers fill a
// caller-provided span; output is built back to front in a PacketBuf
// (payload, then the transport header, then the IPv4 header). No
// reinterpret_cast of packet bytes: every field is an explicit big-endian
// load or store.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#include "utcp/types.hpp"

namespace utcp::wire {

enum class ParseError : std::uint8_t {
  truncated,        // buffer shorter than the fixed header, the IHL or the IPv4 total length
  bad_version,      // IPv4 version field != 4
  bad_ihl,          // IHL < 5
  bad_length,       // a length field is smaller than its header (IPv4 total length, UDP length)
  bad_checksum,     // IPv4 header, TCP, UDP or ICMP checksum
  fragment,         // MF set or fragment offset != 0 (fragments are not reassembled, §1.2)
  bad_data_offset,  // TCP data offset < 5 or beyond the segment
};
inline constexpr int parse_error_count = 7;

[[nodiscard]] constexpr std::string_view to_string(ParseError e) noexcept {
  switch (e) {
    case ParseError::truncated: return "truncated";
    case ParseError::bad_version: return "bad_version";
    case ParseError::bad_ihl: return "bad_ihl";
    case ParseError::bad_length: return "bad_length";
    case ParseError::bad_checksum: return "bad_checksum";
    case ParseError::fragment: return "fragment";
    case ParseError::bad_data_offset: return "bad_data_offset";
  }
  return "?";
}

// --- Big-endian loads and stores. Preconditions: the span holds the bytes.

[[nodiscard]] constexpr std::uint8_t load_u8(std::span<const std::byte> b, std::size_t at) noexcept {
  return std::to_integer<std::uint8_t>(b[at]);
}
[[nodiscard]] constexpr std::uint16_t load_be16(std::span<const std::byte> b,
                                                std::size_t at) noexcept {
  return static_cast<std::uint16_t>((std::to_integer<std::uint16_t>(b[at]) << 8) |
                                    std::to_integer<std::uint16_t>(b[at + 1]));
}
[[nodiscard]] constexpr std::uint32_t load_be32(std::span<const std::byte> b,
                                                std::size_t at) noexcept {
  return (std::uint32_t{load_be16(b, at)} << 16) | std::uint32_t{load_be16(b, at + 2)};
}
constexpr void store_u8(std::span<std::byte> b, std::size_t at, std::uint8_t v) noexcept {
  b[at] = std::byte{v};
}
constexpr void store_be16(std::span<std::byte> b, std::size_t at, std::uint16_t v) noexcept {
  b[at] = static_cast<std::byte>(v >> 8);
  b[at + 1] = static_cast<std::byte>(v & 0xffu);
}
constexpr void store_be32(std::span<std::byte> b, std::size_t at, std::uint32_t v) noexcept {
  store_be16(b, at, static_cast<std::uint16_t>(v >> 16));
  store_be16(b, at + 2, static_cast<std::uint16_t>(v & 0xffffu));
}

// --- IPv4 (RFC 791).

inline constexpr std::size_t ipv4_header_len = 20;  // without options; we never send options
inline constexpr std::size_t ipv4_max_header_len = 60;

// A parsed or to-be-written IPv4 header. IP options are skipped on receipt
// and never written (§1.2), so there is no IHL field: write_ipv4 always
// writes IHL 5, and a parsed header's options lie between the fixed header and
// the payload.
struct Ipv4Header {
  std::uint8_t tos = 0;
  std::uint8_t ttl = 0;
  std::uint8_t proto = 0;      // ip_proto_* of utcp/checksum.hpp
  std::uint16_t total_len = 0;  // header plus payload, bytes
  std::uint16_t id = 0;
  std::uint16_t frag_off = 0;  // fragment offset in 8-byte units (13 bits)
  bool df = false;
  bool mf = false;
  Ipv4Addr src, dst;

  constexpr bool operator==(const Ipv4Header&) const = default;
};

struct Ipv4View {
  Ipv4Header h;
  std::uint8_t ihl = 5;                 // header length in 32-bit words, options included
  std::span<const std::byte> payload;  // bytes [IHL*4, total_len): trailing link padding excluded
};

// Validates and parses one datagram (RFC 791 §3.1; Linux ip_rcv_core order):
// truncated if the buffer is shorter than 20 bytes or than IHL*4;
// bad_version; bad_ihl; bad_checksum (always verified); bad_length if
// total_len < IHL*4; truncated if total_len exceeds the buffer (Linux counts it
// in IpExtInTruncatedPkts); fragment if MF is set or the offset is non-zero.
// Bytes after total_len are ignored. The destination is not checked here.
[[nodiscard]] std::expected<Ipv4View, ParseError> parse_ipv4(
    std::span<const std::byte> datagram) noexcept;

// Writes a 20-byte header (version 4, IHL 5, no options) into out20 and sets
// the header checksum. Precondition (checked): out20.size() >= 20.
void write_ipv4(std::span<std::byte> out20, const Ipv4Header& h) noexcept;

// Computes and stores the checksum of a complete TCP segment or UDP datagram
// `l4` (header and payload) over the IPv4 pseudo-header (RFC 9293 §3.1, RFC
// 768). The checksum field (offset 16 for TCP, 6 for UDP) may hold anything
// before the call. For UDP a computed 0 is stored as 0xFFFF (RFC 768).
// Precondition (checked): proto is ip_proto_tcp or ip_proto_udp, l4 holds the
// header, l4.size() <= 65535.
void set_l4_checksum(std::span<std::byte> l4, Ipv4Addr src, Ipv4Addr dst,
                     std::uint8_t proto) noexcept;

}  // namespace utcp::wire
