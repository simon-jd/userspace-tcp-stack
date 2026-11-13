// Builds IPv4 datagrams of every protocol for tests: well-formed by default,
// with fields that tests set to make them malformed (checksums, lengths,
// fragments, IHL, options, TCP flags including AE, CWR and ECE).
//
// Everything is returned as std::vector<std::byte>: the transport part
// (udp(), tcp(), icmp()) and the whole datagram (ipv4() around it).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "core/wire/icmp.hpp"
#include "core/wire/tcp.hpp"
#include "utcp/seq.hpp"
#include "utcp/types.hpp"

namespace utcp::test {

using Bytes = std::vector<std::byte>;

// `n` bytes 0, 1, 2, ... (mod 256) plus `seed`.
Bytes pattern(std::size_t n, std::uint8_t seed = 0);

struct IpSpec {
  Ipv4Addr src, dst;
  std::uint8_t proto = 0;
  std::uint8_t ttl = 64;
  std::uint8_t tos = 0;
  std::uint16_t id = 0;
  bool df = true;
  bool mf = false;
  std::uint16_t frag_off = 0;  // 8-byte units
  Bytes options;               // IP options; padded with zeros to a multiple of 4 (at most 40)
  // Overrides, for malformed datagrams.
  std::optional<std::uint8_t> version;       // default 4
  std::optional<std::uint8_t> ihl;           // default from the options
  std::optional<std::uint16_t> total_len;    // default header + payload
  bool corrupt_checksum = false;             // header checksum off by one
};

// The datagram: header (checksum set, then corrupted if asked), then `payload`.
Bytes ipv4(const IpSpec& ip, std::span<const std::byte> payload);

enum class UdpChecksum : std::uint8_t {
  compute,  // correct; a computed 0 is written as 0xFFFF
  none,     // field 0: no checksum (RFC 768)
  corrupt,  // correct value plus one
};

struct UdpSpec {
  UdpSpec() = default;
  UdpSpec(Endpoint s, Endpoint d, Bytes p, UdpChecksum c = UdpChecksum::compute)
      : src(s), dst(d), payload(std::move(p)), checksum(c) {}

  Endpoint src, dst;
  Bytes payload;
  UdpChecksum checksum = UdpChecksum::compute;
  std::optional<std::uint16_t> len;  // override of the length field
};

// The UDP datagram (header and payload); the checksum covers the pseudo-header
// of (src.addr, dst.addr) and the bytes as built.
Bytes udp(const UdpSpec& u);
// A complete IPv4 datagram carrying udp(u), src.addr -> dst.addr.
Bytes udp_datagram(const UdpSpec& u);

struct TcpSpec {
  TcpSpec() = default;
  TcpSpec(Endpoint s, Endpoint d) : src(s), dst(d) {}

  Endpoint src, dst;
  Seq32 seq, ack;
  std::uint16_t flags = 0;   // wire::tcp_* bits, all twelve (AE, CWR, ECE, reserved included)
  std::uint16_t window = 65535;
  std::uint16_t urg = 0;
  wire::TcpOptions opt;      // written in the layout of DESIGN §4.5
  bool syn_layout = false;   // SYN option layout even without the SYN flag (set by SYN)
  Bytes payload;
  bool corrupt_checksum = false;
};

Bytes tcp(const TcpSpec& t);
Bytes tcp_datagram(const TcpSpec& t);

// An ICMP message: type, code, bytes 4-7, then `body`; checksum set (then
// corrupted if asked).
Bytes icmp(std::uint8_t type, std::uint8_t code, std::uint32_t rest,
           std::span<const std::byte> body, bool corrupt_checksum = false);
Bytes icmp_echo_request(Ipv4Addr src, Ipv4Addr dst, std::uint16_t id, std::uint16_t seq,
                        std::span<const std::byte> payload);
// An ICMP error from `src` to `dst` quoting the first `quote_len` bytes of
// `offending` (all of it by default). For type 3 code 4, `rest` carries the
// next-hop MTU in its low 16 bits.
Bytes icmp_error(Ipv4Addr src, Ipv4Addr dst, std::uint8_t type, std::uint8_t code,
                 std::uint32_t rest, std::span<const std::byte> offending,
                 std::optional<std::size_t> quote_len = std::nullopt);

// A datagram with any protocol number and payload.
Bytes raw_datagram(Ipv4Addr src, Ipv4Addr dst, std::uint8_t proto,
                   std::span<const std::byte> payload);

// After editing a datagram in place: recomputes the IPv4 header checksum and,
// for TCP and UDP (fixing_l4), the transport checksum (a UDP field of 0 stays
// 0). Precondition: a parsable header (version 4, IHL >= 5, the header and
// total length within the buffer).
void fix_checksums(std::span<std::byte> datagram, bool fixing_l4 = true);

}  // namespace utcp::test
