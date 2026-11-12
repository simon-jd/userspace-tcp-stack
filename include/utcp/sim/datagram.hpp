// IPv4 datagrams built and inspected by the simulator itself: the router's
// ICMP errors, synthetic test traffic, and the checksum checks of the link
// tests. Uses the core's wire formats (src/core/wire).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "core/wire/udp.hpp"
#include "utcp/types.hpp"

namespace utcp::sim {

// Addresses of the simulated hosts: node i is 198.18.0.(i + 1); the router
// of a path with a smaller MTU is 198.18.0.254 (RFC 2544 benchmark range).
[[nodiscard]] constexpr Ipv4Addr node_addr(std::uint32_t index) noexcept {
  return Ipv4Addr::from_octets(198, 18, 0, static_cast<std::uint8_t>(index + 1));
}
inline constexpr Ipv4Addr default_router_addr = Ipv4Addr::from_octets(198, 18, 0, 254);

struct TcpSegmentSpec {
  Endpoint src, dst;
  std::uint32_t seq = 0, ack = 0;
  std::uint16_t flags = 0;  // wire::tcp_* bits
  std::uint16_t window = 0;
  wire::TcpOptions opt;     // written in the layout of wire::write_tcp_header
  std::span<const std::byte> payload;
  std::uint16_t ip_id = 0;
  bool df = true;
  std::uint8_t ttl = 64;
};

// A complete IPv4/TCP datagram with valid checksums.
[[nodiscard]] std::vector<std::byte> build_tcp(const TcpSegmentSpec& s);
// A complete IPv4/UDP datagram with valid checksums (DF set).
[[nodiscard]] std::vector<std::byte> build_udp(Endpoint src, Endpoint dst,
                                               std::span<const std::byte> payload,
                                               std::uint16_t ip_id = 0);
// An ICMP echo request (type 8) or reply (type 0).
[[nodiscard]] std::vector<std::byte> build_icmp_echo(Ipv4Addr src, Ipv4Addr dst, std::uint8_t type,
                                                     std::uint16_t id, std::uint16_t seq,
                                                     std::span<const std::byte> payload,
                                                     std::uint16_t ip_id = 0);

// Writes an ICMP destination unreachable, fragmentation needed (type 3 code
// 4, RFC 1191 §4) from `from` to the source of `offending`, quoting the
// offending datagram's first bytes up to wire::icmp_max_quote (so the error
// stays within 576 bytes, RFC 1812 §4.3.2.3), into `out`. Returns the length
// written, or 0 if `offending` has no IPv4 header or `out` is too small.
std::size_t write_frag_needed(std::span<std::byte> out, Ipv4Addr from,
                              std::span<const std::byte> offending, std::uint16_t next_hop_mtu,
                              std::uint16_t ip_id);
[[nodiscard]] std::vector<std::byte> build_frag_needed(Ipv4Addr from,
                                                       std::span<const std::byte> offending,
                                                       std::uint16_t next_hop_mtu,
                                                       std::uint16_t ip_id = 0);

// The receiver checks of M0's checksum module: the IPv4 header checksum over
// IHL*4 bytes, and for TCP, UDP (unless its field is 0) and ICMP the
// transport checksum over the rest of the datagram (total length). False for
// anything that does not parse as far as the checksums.
[[nodiscard]] bool checksums_valid(std::span<const std::byte> datagram) noexcept;

// Recomputes the IPv4 header checksum and the TCP, UDP or ICMP checksum of a
// datagram whose total length field matches its size. No-op on datagrams
// shorter than their headers.
void fix_checksums(std::span<std::byte> datagram) noexcept;

// The TCP segment of a datagram that passes the IPv4 and TCP checks
// (checksums verified); nullopt otherwise.
struct TcpPacket {
  wire::Ipv4Header ip;
  wire::TcpView tcp;
};
[[nodiscard]] std::optional<TcpPacket> parse_tcp_packet(std::span<const std::byte> datagram) noexcept;

}  // namespace utcp::sim
