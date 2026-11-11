// Internet checksum (RFC 1071), incremental update (RFC 1624), and the IPv4
// pseudo-header used by TCP (RFC 9293 section 3.1) and UDP (RFC 768).
//
// All 16-bit values here are host integers whose big-endian encoding is the
// on-wire field: write a result `c` as the bytes (c >> 8, c & 0xff).
// IPv4 addresses are host integers too: 192.0.2.1 is 0xC0000201.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace utcp {

// IPv4 protocol numbers that appear in the pseudo-header.
inline constexpr std::uint8_t ip_proto_icmp = 1;
inline constexpr std::uint8_t ip_proto_tcp = 6;
inline constexpr std::uint8_t ip_proto_udp = 17;

// One's-complement sum over a byte stream (RFC 1071 section 1). The stream is
// read as big-endian 16-bit words; an odd final byte is padded with a zero
// byte. The stream may be appended in pieces of any length and alignment; the
// result equals the sum over the concatenation.
class ChecksumAccumulator {
public:
  void add(std::span<const std::byte> data) noexcept;
  void add(std::span<const std::uint8_t> data) noexcept { add(std::as_bytes(data)); }

  // Appends two bytes: value >> 8, then value & 0xff.
  void add_u16(std::uint16_t value) noexcept;
  // Appends four bytes, most significant first.
  void add_u32(std::uint32_t value) noexcept;

  // Folded one's-complement sum. Never 0x0000 unless every byte added is zero.
  [[nodiscard]] std::uint16_t sum() const noexcept;
  // Value for the checksum field: the complement of sum().
  [[nodiscard]] std::uint16_t checksum() const noexcept {
    return static_cast<std::uint16_t>(~sum());
  }
  // True if the data added, checksum field included, sums to 0xFFFF
  // (the RFC 1071 receiver check).
  [[nodiscard]] bool valid() const noexcept { return sum() == 0xFFFF; }

  [[nodiscard]] std::size_t size() const noexcept { return bytes_; }

private:
  std::uint64_t acc_ = 0;   // unfolded sum of big-endian word values
  std::size_t bytes_ = 0;   // stream length so far; its parity matters
};

// Checksum field value for `data` (the complement of its one's-complement
// sum). For an IPv4 header or an ICMP message, pass it with the checksum field
// set to zero.
[[nodiscard]] std::uint16_t internet_checksum(std::span<const std::byte> data) noexcept;

// RFC 1071 receiver check: `data` including its checksum field sums to 0xFFFF.
[[nodiscard]] bool checksum_valid(std::span<const std::byte> data) noexcept;

// RFC 1624 eqn. 3, HC' = ~(~HC + ~m + m'): the new checksum after one 16-bit
// word at an even offset changes from `old_word` to `new_word`. Unlike the
// RFC 1141 form it gives 0x0000, not 0xFFFF, when the recomputed sum is
// 0xFFFF (RFC 1624 section 3). Like the RFC, it assumes the checksummed data
// is not all zero; that holds for every IP header and pseudo-header.
[[nodiscard]] std::uint16_t checksum_update16(std::uint16_t checksum, std::uint16_t old_word,
                                              std::uint16_t new_word) noexcept;

// As checksum_update16 for a 32-bit field at an even offset (two words), e.g.
// an IPv4 address.
[[nodiscard]] std::uint16_t checksum_update32(std::uint16_t checksum, std::uint32_t old_value,
                                              std::uint32_t new_value) noexcept;

// Appends the 12-byte IPv4 pseudo-header: source, destination, zero,
// protocol, length (RFC 9293 section 3.1 figure 2; RFC 768). `length` is the
// TCP or UDP length in bytes, header included.
void add_ipv4_pseudo_header(ChecksumAccumulator& acc, std::uint32_t src, std::uint32_t dst,
                            std::uint8_t protocol, std::uint16_t length) noexcept;

// Checksum over the IPv4 pseudo-header plus `payload` (a TCP segment or UDP
// datagram). With the payload's checksum field zeroed, this is the value to
// store. Precondition: payload.size() <= 65535.
[[nodiscard]] std::uint16_t ipv4_transport_checksum(std::uint32_t src, std::uint32_t dst,
                                                    std::uint8_t protocol,
                                                    std::span<const std::byte> payload) noexcept;

// Receiver check for a TCP segment or UDP datagram with its checksum field in
// place. For UDP the caller handles a zero field ("no checksum", RFC 768)
// before calling this. Precondition: payload.size() <= 65535.
[[nodiscard]] bool ipv4_transport_checksum_valid(std::uint32_t src, std::uint32_t dst,
                                                 std::uint8_t protocol,
                                                 std::span<const std::byte> payload) noexcept;

// TCP checksum to store (RFC 9293 section 3.1); checksum field zeroed.
[[nodiscard]] inline std::uint16_t tcp_checksum_ipv4(std::uint32_t src, std::uint32_t dst,
                                                     std::span<const std::byte> segment) noexcept {
  return ipv4_transport_checksum(src, dst, ip_proto_tcp, segment);
}

// UDP checksum to store (RFC 768); checksum field zeroed. A computed 0x0000
// is sent as 0xFFFF, because 0x0000 in the field means "no checksum".
[[nodiscard]] inline std::uint16_t udp_checksum_ipv4(std::uint32_t src, std::uint32_t dst,
                                                     std::span<const std::byte> datagram) noexcept {
  const std::uint16_t c = ipv4_transport_checksum(src, dst, ip_proto_udp, datagram);
  return c == 0 ? std::uint16_t{0xFFFF} : c;
}

}  // namespace utcp
