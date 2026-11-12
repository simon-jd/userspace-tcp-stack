#include "core/wire/icmp.hpp"

#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp::wire {

std::expected<IcmpView, ParseError> parse_icmp(std::span<const std::byte> m,
                                               bool verify_csum) noexcept {
  if (m.size() < icmp_header_len) {
    return std::unexpected(ParseError::truncated);
  }
  // RFC 792: the checksum covers the whole ICMP message.
  if (verify_csum && !checksum_valid(m)) {
    return std::unexpected(ParseError::bad_checksum);
  }
  IcmpView v;
  v.h.type = load_u8(m, 0);
  v.h.code = load_u8(m, 1);
  v.h.csum = load_be16(m, 2);
  v.h.rest = load_be32(m, 4);
  v.body = m.subspan(icmp_header_len);
  return v;
}

void write_icmp(std::span<std::byte> m, const IcmpHeader& h) noexcept {
  UTCP_CHECK(m.size() >= icmp_header_len);
  store_u8(m, 0, h.type);
  store_u8(m, 1, h.code);
  store_be16(m, 2, 0);
  store_be32(m, 4, h.rest);
  store_be16(m, 2, internet_checksum(m));
}

std::expected<IcmpQuote, ParseError> parse_icmp_quote(std::span<const std::byte> b) noexcept {
  if (b.size() < ipv4_header_len) {
    return std::unexpected(ParseError::truncated);
  }
  const std::uint8_t ver_ihl = load_u8(b, 0);
  if ((ver_ihl >> 4) != 4) {
    return std::unexpected(ParseError::bad_version);
  }
  const auto ihl = static_cast<std::uint8_t>(ver_ihl & 0x0fu);
  if (ihl < 5) {
    return std::unexpected(ParseError::bad_ihl);
  }
  const std::size_t hlen = std::size_t{ihl} * 4;
  if (b.size() < hlen + 8) {
    return std::unexpected(ParseError::truncated);
  }
  const std::uint16_t flags_frag = load_be16(b, 6);
  IcmpQuote q;
  q.ihl = ihl;
  q.ip.tos = load_u8(b, 1);
  q.ip.total_len = load_be16(b, 2);
  q.ip.id = load_be16(b, 4);
  q.ip.df = (flags_frag & 0x4000u) != 0;
  q.ip.mf = (flags_frag & 0x2000u) != 0;
  q.ip.frag_off = static_cast<std::uint16_t>(flags_frag & 0x1fffu);
  q.ip.ttl = load_u8(b, 8);
  q.ip.proto = load_u8(b, 9);
  q.ip.src = Ipv4Addr{load_be32(b, 12)};
  q.ip.dst = Ipv4Addr{load_be32(b, 16)};
  q.l4 = b.subspan(hlen);
  return q;
}

}  // namespace utcp::wire
