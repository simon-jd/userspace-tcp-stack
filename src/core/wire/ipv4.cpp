#include "core/wire/ipv4.hpp"

#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp::wire {
namespace {

constexpr std::uint16_t flag_df = 0x4000;
constexpr std::uint16_t flag_mf = 0x2000;
constexpr std::uint16_t frag_offset_mask = 0x1fff;

}  // namespace

std::expected<Ipv4View, ParseError> parse_ipv4(std::span<const std::byte> d) noexcept {
  if (d.size() < ipv4_header_len) {
    return std::unexpected(ParseError::truncated);
  }
  const std::uint8_t ver_ihl = load_u8(d, 0);
  if ((ver_ihl >> 4) != 4) {
    return std::unexpected(ParseError::bad_version);
  }
  const auto ihl = static_cast<std::uint8_t>(ver_ihl & 0x0fu);
  if (ihl < 5) {
    return std::unexpected(ParseError::bad_ihl);
  }
  const std::size_t hlen = std::size_t{ihl} * 4;
  if (d.size() < hlen) {
    return std::unexpected(ParseError::truncated);
  }
  // RFC 791 §3.1: the checksum covers the header, options included.
  if (!checksum_valid(d.first(hlen))) {
    return std::unexpected(ParseError::bad_checksum);
  }
  const std::uint16_t total_len = load_be16(d, 2);
  if (total_len < hlen) {
    return std::unexpected(ParseError::bad_length);
  }
  if (total_len > d.size()) {
    return std::unexpected(ParseError::truncated);
  }
  const std::uint16_t flags_frag = load_be16(d, 6);
  Ipv4View v;
  v.ihl = ihl;
  v.h.tos = load_u8(d, 1);
  v.h.total_len = total_len;
  v.h.id = load_be16(d, 4);
  v.h.df = (flags_frag & flag_df) != 0;
  v.h.mf = (flags_frag & flag_mf) != 0;
  v.h.frag_off = static_cast<std::uint16_t>(flags_frag & frag_offset_mask);
  v.h.ttl = load_u8(d, 8);
  v.h.proto = load_u8(d, 9);
  v.h.src = Ipv4Addr{load_be32(d, 12)};
  v.h.dst = Ipv4Addr{load_be32(d, 16)};
  // §1.2: fragments are dropped, never reassembled.
  if (v.h.mf || v.h.frag_off != 0) {
    return std::unexpected(ParseError::fragment);
  }
  v.payload = d.subspan(hlen, total_len - hlen);
  return v;
}

void write_ipv4(std::span<std::byte> out, const Ipv4Header& h) noexcept {
  UTCP_CHECK(out.size() >= ipv4_header_len);
  const std::span<std::byte> o = out.first(ipv4_header_len);
  store_u8(o, 0, 0x45);  // version 4, IHL 5
  store_u8(o, 1, h.tos);
  store_be16(o, 2, h.total_len);
  store_be16(o, 4, h.id);
  const auto flags_frag = static_cast<std::uint16_t>((h.frag_off & frag_offset_mask) |
                                                     (h.df ? flag_df : 0u) | (h.mf ? flag_mf : 0u));
  store_be16(o, 6, flags_frag);
  store_u8(o, 8, h.ttl);
  store_u8(o, 9, h.proto);
  store_be16(o, 10, 0);
  store_be32(o, 12, h.src.v);
  store_be32(o, 16, h.dst.v);
  store_be16(o, 10, internet_checksum(o));
}

void set_l4_checksum(std::span<std::byte> l4, Ipv4Addr src, Ipv4Addr dst,
                     std::uint8_t proto) noexcept {
  UTCP_CHECK(proto == ip_proto_tcp || proto == ip_proto_udp);
  UTCP_CHECK(l4.size() <= 0xffff);
  const std::size_t field = proto == ip_proto_tcp ? 16 : 6;
  UTCP_CHECK(l4.size() >= field + 2);
  store_be16(l4, field, 0);
  const std::uint16_t c = proto == ip_proto_tcp ? tcp_checksum_ipv4(src.v, dst.v, l4)
                                                : udp_checksum_ipv4(src.v, dst.v, l4);
  store_be16(l4, field, c);
}

}  // namespace utcp::wire
