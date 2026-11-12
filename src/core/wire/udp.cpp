#include "core/wire/udp.hpp"

#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp::wire {

std::expected<UdpView, ParseError> parse_udp(std::span<const std::byte> d, Ipv4Addr src,
                                             Ipv4Addr dst, bool verify_csum) noexcept {
  UTCP_CHECK(d.size() <= 0xffff);  // an IPv4 payload
  if (d.size() < udp_header_len) {
    return std::unexpected(ParseError::truncated);
  }
  UdpView v;
  v.h.sport = load_be16(d, 0);
  v.h.dport = load_be16(d, 2);
  v.h.len = load_be16(d, 4);
  v.h.csum = load_be16(d, 6);
  if (v.h.len < udp_header_len || v.h.len > d.size()) {
    return std::unexpected(ParseError::bad_length);
  }
  const std::span<const std::byte> dgram = d.first(v.h.len);
  // RFC 768: a zero checksum field means the sender computed none.
  if (verify_csum && v.h.csum != 0 &&
      !ipv4_transport_checksum_valid(src.v, dst.v, ip_proto_udp, dgram)) {
    return std::unexpected(ParseError::bad_checksum);
  }
  v.payload = dgram.subspan(udp_header_len);
  return v;
}

void write_udp_header(std::span<std::byte> out, const UdpHeader& h) noexcept {
  UTCP_CHECK(out.size() >= udp_header_len);
  store_be16(out, 0, h.sport);
  store_be16(out, 2, h.dport);
  store_be16(out, 4, h.len);
  store_be16(out, 6, 0);
}

}  // namespace utcp::wire
