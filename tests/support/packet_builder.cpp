#include "support/packet_builder.hpp"

#include <algorithm>

#include "core/wire/ipv4.hpp"
#include "core/wire/udp.hpp"
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp::test {

namespace w = utcp::wire;

namespace {

// Changes a checksum field so that verification fails: flipping one low bit
// moves the value by one, never between the two encodings of zero (0x0000
// and 0xFFFF); 0x0001 goes to 0x0003, so a UDP field never becomes "none".
std::uint16_t corrupted(std::uint16_t c) {
  return (c ^ 0x0001u) == 0 ? static_cast<std::uint16_t>(c ^ 0x0002u)
                            : static_cast<std::uint16_t>(c ^ 0x0001u);
}

}  // namespace

Bytes pattern(std::size_t n, std::uint8_t seed) {
  Bytes p(n);
  for (std::size_t i = 0; i < n; ++i) {
    p[i] = static_cast<std::byte>((i + seed) & 0xffu);
  }
  return p;
}

Bytes ipv4(const IpSpec& ip, std::span<const std::byte> payload) {
  Bytes opts = ip.options;
  opts.resize((opts.size() + 3) / 4 * 4, std::byte{0});
  UTCP_CHECK(opts.size() <= 40);
  const std::size_t hlen = w::ipv4_header_len + opts.size();
  Bytes d(hlen + payload.size());
  const std::uint8_t version = ip.version.value_or(4);
  const std::uint8_t ihl = ip.ihl.value_or(static_cast<std::uint8_t>(hlen / 4));
  w::store_u8(d, 0, static_cast<std::uint8_t>((version << 4) | (ihl & 0x0fu)));
  w::store_u8(d, 1, ip.tos);
  w::store_be16(d, 2, ip.total_len.value_or(static_cast<std::uint16_t>(d.size())));
  w::store_be16(d, 4, ip.id);
  std::uint16_t ff = static_cast<std::uint16_t>(ip.frag_off & 0x1fffu);
  if (ip.df) {
    ff = static_cast<std::uint16_t>(ff | 0x4000u);
  }
  if (ip.mf) {
    ff = static_cast<std::uint16_t>(ff | 0x2000u);
  }
  w::store_be16(d, 6, ff);
  w::store_u8(d, 8, ip.ttl);
  w::store_u8(d, 9, ip.proto);
  w::store_be16(d, 10, 0);
  w::store_be32(d, 12, ip.src.v);
  w::store_be32(d, 16, ip.dst.v);
  std::copy(opts.begin(), opts.end(), d.begin() + static_cast<std::ptrdiff_t>(w::ipv4_header_len));
  std::uint16_t c = internet_checksum(std::span<const std::byte>(d).first(hlen));
  if (ip.corrupt_checksum) {
    c = corrupted(c);
  }
  w::store_be16(d, 10, c);
  std::copy(payload.begin(), payload.end(), d.begin() + static_cast<std::ptrdiff_t>(hlen));
  return d;
}

Bytes udp(const UdpSpec& u) {
  Bytes d(w::udp_header_len + u.payload.size());
  std::copy(u.payload.begin(), u.payload.end(),
            d.begin() + static_cast<std::ptrdiff_t>(w::udp_header_len));
  w::write_udp_header(d, w::UdpHeader{u.src.port, u.dst.port,
                                      u.len.value_or(static_cast<std::uint16_t>(d.size())), 0});
  if (u.checksum != UdpChecksum::none) {
    w::set_l4_checksum(d, u.src.addr, u.dst.addr, ip_proto_udp);
    if (u.checksum == UdpChecksum::corrupt) {
      w::store_be16(d, 6, corrupted(w::load_be16(d, 6)));
    }
  }
  return d;
}

Bytes udp_datagram(const UdpSpec& u) {
  IpSpec ip;
  ip.src = u.src.addr;
  ip.dst = u.dst.addr;
  ip.proto = ip_proto_udp;
  return ipv4(ip, udp(u));
}

Bytes tcp(const TcpSpec& t) {
  const bool syn = t.syn_layout || (t.flags & w::tcp_syn) != 0;
  const std::size_t hlen = w::tcp_header_len(t.opt, syn);
  Bytes d(hlen + t.payload.size());
  w::TcpHeader h;
  h.sport = t.src.port;
  h.dport = t.dst.port;
  h.seq = t.seq;
  h.ack = t.ack;
  h.window = t.window;
  h.urg = t.urg;
  h.flags = t.flags;
  w::write_tcp_header(d, h, t.opt, syn);
  std::copy(t.payload.begin(), t.payload.end(), d.begin() + static_cast<std::ptrdiff_t>(hlen));
  w::set_l4_checksum(d, t.src.addr, t.dst.addr, ip_proto_tcp);
  if (t.corrupt_checksum) {
    w::store_be16(d, 16, corrupted(w::load_be16(d, 16)));
  }
  return d;
}

Bytes tcp_datagram(const TcpSpec& t) {
  IpSpec ip;
  ip.src = t.src.addr;
  ip.dst = t.dst.addr;
  ip.proto = ip_proto_tcp;
  return ipv4(ip, tcp(t));
}

Bytes icmp(std::uint8_t type, std::uint8_t code, std::uint32_t rest,
           std::span<const std::byte> body, bool corrupt_checksum) {
  Bytes m(w::icmp_header_len + body.size());
  std::copy(body.begin(), body.end(), m.begin() + static_cast<std::ptrdiff_t>(w::icmp_header_len));
  w::write_icmp(m, w::IcmpHeader{type, code, 0, rest});
  if (corrupt_checksum) {
    w::store_be16(m, 2, corrupted(w::load_be16(m, 2)));
  }
  return m;
}

Bytes icmp_echo_request(Ipv4Addr src, Ipv4Addr dst, std::uint16_t id, std::uint16_t seq,
                        std::span<const std::byte> payload) {
  IpSpec ip;
  ip.src = src;
  ip.dst = dst;
  ip.proto = ip_proto_icmp;
  return ipv4(ip, icmp(w::icmp_echo_request, 0, (std::uint32_t{id} << 16) | seq, payload));
}

Bytes icmp_error(Ipv4Addr src, Ipv4Addr dst, std::uint8_t type, std::uint8_t code,
                 std::uint32_t rest, std::span<const std::byte> offending,
                 std::optional<std::size_t> quote_len) {
  const std::size_t n = std::min(quote_len.value_or(offending.size()), offending.size());
  IpSpec ip;
  ip.src = src;
  ip.dst = dst;
  ip.proto = ip_proto_icmp;
  return ipv4(ip, icmp(type, code, rest, offending.first(n)));
}

Bytes raw_datagram(Ipv4Addr src, Ipv4Addr dst, std::uint8_t proto,
                   std::span<const std::byte> payload) {
  IpSpec ip;
  ip.src = src;
  ip.dst = dst;
  ip.proto = proto;
  return ipv4(ip, payload);
}

void fix_checksums(std::span<std::byte> d, bool fixing_l4) {
  UTCP_CHECK(d.size() >= w::ipv4_header_len);
  const std::size_t hlen = std::size_t{w::load_u8(d, 0) & 0x0fu} * 4;
  const std::size_t total = w::load_be16(d, 2);
  UTCP_CHECK(hlen >= w::ipv4_header_len && hlen <= total && total <= d.size());
  w::store_be16(d, 10, 0);
  w::store_be16(d, 10, internet_checksum(d.first(hlen)));
  if (!fixing_l4) {
    return;
  }
  const std::span<std::byte> l4 = d.subspan(hlen, total - hlen);
  const Ipv4Addr src{w::load_be32(d, 12)};
  const Ipv4Addr dst{w::load_be32(d, 16)};
  switch (w::load_u8(d, 9)) {
    case ip_proto_tcp:
      if (l4.size() >= w::tcp_header_min_len) {
        w::set_l4_checksum(l4, src, dst, ip_proto_tcp);
      }
      break;
    case ip_proto_udp:
      if (l4.size() >= w::udp_header_len && w::load_be16(l4, 6) != 0) {
        w::set_l4_checksum(l4, src, dst, ip_proto_udp);
      }
      break;
    case ip_proto_icmp:
      if (l4.size() >= w::icmp_header_len) {
        w::store_be16(l4, 2, 0);
        w::store_be16(l4, 2, internet_checksum(l4));
      }
      break;
    default:
      break;
  }
}

}  // namespace utcp::test
