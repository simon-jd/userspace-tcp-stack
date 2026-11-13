#include "utcp/sim/datagram.hpp"

#include <algorithm>
#include <utility>

#include "utcp/checksum.hpp"

namespace utcp::sim {
namespace {

std::vector<std::byte> finish_ipv4(std::vector<std::byte> d, std::uint8_t proto, Ipv4Addr src,
                                   Ipv4Addr dst, std::uint16_t ip_id, bool df, std::uint8_t ttl,
                                   std::uint8_t tos = 0) {
  wire::Ipv4Header ip;
  ip.tos = tos;
  ip.ttl = ttl;
  ip.proto = proto;
  ip.total_len = static_cast<std::uint16_t>(d.size());
  ip.id = ip_id;
  ip.df = df;
  ip.src = src;
  ip.dst = dst;
  wire::write_ipv4(std::span<std::byte>(d).first(wire::ipv4_header_len), ip);
  return d;
}

}  // namespace

std::vector<std::byte> build_tcp(const TcpSegmentSpec& s) {
  const bool syn = (s.flags & wire::tcp_syn) != 0;
  const std::size_t hl = wire::tcp_header_len(s.opt, syn);
  std::vector<std::byte> d(wire::ipv4_header_len + hl + s.payload.size());
  const auto l4 = std::span<std::byte>(d).subspan(wire::ipv4_header_len);
  wire::TcpHeader h;
  h.sport = s.src.port;
  h.dport = s.dst.port;
  h.seq = Seq32(s.seq);
  h.ack = Seq32(s.ack);
  h.window = s.window;
  h.flags = s.flags;
  wire::write_tcp_header(l4, h, s.opt, syn);
  std::copy(s.payload.begin(), s.payload.end(), l4.begin() + static_cast<std::ptrdiff_t>(hl));
  wire::set_l4_checksum(l4, s.src.addr, s.dst.addr, ip_proto_tcp);
  return finish_ipv4(std::move(d), ip_proto_tcp, s.src.addr, s.dst.addr, s.ip_id, s.df, s.ttl);
}

std::vector<std::byte> build_udp(Endpoint src, Endpoint dst, std::span<const std::byte> payload,
                                 std::uint16_t ip_id) {
  std::vector<std::byte> d(wire::ipv4_header_len + wire::udp_header_len + payload.size());
  const auto l4 = std::span<std::byte>(d).subspan(wire::ipv4_header_len);
  wire::UdpHeader h;
  h.sport = src.port;
  h.dport = dst.port;
  h.len = static_cast<std::uint16_t>(l4.size());
  wire::write_udp_header(l4, h);
  std::copy(payload.begin(), payload.end(), l4.begin() + wire::udp_header_len);
  wire::set_l4_checksum(l4, src.addr, dst.addr, ip_proto_udp);
  return finish_ipv4(std::move(d), ip_proto_udp, src.addr, dst.addr, ip_id, true, 64);
}

std::vector<std::byte> build_icmp_echo(Ipv4Addr src, Ipv4Addr dst, std::uint8_t type,
                                       std::uint16_t id, std::uint16_t seq,
                                       std::span<const std::byte> payload, std::uint16_t ip_id) {
  std::vector<std::byte> d(wire::ipv4_header_len + wire::icmp_header_len + payload.size());
  const auto msg = std::span<std::byte>(d).subspan(wire::ipv4_header_len);
  std::copy(payload.begin(), payload.end(), msg.begin() + wire::icmp_header_len);
  wire::write_icmp(msg, wire::icmp_echo_header(type, id, seq));
  return finish_ipv4(std::move(d), ip_proto_icmp, src, dst, ip_id, true, 64);
}

std::size_t write_frag_needed(std::span<std::byte> out, Ipv4Addr from,
                              std::span<const std::byte> offending, std::uint16_t next_hop_mtu,
                              std::uint16_t ip_id) {
  if (offending.size() < wire::ipv4_header_len ||
      (wire::load_u8(offending, 0) >> 4) != 4) {
    return 0;
  }
  const std::size_t quote = std::min(offending.size(), wire::icmp_max_quote);
  const std::size_t total = wire::ipv4_header_len + wire::icmp_header_len + quote;
  if (out.size() < total) {
    return 0;
  }
  const auto msg = out.subspan(wire::ipv4_header_len, wire::icmp_header_len + quote);
  std::copy_n(offending.begin(), quote, msg.begin() + wire::icmp_header_len);
  wire::write_icmp(msg, wire::icmp_unreach_header(wire::icmp_frag_needed, next_hop_mtu));
  wire::Ipv4Header ip;
  ip.tos = 0xc0;  // IPTOS_PREC_INTERNETCONTROL, as Linux icmp_send
  ip.ttl = 64;
  ip.proto = ip_proto_icmp;
  ip.total_len = static_cast<std::uint16_t>(total);
  ip.id = ip_id;
  ip.src = from;
  ip.dst = Ipv4Addr{wire::load_be32(offending, 12)};
  wire::write_ipv4(out.first(wire::ipv4_header_len), ip);
  return total;
}

std::vector<std::byte> build_frag_needed(Ipv4Addr from, std::span<const std::byte> offending,
                                         std::uint16_t next_hop_mtu, std::uint16_t ip_id) {
  std::vector<std::byte> out(576);
  out.resize(write_frag_needed(out, from, offending, next_hop_mtu, ip_id));
  return out;
}

bool checksums_valid(std::span<const std::byte> d) noexcept {
  if (d.size() < wire::ipv4_header_len) {
    return false;
  }
  const std::uint8_t vihl = wire::load_u8(d, 0);
  const std::size_t ihl = std::size_t{vihl & 0xfu} * 4;
  if ((vihl >> 4) != 4 || ihl < wire::ipv4_header_len || ihl > d.size()) {
    return false;
  }
  if (!checksum_valid(d.first(ihl))) {
    return false;
  }
  const std::size_t total = wire::load_be16(d, 2);
  if (total < ihl || total > d.size()) {
    return false;
  }
  const auto l4 = d.subspan(ihl, total - ihl);
  const std::uint32_t src = wire::load_be32(d, 12);
  const std::uint32_t dst = wire::load_be32(d, 16);
  switch (wire::load_u8(d, 9)) {
    case ip_proto_tcp:
      return ipv4_transport_checksum_valid(src, dst, ip_proto_tcp, l4);
    case ip_proto_udp:
      if (l4.size() < wire::udp_header_len) {
        return false;
      }
      return wire::load_be16(l4, 6) == 0 || ipv4_transport_checksum_valid(src, dst, ip_proto_udp, l4);
    case ip_proto_icmp:
      return checksum_valid(l4);
    default:
      return true;
  }
}

void fix_checksums(std::span<std::byte> d) noexcept {
  if (d.size() < wire::ipv4_header_len) {
    return;
  }
  const std::size_t ihl = std::size_t{wire::load_u8(d, 0) & 0xfu} * 4;
  if (ihl < wire::ipv4_header_len || ihl > d.size()) {
    return;
  }
  wire::store_be16(d, 10, 0);
  wire::store_be16(d, 10, internet_checksum(d.first(ihl)));
  const auto l4 = d.subspan(ihl);
  const std::uint32_t src = wire::load_be32(d, 12);
  const std::uint32_t dst = wire::load_be32(d, 16);
  switch (wire::load_u8(d, 9)) {
    case ip_proto_tcp:
      if (l4.size() >= 18) {
        wire::store_be16(l4, 16, 0);
        wire::store_be16(l4, 16, ipv4_transport_checksum(src, dst, ip_proto_tcp, l4));
      }
      break;
    case ip_proto_udp:
      if (l4.size() >= wire::udp_header_len) {
        wire::store_be16(l4, 4, static_cast<std::uint16_t>(l4.size()));
        wire::store_be16(l4, 6, 0);
        wire::store_be16(l4, 6, udp_checksum_ipv4(src, dst, l4));
      }
      break;
    case ip_proto_icmp:
      if (l4.size() >= 4) {
        wire::store_be16(l4, 2, 0);
        wire::store_be16(l4, 2, internet_checksum(l4));
      }
      break;
    default:
      break;
  }
}

std::optional<TcpPacket> parse_tcp_packet(std::span<const std::byte> datagram) noexcept {
  const auto ip = wire::parse_ipv4(datagram);
  if (!ip || ip->h.proto != ip_proto_tcp) {
    return std::nullopt;
  }
  const auto tcp = wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
  if (!tcp) {
    return std::nullopt;
  }
  return TcpPacket{ip->h, *tcp};
}

}  // namespace utcp::sim
