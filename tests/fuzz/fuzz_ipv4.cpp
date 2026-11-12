// libFuzzer target for the wire formats (DESIGN §11, Fuzz): every input is
// parsed as an IPv4 datagram and, on its own, as a TCP segment, a UDP
// datagram and an ICMP message (checksums not verified, so the parsers past
// the checksum are reached). Whatever parses is written again with our
// writers and parsed back; the second parse must equal the first, after
// normalising what the writers do not reproduce (IP options, TCP options
// outside the §4.5 layout). A mismatch aborts through UTCP_CHECK.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "core/wire/udp.hpp"
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace {

namespace w = utcp::wire;
using utcp::Ipv4Addr;

const Ipv4Addr src_addr = Ipv4Addr::from_octets(198, 18, 0, 2);
const Ipv4Addr dst_addr = Ipv4Addr::from_octets(198, 19, 1, 3);

bool same_bytes(std::span<const std::byte> a, std::span<const std::byte> b) {
  return std::ranges::equal(a, b);
}

// The options write_tcp_header emits for `opt`.
w::TcpOptions written_options(const w::TcpOptions& opt, bool syn) {
  w::TcpOptions n;
  n.ts = opt.ts;
  if (syn) {
    n.mss = opt.mss;
    n.wscale = opt.wscale;
    n.sack_permitted = opt.sack_permitted;
  } else {
    n.sack_count = opt.sack_count;
    std::copy_n(opt.sack.begin(), opt.sack_count, n.sack.begin());
  }
  return n;
}

void tcp_round_trip(std::span<const std::byte> seg, Ipv4Addr src, Ipv4Addr dst) {
  const auto v = w::parse_tcp(seg, src, dst, false);
  if (!v) {
    return;
  }
  // Unused SACK entries are zero, so TcpOptions equality is meaningful.
  for (std::size_t i = v->opt.sack_count; i < v->opt.sack.size(); ++i) {
    UTCP_CHECK(v->opt.sack[i].first.raw() == 0 && v->opt.sack[i].second.raw() == 0);
  }
  const bool syn = (v->h.flags & w::tcp_syn) != 0;
  const w::TcpOptions want = written_options(v->opt, syn);
  const std::size_t hlen = w::tcp_header_len(want, syn);
  UTCP_CHECK(hlen <= w::tcp_header_max_len);
  if (hlen + v->payload.size() > 0xffff) {
    return;
  }
  std::vector<std::byte> buf(hlen + v->payload.size());
  w::write_tcp_header(buf, v->h, want, syn);
  std::ranges::copy(v->payload, buf.begin() + static_cast<std::ptrdiff_t>(hlen));
  w::set_l4_checksum(buf, src, dst, utcp::ip_proto_tcp);
  const auto r = w::parse_tcp(buf, src, dst, true);
  UTCP_CHECK(r.has_value());
  UTCP_CHECK(r->h == v->h);
  UTCP_CHECK(r->opt == want);
  UTCP_CHECK(std::size_t{r->data_offset} * 4 == hlen);
  UTCP_CHECK(same_bytes(r->payload, v->payload));
}

void udp_round_trip(std::span<const std::byte> d, Ipv4Addr src, Ipv4Addr dst) {
  const auto v = w::parse_udp(d, src, dst, false);
  if (!v) {
    return;
  }
  UTCP_CHECK(v->h.len >= w::udp_header_len && v->h.len <= d.size());
  UTCP_CHECK(v->payload.size() + w::udp_header_len == v->h.len);
  std::vector<std::byte> buf(v->h.len);
  w::write_udp_header(buf, v->h);
  std::ranges::copy(v->payload, buf.begin() + w::udp_header_len);
  w::set_l4_checksum(buf, src, dst, utcp::ip_proto_udp);
  const auto r = w::parse_udp(buf, src, dst, true);
  UTCP_CHECK(r.has_value());
  UTCP_CHECK(r->h.sport == v->h.sport && r->h.dport == v->h.dport && r->h.len == v->h.len);
  UTCP_CHECK(r->h.csum != 0);  // a computed 0 is sent as 0xFFFF (RFC 768)
  UTCP_CHECK(same_bytes(r->payload, v->payload));
}

void icmp_round_trip(std::span<const std::byte> m) {
  const auto v = w::parse_icmp(m, false);
  if (!v) {
    return;
  }
  UTCP_CHECK(v->body.size() + 8 == m.size());
  std::vector<std::byte> buf(m.size());
  std::ranges::copy(v->body, buf.begin() + 8);
  w::write_icmp(buf, v->h);
  const auto r = w::parse_icmp(buf, true);
  UTCP_CHECK(r.has_value());
  UTCP_CHECK(r->h.type == v->h.type && r->h.code == v->h.code && r->h.rest == v->h.rest);
  UTCP_CHECK(same_bytes(r->body, v->body));

  // The quoted datagram of an error, rebuilt without IP options.
  const auto q = w::parse_icmp_quote(v->body);
  if (!q) {
    return;
  }
  UTCP_CHECK(q->l4.size() >= 8);
  std::vector<std::byte> qb(w::ipv4_header_len + q->l4.size());
  w::write_ipv4(qb, q->ip);
  std::ranges::copy(q->l4, qb.begin() + w::ipv4_header_len);
  const auto rq = w::parse_icmp_quote(qb);
  UTCP_CHECK(rq.has_value());
  UTCP_CHECK(rq->ip == q->ip && rq->ihl == 5);
  UTCP_CHECK(same_bytes(rq->l4, q->l4));
}

void ipv4_round_trip(std::span<const std::byte> d) {
  const auto v = w::parse_ipv4(d);
  if (!v) {
    return;
  }
  UTCP_CHECK(v->ihl >= 5 && std::size_t{v->ihl} * 4 + v->payload.size() == v->h.total_len);
  UTCP_CHECK(!v->h.mf && v->h.frag_off == 0);
  w::Ipv4Header h = v->h;
  h.total_len = static_cast<std::uint16_t>(w::ipv4_header_len + v->payload.size());
  std::vector<std::byte> buf(h.total_len);
  w::write_ipv4(buf, h);
  std::ranges::copy(v->payload, buf.begin() + w::ipv4_header_len);
  const auto r = w::parse_ipv4(buf);
  UTCP_CHECK(r.has_value());
  UTCP_CHECK(r->h == h && r->ihl == 5);
  UTCP_CHECK(same_bytes(r->payload, v->payload));

  switch (v->h.proto) {
    case utcp::ip_proto_tcp: tcp_round_trip(v->payload, v->h.src, v->h.dst); break;
    case utcp::ip_proto_udp: udp_round_trip(v->payload, v->h.src, v->h.dst); break;
    case utcp::ip_proto_icmp: icmp_round_trip(v->payload); break;
    default: break;
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const auto in = std::as_bytes(std::span(data, std::min<std::size_t>(size, 0xffff)));
  ipv4_round_trip(in);
  tcp_round_trip(in, src_addr, dst_addr);
  udp_round_trip(in, src_addr, dst_addr);
  icmp_round_trip(in);
  return 0;
}
