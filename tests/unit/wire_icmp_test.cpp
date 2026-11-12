#include "core/wire/icmp.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "core/wire/ipv4.hpp"
#include "core/wire/udp.hpp"
#include "utcp/checksum.hpp"

namespace {

using utcp::Ipv4Addr;
using utcp::wire::IcmpHeader;
using utcp::wire::ParseError;
using utcp::wire::parse_icmp;
using utcp::wire::parse_icmp_quote;
namespace w = utcp::wire;

const Ipv4Addr us = Ipv4Addr::from_octets(198, 18, 0, 2);
const Ipv4Addr peer = Ipv4Addr::from_octets(198, 19, 1, 2);

std::vector<std::byte> message(const IcmpHeader& h, std::span<const std::byte> body) {
  std::vector<std::byte> m(8 + body.size());
  std::copy(body.begin(), body.end(), m.begin() + 8);
  w::write_icmp(m, h);
  return m;
}

// An IPv4/UDP datagram from `peer` to `us`.
std::vector<std::byte> udp_datagram(std::size_t payload) {
  std::vector<std::byte> d(28 + payload, std::byte{0x5a});
  w::write_udp_header(std::span(d).subspan(20),
                      w::UdpHeader{40000, 7, static_cast<std::uint16_t>(8 + payload), 0});
  w::set_l4_checksum(std::span(d).subspan(20), peer, us, utcp::ip_proto_udp);
  w::Ipv4Header h;
  h.ttl = 64;
  h.proto = utcp::ip_proto_udp;
  h.total_len = static_cast<std::uint16_t>(d.size());
  h.id = 77;
  h.df = true;
  h.src = peer;
  h.dst = us;
  w::write_ipv4(d, h);
  return d;
}

TEST(WireIcmp, EchoRoundTrip) {
  const std::vector<std::byte> payload(56, std::byte{0x42});
  for (const std::uint8_t type : {w::icmp_echo_request, w::icmp_echo_reply}) {
    const auto m = message(w::icmp_echo_header(type, 0x1234, 7), payload);
    EXPECT_TRUE(utcp::checksum_valid(m));
    const auto v = parse_icmp(m, true);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->h.type, type);
    EXPECT_EQ(v->h.code, 0);
    EXPECT_EQ(v->h.echo_id(), 0x1234);
    EXPECT_EQ(v->h.echo_seq(), 7);
    EXPECT_EQ(std::vector<std::byte>(v->body.begin(), v->body.end()), payload);
    // Serialising the parsed header gives the same bytes.
    EXPECT_EQ(message(v->h, v->body), m);
  }
}

TEST(WireIcmp, EchoRequestBytes) {
  // Type 8, code 0, id 1, seq 1, payload "abcd": checksum by hand
  // (RFC 1071): 0x0800 + 0x0001 + 0x0001 + 0x6162 + 0x6364 = 0xccc8, ~ = 0x3337.
  const std::vector<std::byte> body{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
  const auto m = message(w::icmp_echo_header(w::icmp_echo_request, 1, 1), body);
  const std::vector<std::byte> expect{std::byte{8},    std::byte{0},    std::byte{0x33},
                                      std::byte{0x37}, std::byte{0},    std::byte{1},
                                      std::byte{0},    std::byte{1},    std::byte{'a'},
                                      std::byte{'b'},  std::byte{'c'},  std::byte{'d'}};
  EXPECT_EQ(m, expect);
}

TEST(WireIcmp, PortUnreachableQuotesTheDatagram) {
  const auto original = udp_datagram(100);
  // RFC 1812 §4.3.2.3: quote as much as fits in 576 bytes.
  const std::size_t quote = std::min(original.size(), w::icmp_max_quote);
  EXPECT_EQ(w::icmp_max_quote, 548u);
  const auto m = message(w::icmp_unreach_header(w::icmp_port_unreach),
                         std::span(original).first(quote));
  const auto v = parse_icmp(m, true);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->h.type, w::icmp_dest_unreach);
  EXPECT_EQ(v->h.code, w::icmp_port_unreach);
  EXPECT_EQ(v->h.rest, 0u);
  const auto q = parse_icmp_quote(v->body);
  ASSERT_TRUE(q.has_value());
  EXPECT_EQ(q->ihl, 5);
  EXPECT_EQ(q->ip.src, peer);
  EXPECT_EQ(q->ip.dst, us);
  EXPECT_EQ(q->ip.proto, utcp::ip_proto_udp);
  EXPECT_EQ(q->ip.id, 77);
  EXPECT_TRUE(q->ip.df);
  EXPECT_EQ(q->ip.total_len, 128);
  ASSERT_EQ(q->l4.size(), 108u);
  EXPECT_EQ(w::load_be16(q->l4, 0), 40000);
  EXPECT_EQ(w::load_be16(q->l4, 2), 7);
}

TEST(WireIcmp, FragNeededCarriesTheNextHopMtu) {
  const auto original = udp_datagram(1472);
  // Only the first 28 bytes quoted (IPv4 header + 8), as many routers do.
  const auto m =
      message(w::icmp_unreach_header(w::icmp_frag_needed, 1400), std::span(original).first(28));
  const auto v = parse_icmp(m, true);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->h.code, w::icmp_frag_needed);
  EXPECT_EQ(v->h.next_hop_mtu(), 1400);
  EXPECT_EQ(w::load_be32(m, 4), 1400u);  // unused high half zero (RFC 1191 §4)
  const auto q = parse_icmp_quote(v->body);
  ASSERT_TRUE(q.has_value());
  EXPECT_EQ(q->ip.total_len, 1500);  // quoted header fields are not checked against the quote
  EXPECT_EQ(q->l4.size(), 8u);
}

TEST(WireIcmp, Malformed) {
  const std::vector<std::byte> payload(8, std::byte{1});
  auto m = message(w::icmp_echo_header(w::icmp_echo_request, 9, 9), payload);
  EXPECT_EQ(parse_icmp(std::span(m).first(7), false).error(), ParseError::truncated);
  m[9] ^= std::byte{0x10};
  EXPECT_EQ(parse_icmp(m, true).error(), ParseError::bad_checksum);
  EXPECT_TRUE(parse_icmp(m, false).has_value());

  const auto original = udp_datagram(20);
  // Quote shorter than IPv4 header + 8 bytes.
  EXPECT_EQ(parse_icmp_quote(std::span(original).first(27)).error(), ParseError::truncated);
  EXPECT_EQ(parse_icmp_quote(std::span(original).first(19)).error(), ParseError::truncated);
  ASSERT_TRUE(parse_icmp_quote(std::span(original).first(28)).has_value());
  // IHL 6 needs 24 + 8 bytes.
  auto ihl6 = std::vector<std::byte>(original.begin(), original.begin() + 31);
  ihl6[0] = std::byte{0x46};
  EXPECT_EQ(parse_icmp_quote(ihl6).error(), ParseError::truncated);
  ihl6[0] = std::byte{0x44};
  EXPECT_EQ(parse_icmp_quote(ihl6).error(), ParseError::bad_ihl);
  ihl6[0] = std::byte{0x65};
  EXPECT_EQ(parse_icmp_quote(ihl6).error(), ParseError::bad_version);
}

}  // namespace
