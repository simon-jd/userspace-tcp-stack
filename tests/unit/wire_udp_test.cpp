#include "core/wire/udp.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "core/wire/ipv4.hpp"
#include "utcp/checksum.hpp"

namespace {

using utcp::Ipv4Addr;
using utcp::wire::ParseError;
using utcp::wire::parse_udp;
using utcp::wire::UdpHeader;
namespace w = utcp::wire;

const Ipv4Addr src = Ipv4Addr::from_octets(198, 18, 0, 2);
const Ipv4Addr dst = Ipv4Addr::from_octets(198, 19, 1, 2);

std::vector<std::byte> datagram(std::uint16_t sport, std::uint16_t dport,
                                const std::vector<std::byte>& payload) {
  std::vector<std::byte> d(8 + payload.size());
  std::copy(payload.begin(), payload.end(), d.begin() + 8);
  w::write_udp_header(d, UdpHeader{sport, dport, static_cast<std::uint16_t>(d.size()), 0});
  w::set_l4_checksum(d, src, dst, utcp::ip_proto_udp);
  return d;
}

std::vector<std::byte> pattern(std::size_t n) {
  std::vector<std::byte> p(n);
  for (std::size_t i = 0; i < n; ++i) {
    p[i] = static_cast<std::byte>(i * 11 + 3);
  }
  return p;
}

TEST(WireUdp, RoundTrip) {
  for (const std::size_t n : {0u, 1u, 2u, 1472u}) {
    const auto d = datagram(5353, 53, pattern(n));
    const auto v = parse_udp(d, src, dst, true);
    ASSERT_TRUE(v.has_value()) << n;
    EXPECT_EQ(v->h.sport, 5353);
    EXPECT_EQ(v->h.dport, 53);
    EXPECT_EQ(v->h.len, 8 + n);
    EXPECT_NE(v->h.csum, 0);
    EXPECT_EQ(std::vector<std::byte>(v->payload.begin(), v->payload.end()), pattern(n));
    EXPECT_TRUE(utcp::ipv4_transport_checksum_valid(src.v, dst.v, utcp::ip_proto_udp, d));
  }
}

TEST(WireUdp, ComputedZeroChecksumIsSentAsFfff) {
  // Choose the last two payload bytes so that the one's-complement sum of the
  // pseudo-header and datagram is 0xFFFF: the computed checksum is then 0.
  auto d = datagram(1000, 2000, pattern(10));
  w::store_be16(d, 6, 0);
  w::store_be16(d, 16, 0);
  const std::uint16_t c = utcp::ipv4_transport_checksum(src.v, dst.v, utcp::ip_proto_udp, d);
  // Adding the complement of the current sum's complement turns the sum into 0xFFFF.
  w::store_be16(d, 16, c);
  ASSERT_EQ(utcp::ipv4_transport_checksum(src.v, dst.v, utcp::ip_proto_udp, d), 0);
  w::set_l4_checksum(d, src, dst, utcp::ip_proto_udp);
  EXPECT_EQ(w::load_be16(d, 6), 0xffff);
  const auto v = parse_udp(d, src, dst, true);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->h.csum, 0xffff);
}

TEST(WireUdp, ZeroChecksumMeansNone) {
  auto d = datagram(1, 2, pattern(20));
  w::store_be16(d, 6, 0);
  d.back() ^= std::byte{0x80};  // would fail a checksum, but there is none (RFC 768)
  const auto v = parse_udp(d, src, dst, true);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->h.csum, 0);
}

TEST(WireUdp, Malformed) {
  auto d = datagram(1, 2, pattern(20));
  ASSERT_TRUE(parse_udp(d, src, dst, true).has_value());
  EXPECT_EQ(parse_udp(std::span(d).first(7), src, dst, false).error(), ParseError::truncated);

  auto bad = d;
  bad[10] ^= std::byte{0x01};
  EXPECT_EQ(parse_udp(bad, src, dst, true).error(), ParseError::bad_checksum);
  EXPECT_TRUE(parse_udp(bad, src, dst, false).has_value());

  auto len = d;
  w::store_be16(len, 4, 7);
  EXPECT_EQ(parse_udp(len, src, dst, false).error(), ParseError::bad_length);
  w::store_be16(len, 4, 29);
  EXPECT_EQ(parse_udp(len, src, dst, false).error(), ParseError::bad_length);
}

TEST(WireUdp, BytesAfterTheLengthAreIgnored) {
  auto d = datagram(1, 2, pattern(4));
  d.push_back(std::byte{0xee});
  d.push_back(std::byte{0xee});
  const auto v = parse_udp(d, src, dst, true);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->payload.size(), 4u);
}

}  // namespace
