#include "core/wire/ipv4.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "utcp/checksum.hpp"
#include "utcp/random.hpp"

namespace {

using utcp::Ipv4Addr;
using utcp::wire::Ipv4Header;
using utcp::wire::ParseError;
using utcp::wire::parse_ipv4;
using utcp::wire::write_ipv4;

std::vector<std::byte> from_hex(std::string_view hex) {
  std::vector<std::byte> out;
  int hi = -1;
  for (const char c : hex) {
    int v = -1;
    if (c >= '0' && c <= '9') {
      v = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      v = c - 'a' + 10;
    }
    if (v < 0) {
      continue;  // spaces
    }
    if (hi < 0) {
      hi = v;
    } else {
      out.push_back(static_cast<std::byte>(hi * 16 + v));
      hi = -1;
    }
  }
  return out;
}

// The IPv4 header of the Linux 7.0 SYN in wire_tcp_test.cpp (capture command there).
constexpr std::string_view linux_syn_hex =
    "4500 003c bd3d 4000 4006 2557 ac11 0004 ac11 0001"
    "e782 0009 b5ff 3222 0000 0000 a002 faf0 1a0d 0000"
    "0204 05b4 0402 080a a3ff 672a 0000 0000 0103 030a";

Ipv4Header sample_header(std::uint16_t total_len) {
  Ipv4Header h;
  h.tos = 0x10;
  h.ttl = 64;
  h.proto = utcp::ip_proto_udp;
  h.total_len = total_len;
  h.id = 0x1234;
  h.df = true;
  h.src = Ipv4Addr::from_octets(198, 18, 0, 2);
  h.dst = Ipv4Addr::from_octets(198, 19, 1, 2);
  return h;
}

std::vector<std::byte> datagram(const Ipv4Header& h, std::size_t payload_len) {
  std::vector<std::byte> d(20 + payload_len);
  for (std::size_t i = 0; i < payload_len; ++i) {
    d[20 + i] = static_cast<std::byte>(i * 7 + 1);
  }
  write_ipv4(d, h);
  return d;
}

TEST(WireIpv4, ParsesTheLinuxSynHeader) {
  const auto d = from_hex(linux_syn_hex);
  ASSERT_EQ(d.size(), 60u);
  const auto v = parse_ipv4(d);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->ihl, 5);
  EXPECT_EQ(v->h.tos, 0);
  EXPECT_EQ(v->h.ttl, 64);
  EXPECT_EQ(v->h.proto, utcp::ip_proto_tcp);
  EXPECT_EQ(v->h.total_len, 60);
  EXPECT_EQ(v->h.id, 0xbd3d);
  EXPECT_TRUE(v->h.df);
  EXPECT_FALSE(v->h.mf);
  EXPECT_EQ(v->h.frag_off, 0);
  EXPECT_EQ(v->h.src, Ipv4Addr::from_octets(172, 17, 0, 4));
  EXPECT_EQ(v->h.dst, Ipv4Addr::from_octets(172, 17, 0, 1));
  EXPECT_EQ(v->payload.size(), 40u);
  EXPECT_EQ(v->payload.data(), d.data() + 20);

  // Writing the parsed header gives Linux's bytes, checksum 0x2557 included.
  std::vector<std::byte> out(20);
  write_ipv4(out, v->h);
  EXPECT_EQ(out, std::vector<std::byte>(d.begin(), d.begin() + 20));
}

TEST(WireIpv4, RoundTrip) {
  const Ipv4Header h = sample_header(20 + 100);
  const auto d = datagram(h, 100);
  EXPECT_TRUE(utcp::checksum_valid(std::span(d).first(20)));
  const auto v = parse_ipv4(d);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->h, h);
  ASSERT_EQ(v->payload.size(), 100u);
  EXPECT_EQ(v->payload[99], static_cast<std::byte>(99 * 7 + 1));

  std::vector<std::byte> again(20);
  write_ipv4(again, v->h);
  EXPECT_EQ(again, std::vector<std::byte>(d.begin(), d.begin() + 20));
}

TEST(WireIpv4, RandomHeadersRoundTrip) {
  auto rng = utcp::Rng::derive(utcp::Seed::from_u64(1), "wire_ipv4");
  for (int i = 0; i < 2000; ++i) {
    Ipv4Header h;
    h.tos = static_cast<std::uint8_t>(rng.below(256));
    h.ttl = static_cast<std::uint8_t>(rng.below(256));
    h.proto = static_cast<std::uint8_t>(rng.below(256));
    const auto payload = rng.below(1481);
    h.total_len = static_cast<std::uint16_t>(20 + payload);
    h.id = static_cast<std::uint16_t>(rng.below(65536));
    h.df = rng.below(2) == 1;
    h.src = Ipv4Addr{static_cast<std::uint32_t>(rng.next())};
    h.dst = Ipv4Addr{static_cast<std::uint32_t>(rng.next())};
    const auto d = datagram(h, payload);
    const auto v = parse_ipv4(d);
    ASSERT_TRUE(v.has_value()) << i;
    EXPECT_EQ(v->h, h) << i;
    EXPECT_EQ(v->payload.size(), payload);
  }
}

TEST(WireIpv4, FragmentFieldsAreWrittenAndRejected) {
  Ipv4Header h = sample_header(28);
  h.mf = true;
  auto d = datagram(h, 8);
  EXPECT_EQ(utcp::wire::load_be16(d, 6), 0x6000);  // DF and MF
  EXPECT_EQ(parse_ipv4(d).error(), ParseError::fragment);

  h.mf = false;
  h.df = false;
  h.frag_off = 0x1fff;
  d = datagram(h, 8);
  EXPECT_EQ(utcp::wire::load_be16(d, 6), 0x1fff);
  EXPECT_EQ(parse_ipv4(d).error(), ParseError::fragment);

  h.frag_off = 1;
  d = datagram(h, 8);
  EXPECT_EQ(parse_ipv4(d).error(), ParseError::fragment);
}

TEST(WireIpv4, TrailingPaddingIsIgnored) {
  const Ipv4Header h = sample_header(20 + 6);
  auto d = datagram(h, 6);
  d.resize(46);  // Ethernet minimum frame padding
  const auto v = parse_ipv4(d);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->payload.size(), 6u);
}

TEST(WireIpv4, OptionsAreSkipped) {
  // IHL 6 with one NOP, NOP, NOP, EOL word; the checksum covers it.
  auto d = from_hex("4600 001c 0001 4000 4011 0000 c612 0002 c613 0102 0101 0100 dead beef");
  utcp::wire::store_be16(d, 10, utcp::internet_checksum(std::span(d).first(24)));
  const auto v = parse_ipv4(d);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->ihl, 6);
  ASSERT_EQ(v->payload.size(), 4u);
  EXPECT_EQ(v->payload[0], std::byte{0xde});
}

TEST(WireIpv4, Malformed) {
  const Ipv4Header h = sample_header(20 + 8);
  const auto good = datagram(h, 8);
  ASSERT_TRUE(parse_ipv4(good).has_value());

  // Shorter than the fixed header.
  EXPECT_EQ(parse_ipv4(std::span(good).first(19)).error(), ParseError::truncated);
  EXPECT_EQ(parse_ipv4({}).error(), ParseError::truncated);

  auto patch = [&](std::size_t at, std::uint8_t value, bool fix_checksum) {
    auto d = good;
    d[at] = std::byte{value};
    if (fix_checksum) {
      utcp::wire::store_be16(d, 10, 0);
      utcp::wire::store_be16(d, 10, utcp::internet_checksum(std::span(d).first(20)));
    }
    return d;
  };
  // Version 6.
  EXPECT_EQ(parse_ipv4(patch(0, 0x65, true)).error(), ParseError::bad_version);
  // IHL < 5.
  EXPECT_EQ(parse_ipv4(patch(0, 0x44, true)).error(), ParseError::bad_ihl);
  EXPECT_EQ(parse_ipv4(patch(0, 0x40, true)).error(), ParseError::bad_ihl);
  // IHL 15 (60 bytes) in a 28-byte buffer.
  EXPECT_EQ(parse_ipv4(patch(0, 0x4f, false)).error(), ParseError::truncated);
  // Bad header checksum: one bit flipped in the TTL.
  EXPECT_EQ(parse_ipv4(patch(8, 65, false)).error(), ParseError::bad_checksum);
  // Total length larger than the buffer.
  EXPECT_EQ(parse_ipv4(patch(3, 29, true)).error(), ParseError::truncated);
  // Total length smaller than the header.
  EXPECT_EQ(parse_ipv4(patch(3, 19, true)).error(), ParseError::bad_length);
  // Total length 20: no payload, valid.
  const auto empty = parse_ipv4(patch(3, 20, true));
  ASSERT_TRUE(empty.has_value());
  EXPECT_TRUE(empty->payload.empty());
}

TEST(WireIpv4, ByteOrderHelpers) {
  std::vector<std::byte> b(8);
  utcp::wire::store_be32(b, 0, 0x0102'0304);
  utcp::wire::store_be16(b, 4, 0xa0b0);
  utcp::wire::store_u8(b, 6, 0xff);
  EXPECT_EQ(b, from_hex("0102 0304 a0b0 ff00"));
  EXPECT_EQ(utcp::wire::load_be32(b, 0), 0x0102'0304u);
  EXPECT_EQ(utcp::wire::load_be16(b, 1), 0x0203);
  EXPECT_EQ(utcp::wire::load_u8(b, 6), 0xff);
  EXPECT_EQ(utcp::wire::to_string(ParseError::bad_data_offset), "bad_data_offset");
}

}  // namespace
