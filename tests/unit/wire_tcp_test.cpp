#include "core/wire/tcp.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "core/wire/ipv4.hpp"
#include "utcp/checksum.hpp"
#include "utcp/random.hpp"

namespace {

using utcp::Ipv4Addr;
using utcp::Seq32;
using utcp::wire::ParseError;
using utcp::wire::parse_tcp;
using utcp::wire::TcpHeader;
using utcp::wire::TcpOptions;
using utcp::wire::tcp_header_len;
using utcp::wire::Timestamps;
using utcp::wire::write_tcp_header;
namespace w = utcp::wire;

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
      continue;
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

// A SYN sent by Linux 7.0 (kernel 7.0.0-42-generic, home-ubuntu) from a
// container of the testbed image with the netns defaults tcp_sack=1,
// tcp_timestamps=1, tcp_window_scaling=1, tcp_ecn=2 and tcp_rmem max 33554432
// (hence wscale 10), captured on 2026-11-11 with:
//
//   docker run --rm --name utcp-m1-syncap --cpuset-cpus 16-31 --cap-add NET_ADMIN
//     -v "$PWD:/out" utcp-testbed:dev bash -c '
//       ethtool -K eth0 tx off   # checksum computed before tcpdump sees the packet
//       gw=$(ip route | awk "/^default/ {print \$3}")
//       tcpdump -i eth0 -w /out/linux70-syn.pcap -c 1
//         "tcp[tcpflags] & tcp-syn != 0 and dst port 9" &
//       sleep 1; timeout 2 bash -c "exec 3<>/dev/tcp/$gw/9" || true; wait
//       tcpdump -r /out/linux70-syn.pcap -nn -vv -x'
//
// (one shell command; the line breaks of the docker and first tcpdump lines
// are continuations). The SYN goes to the docker0 gateway's closed port 9,
// which answers with a RST.
//
// tcpdump: 172.17.0.4.59266 > 172.17.0.1.9: Flags [S], cksum 0x1a0d (correct),
// seq 3053400610, win 64240, options [mss 1460,sackOK,TS val 2751424298 ecr
// 0,nop,wscale 10], length 0. The bytes below are the IPv4 datagram (the
// 14-byte Ethernet header removed).
constexpr std::string_view linux_syn_hex =
    "4500 003c bd3d 4000 4006 2557 ac11 0004 ac11 0001"
    "e782 0009 b5ff 3222 0000 0000 a002 faf0 1a0d 0000"
    "0204 05b4 0402 080a a3ff 672a 0000 0000 0103 030a";

const Ipv4Addr src = Ipv4Addr::from_octets(198, 18, 0, 2);
const Ipv4Addr dst = Ipv4Addr::from_octets(198, 19, 1, 2);

// A complete segment: header with options, payload, checksum.
std::vector<std::byte> segment(const TcpHeader& h, const TcpOptions& opt, bool syn,
                               std::size_t payload_len = 0) {
  const std::size_t hlen = tcp_header_len(opt, syn);
  std::vector<std::byte> s(hlen + payload_len);
  for (std::size_t i = 0; i < payload_len; ++i) {
    s[hlen + i] = static_cast<std::byte>(i * 3 + 5);
  }
  write_tcp_header(s, h, opt, syn);
  w::set_l4_checksum(s, src, dst, utcp::ip_proto_tcp);
  return s;
}

// A segment with a hand-written option area (padded to a multiple of 4 with
// `pad`), valid checksum.
std::vector<std::byte> with_options(std::vector<std::byte> options, std::byte pad = std::byte{0}) {
  while (options.size() % 4 != 0) {
    options.push_back(pad);
  }
  std::vector<std::byte> s(20 + options.size());
  TcpHeader h;
  h.sport = 1;
  h.dport = 2;
  h.flags = w::tcp_ack;
  write_tcp_header(s, h, TcpOptions{}, false);
  w::store_u8(s, 12, static_cast<std::uint8_t>((s.size() / 4) << 4));
  std::copy(options.begin(), options.end(), s.begin() + 20);
  w::set_l4_checksum(s, src, dst, utcp::ip_proto_tcp);
  return s;
}

TcpOptions parse_opts(const std::vector<std::byte>& s) {
  const auto v = parse_tcp(s, src, dst, true);
  EXPECT_TRUE(v.has_value());
  return v ? v->opt : TcpOptions{};
}

TcpHeader sample_header(std::uint16_t flags) {
  TcpHeader h;
  h.sport = 40000;
  h.dport = 80;
  h.seq = Seq32(0xfffffff0u);
  h.ack = Seq32(0x12345678u);
  h.window = 501;
  h.urg = 0;
  h.flags = flags;
  return h;
}

TEST(WireTcp, ParsesTheLinuxSyn) {
  const auto d = from_hex(linux_syn_hex);
  const auto ip = w::parse_ipv4(d);
  ASSERT_TRUE(ip.has_value());
  const auto v = parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->h.sport, 59266);
  EXPECT_EQ(v->h.dport, 9);
  EXPECT_EQ(v->h.seq, Seq32(3053400610u));
  EXPECT_EQ(v->h.ack, Seq32(0));
  EXPECT_EQ(v->h.flags, w::tcp_syn);
  EXPECT_EQ(v->h.window, 64240);
  EXPECT_EQ(v->h.urg, 0);
  EXPECT_EQ(v->data_offset, 10);
  EXPECT_TRUE(v->payload.empty());
  EXPECT_EQ(v->opt.mss, 1460);
  EXPECT_TRUE(v->opt.sack_permitted);
  ASSERT_TRUE(v->opt.ts.has_value());
  EXPECT_EQ(v->opt.ts->val, 2751424298u);
  EXPECT_EQ(v->opt.ts->ecr, 0u);
  EXPECT_EQ(v->opt.wscale, 10);
  EXPECT_EQ(v->opt.sack_count, 0);
  EXPECT_FALSE(v->opt.malformed);
}

TEST(WireTcp, SynWriterMatchesLinuxByteForByte) {
  const auto d = from_hex(linux_syn_hex);
  const auto ip = w::parse_ipv4(d);
  ASSERT_TRUE(ip.has_value());
  const auto v = parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
  ASSERT_TRUE(v.has_value());

  // Rebuild the SYN from the values alone.
  TcpHeader h;
  h.sport = 59266;
  h.dport = 9;
  h.seq = Seq32(3053400610u);
  h.window = 64240;
  h.flags = w::tcp_syn;
  TcpOptions opt;
  opt.mss = 1460;
  opt.sack_permitted = true;
  opt.ts = Timestamps{2751424298u, 0};
  opt.wscale = 10;
  ASSERT_EQ(tcp_header_len(opt, true), 40u);
  std::vector<std::byte> out(40);
  write_tcp_header(out, h, opt, true);
  // MSS, SACK_PERM, TS, NOP, WS: the 20 option bytes equal Linux's.
  EXPECT_EQ(std::vector<std::byte>(out.begin() + 20, out.end()),
            std::vector<std::byte>(ip->payload.begin() + 20, ip->payload.end()));
  EXPECT_EQ(std::vector<std::byte>(out.begin() + 20, out.end()),
            from_hex("0204 05b4 0402 080a a3ff 672a 0000 0000 0103 030a"));
  // With the checksum the whole TCP header is Linux's.
  w::set_l4_checksum(out, ip->h.src, ip->h.dst, utcp::ip_proto_tcp);
  EXPECT_EQ(out, std::vector<std::byte>(ip->payload.begin(), ip->payload.end()));
}

TEST(WireTcp, SynLayoutWithoutTimestamps) {
  TcpOptions opt;
  opt.mss = 1460;
  opt.sack_permitted = true;
  opt.wscale = 7;
  const auto s = segment(sample_header(w::tcp_syn), opt, true);
  ASSERT_EQ(s.size(), 32u);
  // MSS, NOP, NOP, SACK_PERM, NOP, WS (Linux tcp_options_write).
  EXPECT_EQ(std::vector<std::byte>(s.begin() + 20, s.end()),
            from_hex("0204 05b4 0101 0402 0103 0307"));
  EXPECT_EQ(parse_opts(s), opt);
}

TEST(WireTcp, SynLayoutsOfEveryOptionSubset) {
  // Every combination of MSS, SACK-permitted, TS and WS on a SYN.
  for (int bits = 0; bits < 16; ++bits) {
    TcpOptions opt;
    if ((bits & 1) != 0) {
      opt.mss = 536;
    }
    opt.sack_permitted = (bits & 2) != 0;
    if ((bits & 4) != 0) {
      opt.ts = Timestamps{7, 9};
    }
    if ((bits & 8) != 0) {
      opt.wscale = 14;
    }
    const auto s = segment(sample_header(w::tcp_syn | w::tcp_ack), opt, true);
    const std::size_t expect_len = 20 + ((bits & 1) != 0 ? 4 : 0) + ((bits & 4) != 0 ? 12 : 0) +
                                   ((bits & 2) != 0 && (bits & 4) == 0 ? 4 : 0) +
                                   ((bits & 8) != 0 ? 4 : 0);
    EXPECT_EQ(s.size(), expect_len) << bits;
    EXPECT_EQ(parse_opts(s), opt) << bits;
  }
}

TEST(WireTcp, NonSynLayout) {
  TcpOptions opt;
  opt.ts = Timestamps{0x01020304, 0x05060708};
  opt.sack[0] = {Seq32(0x1000), Seq32(0x2000)};
  opt.sack[1] = {Seq32(0x3000), Seq32(0x4000)};
  opt.sack_count = 2;
  const auto s = segment(sample_header(w::tcp_ack), opt, false, 10);
  ASSERT_EQ(tcp_header_len(opt, false), 20u + 12u + 4u + 16u);
  // NOP, NOP, TS then NOP, NOP, SACK(2).
  EXPECT_EQ(std::vector<std::byte>(s.begin() + 20, s.begin() + 52),
            from_hex("0101 080a 0102 0304 0506 0708 0101 0512"
                     "0000 1000 0000 2000 0000 3000 0000 4000"));
  const auto v = parse_tcp(s, src, dst, true);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->opt, opt);
  EXPECT_EQ(v->h, sample_header(w::tcp_ack));
  ASSERT_EQ(v->payload.size(), 10u);
  EXPECT_EQ(v->payload[9], static_cast<std::byte>(9 * 3 + 5));
}

TEST(WireTcp, SynOnlyOptionsAreNotWrittenOnOtherSegments) {
  TcpOptions opt;
  opt.mss = 1460;
  opt.sack_permitted = true;
  opt.wscale = 7;
  opt.sack[0] = {Seq32(1), Seq32(2)};
  opt.sack_count = 1;
  // Not a SYN: only the SACK block.
  EXPECT_EQ(tcp_header_len(opt, false), 20u + 12u);
  TcpOptions expect_non_syn;
  expect_non_syn.sack = opt.sack;
  expect_non_syn.sack_count = 1;
  EXPECT_EQ(parse_opts(segment(sample_header(w::tcp_ack), opt, false)), expect_non_syn);
  // A SYN: no SACK blocks.
  TcpOptions expect_syn = opt;
  expect_syn.sack = {};
  expect_syn.sack_count = 0;
  EXPECT_EQ(parse_opts(segment(sample_header(w::tcp_syn), opt, true)), expect_syn);
}

TEST(WireTcp, MaximumHeaderLengths) {
  TcpOptions opt;
  opt.ts = Timestamps{1, 2};
  opt.sack_count = 3;
  EXPECT_EQ(tcp_header_len(opt, false), 60u);
  opt.ts.reset();
  opt.sack_count = 4;
  EXPECT_EQ(tcp_header_len(opt, false), 56u);
  for (std::uint8_t n = 1; n <= 4; ++n) {
    TcpOptions o;
    for (std::uint8_t i = 0; i < n; ++i) {
      o.sack[i] = {Seq32(100u * i), Seq32(100u * i + 50)};
    }
    o.sack_count = n;
    EXPECT_EQ(parse_opts(segment(sample_header(w::tcp_ack), o, false)), o);
  }
}

TEST(WireTcpDeathTest, TooManySackBlocksWithTimestamps) {
  TcpOptions opt;
  opt.ts = Timestamps{1, 2};
  opt.sack_count = 4;
  EXPECT_DEATH(static_cast<void>(tcp_header_len(opt, false)), "UTCP_CHECK");
}

TEST(WireTcp, FlagsRoundTripAllTwelveBits) {
  for (std::uint16_t flags = 0; flags <= w::tcp_all_flags; ++flags) {
    const auto s = segment(sample_header(flags), TcpOptions{}, false);
    ASSERT_EQ(s.size(), 20u);
    EXPECT_EQ(w::load_u8(s, 12), 0x50 | (flags >> 8));  // data offset 5, AE and reserved bits
    EXPECT_EQ(w::load_u8(s, 13), flags & 0xff);
    const auto v = parse_tcp(s, src, dst, true);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->h.flags, flags);
  }
  // AE alone, and the reserved bits alone.
  EXPECT_EQ(w::load_u8(segment(sample_header(w::tcp_ae), TcpOptions{}, false), 12), 0x51);
  EXPECT_EQ(w::load_u8(segment(sample_header(w::tcp_reserved_flags), TcpOptions{}, false), 12),
            0x5e);
}

TEST(WireTcp, RandomRoundTrip) {
  auto rng = utcp::Rng::derive(utcp::Seed::from_u64(2), "wire_tcp");
  for (int i = 0; i < 5000; ++i) {
    TcpHeader h;
    h.sport = static_cast<std::uint16_t>(rng.below(65536));
    h.dport = static_cast<std::uint16_t>(rng.below(65536));
    h.seq = Seq32(static_cast<std::uint32_t>(rng.next()));
    h.ack = Seq32(static_cast<std::uint32_t>(rng.next()));
    h.window = static_cast<std::uint16_t>(rng.below(65536));
    h.urg = static_cast<std::uint16_t>(rng.below(65536));
    h.flags = static_cast<std::uint16_t>(rng.below(4096));
    const bool syn = rng.below(2) == 1;
    TcpOptions opt;
    if (rng.below(2) == 1) {
      opt.ts = Timestamps{static_cast<std::uint32_t>(rng.next()),
                          static_cast<std::uint32_t>(rng.next())};
    }
    if (syn) {
      if (rng.below(2) == 1) {
        opt.mss = static_cast<std::uint16_t>(rng.below(65536));
      }
      if (rng.below(2) == 1) {
        opt.wscale = static_cast<std::uint8_t>(rng.below(256));
      }
      opt.sack_permitted = rng.below(2) == 1;
    } else {
      opt.sack_count = static_cast<std::uint8_t>(rng.below(opt.ts ? 4 : 5));
      for (std::uint8_t b = 0; b < opt.sack_count; ++b) {
        opt.sack[b] = {Seq32(static_cast<std::uint32_t>(rng.next())),
                       Seq32(static_cast<std::uint32_t>(rng.next()))};
      }
    }
    const auto payload = rng.below(100);
    const auto s = segment(h, opt, syn, payload);
    const auto v = parse_tcp(s, src, dst, true);
    ASSERT_TRUE(v.has_value()) << i;
    EXPECT_EQ(v->h, h) << i;
    EXPECT_EQ(v->opt, opt) << i;
    EXPECT_EQ(v->payload.size(), payload) << i;
    EXPECT_EQ(v->data_offset * 4u, tcp_header_len(opt, syn)) << i;
  }
}

TEST(WireTcp, ChecksumAndLengthErrors) {
  TcpOptions opt;
  opt.ts = Timestamps{1, 2};
  auto s = segment(sample_header(w::tcp_ack | w::tcp_psh), opt, false, 33);
  ASSERT_TRUE(parse_tcp(s, src, dst, true).has_value());
  // Wrong pseudo-header address.
  EXPECT_EQ(parse_tcp(s, src, Ipv4Addr{dst.v + 1}, true).error(), ParseError::bad_checksum);
  // A flipped payload bit; accepted when the checksum is not verified
  // (RxMeta::csum_verified).
  s.back() ^= std::byte{0x01};
  EXPECT_EQ(parse_tcp(s, src, dst, true).error(), ParseError::bad_checksum);
  EXPECT_TRUE(parse_tcp(s, src, dst, false).has_value());

  // Shorter than 20 bytes.
  EXPECT_EQ(parse_tcp(std::span(s).first(19), src, dst, false).error(), ParseError::truncated);
  // Data offset below 5.
  for (std::uint8_t doff = 0; doff < 5; ++doff) {
    auto t = s;
    w::store_u8(t, 12, static_cast<std::uint8_t>(doff << 4));
    EXPECT_EQ(parse_tcp(t, src, dst, false).error(), ParseError::bad_data_offset) << int{doff};
  }
  // Data offset beyond the segment: 15 words in a 20-byte segment, and 8
  // words (32 bytes) in a 31-byte one.
  auto bare = segment(sample_header(w::tcp_ack), TcpOptions{}, false);
  w::store_u8(bare, 12, 0xf0);
  EXPECT_EQ(parse_tcp(bare, src, dst, false).error(), ParseError::bad_data_offset);
  auto ts_only = segment(sample_header(w::tcp_ack), opt, false);
  ASSERT_EQ(ts_only.size(), 32u);
  EXPECT_EQ(parse_tcp(std::span(ts_only).first(31), src, dst, false).error(),
            ParseError::bad_data_offset);
}

TEST(WireTcp, MalformedOptionLengthKeepsEarlierOptions) {
  // MSS, then an option of length 0: parsing stops, MSS kept.
  auto o = parse_opts(with_options(from_hex("0204 05b4 0800")));
  EXPECT_TRUE(o.malformed);
  EXPECT_EQ(o.mss, 1460);
  EXPECT_FALSE(o.ts.has_value());

  // Length 1, then a valid window scale that must not be parsed.
  o = parse_opts(with_options(from_hex("0402 1301 0103 0307")));
  EXPECT_TRUE(o.malformed);
  EXPECT_TRUE(o.sack_permitted);
  EXPECT_FALSE(o.wscale.has_value());

  // An option running past the header: window scale, then a SACK of length
  // 10 with only 6 bytes left.
  o = parse_opts(with_options(from_hex("0303 0701 050a 0000 0000")));
  EXPECT_TRUE(o.malformed);
  EXPECT_EQ(o.wscale, 7);
  EXPECT_EQ(o.sack_count, 0);

  // A kind byte as the last option byte (no room for a length).
  o = parse_opts(with_options(from_hex("0101 0402 0101 01fd")));
  EXPECT_TRUE(o.malformed);
  EXPECT_TRUE(o.sack_permitted);
}

TEST(WireTcp, TruncatedTimestamps) {
  // TS of length 10 cut off by the end of the header: malformed, the MSS
  // before it kept.
  auto o = parse_opts(with_options(from_hex("0204 0218 080a 0000 0001 0000")));
  EXPECT_TRUE(o.malformed);
  EXPECT_EQ(o.mss, 536);
  EXPECT_FALSE(o.ts.has_value());

  // TS whose length field is 6: not a timestamp option Linux accepts, so it
  // is skipped (as tcp_parse_options) and the options after it are parsed.
  o = parse_opts(with_options(from_hex("0806 0000 0001 0303 0201")));
  EXPECT_FALSE(o.malformed);
  EXPECT_FALSE(o.ts.has_value());
  EXPECT_EQ(o.wscale, 2);
}

TEST(WireTcp, WrongLengthKnownOptionsAreSkipped) {
  // MSS of length 3, WS of length 4, SACK_PERM of length 3, SACK of length 9:
  // each skipped, the TS after them parsed.
  const auto o = parse_opts(with_options(
      from_hex("0203ff 0304ffff 0403ff 0509ffffffffffffff 080a0000000500000006"),
      std::byte{1}));
  EXPECT_FALSE(o.malformed);
  EXPECT_FALSE(o.mss.has_value());
  EXPECT_FALSE(o.wscale.has_value());
  EXPECT_FALSE(o.sack_permitted);
  EXPECT_EQ(o.sack_count, 0);
  ASSERT_TRUE(o.ts.has_value());
  EXPECT_EQ(o.ts->val, 5u);
  EXPECT_EQ(o.ts->ecr, 6u);
}

TEST(WireTcp, EndOfListAndUnknownOptions) {
  // Unknown kind 30 (MPTCP) of length 4 skipped; EOL ends the list, the bytes
  // after it are ignored and not malformed.
  const auto o = parse_opts(with_options(from_hex("1e04 0000 0402 0000 0204 05b4")));
  EXPECT_FALSE(o.malformed);
  EXPECT_TRUE(o.sack_permitted);
  EXPECT_FALSE(o.mss.has_value());
  // NOPs only.
  EXPECT_EQ(parse_opts(with_options(from_hex("0101 0101"))), TcpOptions{});
  // A repeated option: the later one wins (as Linux).
  EXPECT_EQ(parse_opts(with_options(from_hex("0204 0218 0204 05b4"))).mss, 1460);
}

TEST(WireTcp, RawValuesAreReported) {
  // MSS 0 and window scale 15 are reported as sent; the engine applies §4.5.
  const auto o = parse_opts(with_options(from_hex("0204 0000 0103 030f")));
  EXPECT_EQ(o.mss, 0);
  EXPECT_EQ(o.wscale, 15);
}

}  // namespace
