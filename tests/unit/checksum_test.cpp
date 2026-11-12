#include "utcp/checksum.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <string_view>
#include <vector>

namespace {

using utcp::ChecksumAccumulator;

std::vector<std::byte> bytes(std::initializer_list<unsigned> values) {
  std::vector<std::byte> out;
  for (const unsigned v : values) {
    out.push_back(static_cast<std::byte>(v));
  }
  return out;
}

std::vector<std::byte> words(std::initializer_list<std::uint16_t> values) {
  std::vector<std::byte> out;
  for (const std::uint16_t v : values) {
    out.push_back(static_cast<std::byte>(v >> 8));
    out.push_back(static_cast<std::byte>(v & 0xFF));
  }
  return out;
}

std::uint16_t get16(std::span<const std::byte> p, std::size_t off) {
  return static_cast<std::uint16_t>((std::to_integer<unsigned>(p[off]) << 8) |
                                    std::to_integer<unsigned>(p[off + 1]));
}

void put16(std::span<std::byte> p, std::size_t off, std::uint16_t v) {
  p[off] = static_cast<std::byte>(v >> 8);
  p[off + 1] = static_cast<std::byte>(v & 0xFF);
}

// Byte-at-a-time reference straight from RFC 1071 section 1: even-offset
// bytes are the high half of a word, odd-offset bytes the low half, carries
// are added back in.
std::uint16_t naive_sum(std::span<const std::byte> data) {
  std::uint32_t s = 0;
  for (std::size_t i = 0; i < data.size(); ++i) {
    const unsigned b = std::to_integer<unsigned>(data[i]);
    s += (i % 2 == 0) ? (b << 8) : b;
    s = (s & 0xFFFF) + (s >> 16);
  }
  return static_cast<std::uint16_t>(s);
}

std::uint16_t sum_of(std::span<const std::byte> data) {
  ChecksumAccumulator acc;
  acc.add(data);
  return acc.sum();
}

// ---- RFC 1071 ----

// RFC 1071 section 3, numerical example: 00 01 f2 03 f4 f5 f6 f7 sums to ddf2.
TEST(Checksum, Rfc1071NumericalExample) {
  const auto data = bytes({0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7});
  EXPECT_EQ(sum_of(data), 0xddf2);
  EXPECT_EQ(utcp::internet_checksum(data), 0x220d);
  EXPECT_EQ(naive_sum(data), 0xddf2);
}

// A commonly used IPv4 header example; the stored checksum is b861.
TEST(Checksum, Ipv4HeaderExample) {
  auto hdr = bytes({0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                    0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7});
  EXPECT_TRUE(utcp::checksum_valid(hdr));
  put16(hdr, 10, 0);
  EXPECT_EQ(utcp::internet_checksum(hdr), 0xb861);
  EXPECT_FALSE(utcp::checksum_valid(hdr));
}

TEST(Checksum, EmptyAndAllZero) {
  EXPECT_EQ(sum_of({}), 0x0000);
  EXPECT_EQ(utcp::internet_checksum({}), 0xFFFF);
  const std::vector<std::byte> zeros(9, std::byte{0});
  EXPECT_EQ(sum_of(zeros), 0x0000);
  EXPECT_EQ(utcp::internet_checksum(zeros), 0xFFFF);
}

// One's-complement addition of non-zero inputs gives 0xFFFF (-0), never 0x0000.
TEST(Checksum, NegativeZero) {
  EXPECT_EQ(sum_of(words({0xFFFF})), 0xFFFF);
  EXPECT_EQ(sum_of(words({0x8000, 0x7FFF})), 0xFFFF);
  EXPECT_EQ(sum_of(words({0xFFFF, 0xFFFF, 0xFFFF})), 0xFFFF);
  EXPECT_EQ(utcp::internet_checksum(words({0x1234, 0xEDCB})), 0x0000);
}

TEST(Checksum, CarriesWrapAround) {
  // 0xFFFF + 0x0001 = 0x1_0000 -> 0x0001.
  EXPECT_EQ(sum_of(words({0xFFFF, 0x0001})), 0x0001);
  // 64 KiB of 0xFF: every word is 0xFFFF, the sum stays 0xFFFF.
  const std::vector<std::byte> ff(65536, std::byte{0xFF});
  EXPECT_EQ(sum_of(ff), 0xFFFF);
  // 0x8000 * 4 = 0x2_0000 -> 0x0002.
  EXPECT_EQ(sum_of(words({0x8000, 0x8000, 0x8000, 0x8000})), 0x0002);
}

// An odd final byte is padded with a zero byte (RFC 1071 section 1).
TEST(Checksum, OddLengths) {
  EXPECT_EQ(sum_of(bytes({0xAB})), 0xAB00);
  EXPECT_EQ(utcp::internet_checksum(bytes({0xAB})), 0x54FF);
  EXPECT_EQ(sum_of(bytes({0x01, 0x02, 0x03})), 0x0402);
  EXPECT_EQ(sum_of(bytes({0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x10})), 0xedf2);
  for (std::size_t n = 1; n <= 41; n += 2) {
    std::vector<std::byte> data(n);
    for (std::size_t i = 0; i < n; ++i) {
      data[i] = static_cast<std::byte>(0xA5 ^ (i * 37));
    }
    EXPECT_EQ(sum_of(data), naive_sum(data)) << "length " << n;
  }
}

// The same bytes at every start alignment give the same sum.
TEST(Checksum, UnalignedInput) {
  std::array<std::byte, 64 + 16> buf{};
  const auto pattern = bytes({0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8,
                              0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7, 0xff, 0x01,
                              0x80, 0x7f, 0x00, 0xfe, 0x33, 0xcc, 0x5a, 0xa5, 0x0f});
  const std::uint16_t want = naive_sum(pattern);
  for (std::size_t off = 0; off < 16; ++off) {
    std::ranges::fill(buf, std::byte{0xEE});
    std::ranges::copy(pattern, buf.begin() + static_cast<std::ptrdiff_t>(off));
    EXPECT_EQ(sum_of(std::span(buf).subspan(off, pattern.size())), want) << "offset " << off;
  }
}

// Appending in pieces, including odd-length pieces, equals one call.
TEST(Checksum, SplitAcrossCalls) {
  const auto data = bytes({0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7, 0x10, 0x9a, 0xbc});
  const std::uint16_t want = naive_sum(data);
  for (std::size_t a = 0; a <= data.size(); ++a) {
    for (std::size_t b = a; b <= data.size(); ++b) {
      ChecksumAccumulator acc;
      const std::span<const std::byte> d(data);
      acc.add(d.subspan(0, a));
      acc.add(d.subspan(a, b - a));
      acc.add(d.subspan(b));
      EXPECT_EQ(acc.sum(), want) << "split at " << a << ", " << b;
      EXPECT_EQ(acc.size(), data.size());
    }
  }
}

// add_u16/add_u32 append bytes, so they work after an odd number of bytes too.
TEST(Checksum, AddWordsAtOddOffset) {
  ChecksumAccumulator acc;
  acc.add(bytes({0x12}));
  acc.add_u16(0x3456);
  acc.add_u32(0x789ABCDE);
  EXPECT_EQ(acc.sum(), naive_sum(bytes({0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE})));
  EXPECT_EQ(acc.size(), 7u);
}

TEST(Checksum, Uint8Overload) {
  const std::array<std::uint8_t, 3> data{0x01, 0x02, 0x03};
  ChecksumAccumulator acc;
  acc.add(data);
  EXPECT_EQ(acc.sum(), 0x0402);
}

// Randomized comparison against the naive reference: random lengths, start
// alignments and split points. Fixed seed, so a failure reproduces.
TEST(Checksum, RandomizedAgainstNaive) {
  constexpr std::uint64_t seed = 0x75746370'00000001;
  std::mt19937_64 rng(seed);
  std::uniform_int_distribution<int> byte_dist(0, 255);
  std::vector<std::byte> buf(9000 + 16);
  for (int iter = 0; iter < 20000; ++iter) {
    // Mostly packet-sized lengths, sometimes jumbo-sized.
    const std::size_t len = (iter % 10 == 0) ? rng() % 9000 : rng() % 1600;
    const std::size_t off = rng() % 16;
    // Bias some inputs towards 0xFF to exercise carries.
    const bool heavy = iter % 3 == 0;
    for (std::size_t i = 0; i < len; ++i) {
      buf[off + i] = heavy && (rng() % 4 != 0) ? std::byte{0xFF}
                                               : static_cast<std::byte>(byte_dist(rng));
    }
    const std::span<const std::byte> data = std::span(buf).subspan(off, len);
    const std::uint16_t want = naive_sum(data);
    ASSERT_EQ(sum_of(data), want) << "seed " << seed << " iter " << iter << " len " << len;

    ChecksumAccumulator acc;
    std::size_t pos = 0;
    while (pos < len) {
      const std::size_t piece = std::min<std::size_t>(len - pos, rng() % 70);
      acc.add(data.subspan(pos, piece));
      pos += piece;
    }
    ASSERT_EQ(acc.sum(), want) << "seed " << seed << " iter " << iter << " (split)";
  }
}

// ---- RFC 1624 ----

// RFC 1624 section 4: a 16-bit field m = 0x5555 changes to m' = 0x3285 and
// the other header words sum to 0xCD7A.
TEST(ChecksumUpdate, Rfc1624Section4Example) {
  // HC = ~(0xCD7A + 0x5555) = 0xDD2F; recomputed HC' = ~(0xCD7A + 0x3285) = 0x0000.
  EXPECT_EQ(utcp::internet_checksum(words({0xCD7A, 0x5555})), 0xDD2F);
  EXPECT_EQ(utcp::internet_checksum(words({0xCD7A, 0x3285})), 0x0000);
  // Eqn. 3 gives the recomputed value 0x0000 ...
  EXPECT_EQ(utcp::checksum_update16(0xDD2F, 0x5555, 0x3285), 0x0000);
  // ... where the RFC 1141 form HC + m + ~m' gives 0xFFFF.
  const std::uint16_t rfc1141 = sum_of(words({0xDD2F, 0x5555, static_cast<std::uint16_t>(~0x3285)}));
  EXPECT_EQ(rfc1141, 0xFFFF);
}

// RFC 1624 section 5: a receiver that sums the checksum field in accepts
// both +0 and -0 in the field.
TEST(ChecksumUpdate, Rfc1624Section5Verification) {
  EXPECT_TRUE(utcp::checksum_valid(words({0xCD7A, 0x3285, 0xFFFF})));
  EXPECT_TRUE(utcp::checksum_valid(words({0xCD7A, 0x3285, 0x0000})));
  EXPECT_FALSE(utcp::checksum_valid(words({0xCD7A, 0x3285, 0x0001})));
}

// Eqn. 3 never produces 0xFFFF for data that is not all zero, matching a
// full recomputation (RFC 1624 section 3).
TEST(ChecksumUpdate, NeverNegativeZero) {
  // Old word 0x0000, new word ~(rest): recomputed sum is 0xFFFF -> checksum 0x0000.
  const std::uint16_t rest = 0x1234;
  const std::uint16_t hc = utcp::internet_checksum(words({rest, 0x0000}));
  const std::uint16_t updated = utcp::checksum_update16(hc, 0x0000, static_cast<std::uint16_t>(~rest));
  EXPECT_EQ(updated, 0x0000);
  EXPECT_EQ(updated, utcp::internet_checksum(words({rest, static_cast<std::uint16_t>(~rest)})));
}

TEST(ChecksumUpdate, NoChangeKeepsChecksum) {
  EXPECT_EQ(utcp::checksum_update16(0xB861, 0x4011, 0x4011), 0xB861);
  EXPECT_EQ(utcp::checksum_update32(0xB861, 0xC0A80001, 0xC0A80001), 0xB861);
}

// TTL decrement in the IPv4 header example (the RFC 1141/1624 use case).
TEST(ChecksumUpdate, Ipv4TtlDecrement) {
  auto hdr = bytes({0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                    0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7});
  const std::uint16_t old_word = get16(hdr, 8);  // TTL, protocol
  hdr[8] = std::byte{0x3F};
  const std::uint16_t new_word = get16(hdr, 8);
  const std::uint16_t updated = utcp::checksum_update16(0xb861, old_word, new_word);
  put16(hdr, 10, 0);
  EXPECT_EQ(updated, utcp::internet_checksum(hdr));
  EXPECT_EQ(updated, 0xb961);
}

// Randomized: after changing one aligned 16- or 32-bit field, the updated
// checksum equals a full recomputation.
TEST(ChecksumUpdate, RandomizedAgainstRecompute) {
  constexpr std::uint64_t seed = 0x75746370'00000002;
  std::mt19937_64 rng(seed);
  for (int iter = 0; iter < 20000; ++iter) {
    const std::size_t len = 20 + 2 * (rng() % 30);
    std::vector<std::byte> data(len);
    for (auto& b : data) {
      b = static_cast<std::byte>(rng() & 0xFF);
    }
    data[0] = std::byte{0x45};  // never all zero, as in a real IPv4 header
    std::uint16_t hc = utcp::internet_checksum(data);

    // A few successive updates, each checked against recomputation.
    for (int step = 0; step < 4; ++step) {
      if (rng() % 2 == 0) {
        const std::size_t off = 2 * (1 + rng() % (len / 2 - 1));
        const std::uint16_t old_word = get16(data, off);
        // Sometimes pick the value that makes the recomputed sum 0xFFFF.
        auto new_word = static_cast<std::uint16_t>(rng());
        if (rng() % 8 == 0) {
          put16(data, off, 0);
          new_word = static_cast<std::uint16_t>(~sum_of(data));
        }
        put16(data, off, new_word);
        hc = utcp::checksum_update16(hc, old_word, new_word);
      } else {
        const std::size_t off = 2 * (1 + rng() % (len / 2 - 2));
        const std::uint32_t old_value = (std::uint32_t{get16(data, off)} << 16) | get16(data, off + 2);
        const auto new_value = static_cast<std::uint32_t>(rng());
        put16(data, off, static_cast<std::uint16_t>(new_value >> 16));
        put16(data, off + 2, static_cast<std::uint16_t>(new_value & 0xFFFF));
        hc = utcp::checksum_update32(hc, old_value, new_value);
      }
      ASSERT_EQ(hc, utcp::internet_checksum(data))
          << "seed " << seed << " iter " << iter << " step " << step;
    }
  }
}

// ---- IPv4 pseudo-header (RFC 9293 section 3.1, RFC 768) ----

TEST(ChecksumPseudoHeader, MatchesExplicitBytes) {
  const std::uint32_t src = 0xC0000201;  // 192.0.2.1
  const std::uint32_t dst = 0xC6336402;  // 198.51.100.2
  const auto payload = bytes({0x30, 0x39, 0x00, 0x35, 0x00, 0x0b, 0x00, 0x00, 'a', 'b', 'c'});
  // src, dst, zero, protocol 17, length 11, then the payload.
  auto explicit_bytes = bytes({0xC0, 0x00, 0x02, 0x01, 0xC6, 0x33, 0x64, 0x02, 0x00, 17, 0x00, 11});
  explicit_bytes.insert(explicit_bytes.end(), payload.begin(), payload.end());

  ChecksumAccumulator acc;
  utcp::add_ipv4_pseudo_header(acc, src, dst, utcp::ip_proto_udp, 11);
  EXPECT_EQ(acc.size(), 12u);
  acc.add(payload);
  EXPECT_EQ(acc.sum(), naive_sum(explicit_bytes));
  EXPECT_EQ(utcp::ipv4_transport_checksum(src, dst, utcp::ip_proto_udp, payload),
            static_cast<std::uint16_t>(~naive_sum(explicit_bytes)));
}

TEST(ChecksumPseudoHeader, StoreThenVerify) {
  const std::uint32_t src = 0x0A000001;
  const std::uint32_t dst = 0x0A000002;
  // TCP header (20 bytes, checksum at offset 16) plus 5 bytes of data: odd length.
  auto seg = bytes({0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50,
                    0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o'});
  const std::uint16_t c = utcp::tcp_checksum_ipv4(src, dst, seg);
  put16(seg, 16, c);
  EXPECT_TRUE(utcp::ipv4_transport_checksum_valid(src, dst, utcp::ip_proto_tcp, seg));
  EXPECT_EQ(utcp::ipv4_transport_checksum(src, dst, utcp::ip_proto_tcp, seg), 0x0000);
  // Wrong address, protocol or a flipped bit are all caught.
  EXPECT_FALSE(utcp::ipv4_transport_checksum_valid(src, dst + 1, utcp::ip_proto_tcp, seg));
  EXPECT_FALSE(utcp::ipv4_transport_checksum_valid(src, dst, utcp::ip_proto_udp, seg));
  seg[22] ^= std::byte{0x01};
  EXPECT_FALSE(utcp::ipv4_transport_checksum_valid(src, dst, utcp::ip_proto_tcp, seg));
}

// RFC 768: a computed UDP checksum of 0x0000 is sent as 0xFFFF.
TEST(ChecksumPseudoHeader, UdpZeroIsSentAsAllOnes) {
  const std::uint32_t src = 0xC0000201;
  const std::uint32_t dst = 0xC0000202;
  // UDP header (length 10, checksum 0) plus one 16-bit word chosen so the
  // whole sum is 0xFFFF, i.e. the computed checksum is 0x0000.
  auto dgram = bytes({0x12, 0x34, 0x00, 0x07, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00});
  ChecksumAccumulator acc;
  utcp::add_ipv4_pseudo_header(acc, src, dst, utcp::ip_proto_udp, 10);
  acc.add(dgram);
  put16(dgram, 8, static_cast<std::uint16_t>(~acc.sum()));
  ASSERT_EQ(utcp::ipv4_transport_checksum(src, dst, utcp::ip_proto_udp, dgram), 0x0000);

  const std::uint16_t c = utcp::udp_checksum_ipv4(src, dst, dgram);
  EXPECT_EQ(c, 0xFFFF);
  put16(dgram, 6, c);
  EXPECT_TRUE(utcp::ipv4_transport_checksum_valid(src, dst, utcp::ip_proto_udp, dgram));
}

// ---- Packets generated by Linux ----

std::vector<std::byte> from_hex(std::string_view hex) {
  const auto nibble = [](char c) {
    return static_cast<unsigned>(c <= '9' ? c - '0' : c - 'a' + 10);
  };
  std::vector<std::byte> out;
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<std::byte>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
  }
  return out;
}

struct KernelPacket {
  const char* name;
  const char* hex;
  std::size_t l4_checksum_offset;  // within the transport header / ICMP message
};

// Sent by Linux 7.0.0-42 from 198.18.0.1 to 198.18.0.2 through a TUN interface
// and read with `apps/tun_probe --hex`. The kernel computes these checksums in
// software (no offload on TUN), so they are an independent reference.
constexpr std::array<KernelPacket, 4> kernel_packets{{
    {"udp, 21-byte payload", "450000312a1940004011847bc6120001c6120002e9410009001d9146"
                             "7574637020636865636b73756d20766563746f720a", 6},
    {"udp, 3-byte payload", "4500001f38ef4000401175b7c6120001c61200028e410007000b12036f6464", 6},
    {"tcp syn with options", "4500003cb6a440004006f7efc6120001c6120002cdec00509796dcdc00000000"
                             "a002faf0d36b0000020405b40402080aa19c092c000000000103030a", 16},
    {"icmp echo request, odd length", "4500003128d34000400185d1c6120001c612000208009e995b140001"
                                      "e3d3f46a00000000e1ed0e00000000001011121314", 2},
}};

TEST(ChecksumKernelPackets, ChecksumsMatchLinux) {
  for (const KernelPacket& kp : kernel_packets) {
    SCOPED_TRACE(kp.name);
    std::vector<std::byte> pkt = from_hex(kp.hex);
    ASSERT_GE(pkt.size(), 20u);
    const std::size_t ihl = (std::to_integer<std::size_t>(pkt[0]) & 0x0F) * 4;
    const std::uint32_t src = (std::uint32_t{get16(pkt, 12)} << 16) | get16(pkt, 14);
    const std::uint32_t dst = (std::uint32_t{get16(pkt, 16)} << 16) | get16(pkt, 18);
    const auto proto = std::to_integer<std::uint8_t>(pkt[9]);
    ASSERT_EQ(src, 0xC6120001u);
    ASSERT_EQ(dst, 0xC6120002u);

    // IPv4 header checksum.
    const std::span<std::byte> hdr = std::span(pkt).first(ihl);
    EXPECT_TRUE(utcp::checksum_valid(hdr));
    const std::uint16_t ip_stored = get16(hdr, 10);
    put16(hdr, 10, 0);
    EXPECT_EQ(utcp::internet_checksum(hdr), ip_stored);
    put16(hdr, 10, ip_stored);

    // Transport (pseudo-header) or ICMP checksum.
    const std::span<std::byte> l4 = std::span(pkt).subspan(ihl);
    const std::uint16_t stored = get16(l4, kp.l4_checksum_offset);
    if (proto == utcp::ip_proto_icmp) {
      EXPECT_TRUE(utcp::checksum_valid(l4));
      put16(l4, kp.l4_checksum_offset, 0);
      EXPECT_EQ(utcp::internet_checksum(l4), stored);
    } else {
      EXPECT_TRUE(utcp::ipv4_transport_checksum_valid(src, dst, proto, l4));
      put16(l4, kp.l4_checksum_offset, 0);
      const std::uint16_t computed = proto == utcp::ip_proto_tcp
                                         ? utcp::tcp_checksum_ipv4(src, dst, l4)
                                         : utcp::udp_checksum_ipv4(src, dst, l4);
      EXPECT_EQ(computed, stored);
    }
  }
}

}  // namespace
