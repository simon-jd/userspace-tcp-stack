#include "common/dns.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace utcp::app {
namespace {

std::vector<std::byte> from_hex(std::string_view h) {
  std::vector<std::byte> out;
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
    out.push_back(static_cast<std::byte>(std::stoi(std::string(h.substr(i, 2)), nullptr, 16)));
  }
  return out;
}

std::string to_hex_string(std::span<const std::byte> b) {
  static constexpr char d[] = "0123456789abcdef";
  std::string s;
  for (const std::byte x : b) {
    s += d[std::to_integer<int>(x) >> 4];
    s += d[std::to_integer<int>(x) & 15];
  }
  return s;
}

// A response captured on the build server (2026-11-13) from its resolver
// (systemd-resolved, 127.0.0.53) for "www.github.com" A, query id 0x1234,
// sent and received with Python:
//   python3 -I -c 'import socket,struct; q=struct.pack("!HHHHHH",0x1234,0x100,1,0,0,0)+
//     b"\x03www\x06github\x03com\x00"+struct.pack("!HH",1,1); s=socket.socket(2,2);
//     s.sendto(q,("127.0.0.53",53)); print(s.recv(4096).hex())'
// Two answers: www.github.com CNAME github.com, github.com A. The CNAME's
// owner is a pointer to the question (c00c) and its RDATA a pointer into the
// question's name (c010 = "github.com"); the A record's owner is c010 too.
constexpr std::string_view captured =
    "123481800001000200000000037777770667697468756203636f6d0000010001"
    "c00c00050001000003b50002c010c010000100010000000a0004acc2dac0";

TEST(DnsQuery, EncodesAStandardQuery) {
  const auto q = dns_encode_query(0x1234, "www.github.com");
  ASSERT_TRUE(q) << q.error();
  // The same bytes as the query that produced the capture above.
  EXPECT_EQ(to_hex_string(*q),
            "123401000001000000000000037777770667697468756203636f6d0000010001");
  const auto q2 = dns_encode_query(7, "Example.ORG.");  // final dot allowed, case kept
  ASSERT_TRUE(q2);
  EXPECT_EQ(to_hex_string(*q2), "00070100000100000000000007" "4578616d706c65" "034f5247" "0000010001");
}

TEST(DnsQuery, RejectsBadNames) {
  EXPECT_FALSE(dns_encode_query(1, ""));
  EXPECT_FALSE(dns_encode_query(1, "."));
  EXPECT_FALSE(dns_encode_query(1, "a..b"));
  EXPECT_FALSE(dns_encode_query(1, std::string(64, 'a') + ".com"));
  EXPECT_TRUE(dns_encode_query(1, std::string(63, 'a') + ".com"));
  std::string long_name;
  while (long_name.size() < 260) {
    long_name += "abcdefghi.";
  }
  EXPECT_FALSE(dns_encode_query(1, long_name));
}

TEST(DnsResponse, DecodesTheCapturedResponseWithCompression) {
  const auto bytes = from_hex(captured);
  const auto r = dns_parse_response(bytes);
  ASSERT_TRUE(r) << r.error();
  EXPECT_EQ(r->id, 0x1234);
  EXPECT_TRUE(r->qr);
  EXPECT_EQ(r->rcode, 0);
  EXPECT_FALSE(r->truncated);
  EXPECT_EQ(r->qname, "www.github.com");
  ASSERT_EQ(r->answers.size(), 2u);
  EXPECT_EQ(r->answers[0].name, "www.github.com");
  EXPECT_EQ(r->answers[0].type, dns_type_cname);
  EXPECT_EQ(r->answers[0].ttl, 949u);
  EXPECT_EQ(r->answers[0].target, "github.com");
  EXPECT_EQ(r->answers[1].name, "github.com");
  EXPECT_EQ(r->answers[1].type, dns_type_a);
  EXPECT_EQ(r->answers[1].ttl, 10u);
  const auto a = dns_a_records(*r, 0x1234, "WWW.GitHub.com.");
  ASSERT_TRUE(a) << a.error();
  ASSERT_EQ(a->size(), 1u);
  EXPECT_EQ(to_string((*a)[0]), "172.194.218.192");
}

TEST(DnsResponse, ChecksIdQuestionAndRcode) {
  const auto bytes = from_hex(captured);
  const auto r = dns_parse_response(bytes);
  ASSERT_TRUE(r);
  EXPECT_FALSE(dns_a_records(*r, 0x1235, "www.github.com"));
  EXPECT_FALSE(dns_a_records(*r, 0x1234, "github.com"));
  auto nx = from_hex(captured);
  nx[3] = std::byte{0x83};  // rcode 3, NXDOMAIN
  const auto rn = dns_parse_response(nx);
  ASSERT_TRUE(rn);
  EXPECT_EQ(rn->rcode, 3);
  const auto e = dns_a_records(*rn, 0x1234, "www.github.com");
  ASSERT_FALSE(e);
  EXPECT_NE(e.error().find("NXDOMAIN"), std::string::npos);
  auto query = from_hex(captured);
  query[2] = std::byte{0x01};  // QR clear: a query, not a response
  EXPECT_FALSE(dns_a_records(*dns_parse_response(query), 0x1234, "www.github.com"));
}

TEST(DnsResponse, RejectsMalformedMessages) {
  const auto good = from_hex(captured);
  // Every truncation fails cleanly.
  for (std::size_t n = 0; n < good.size(); ++n) {
    EXPECT_FALSE(dns_parse_response(std::span(good).first(n))) << n;
  }
  // A pointer to itself, and one pointing forward.
  auto loop = good;
  loop[32] = std::byte{0xc0};
  loop[33] = std::byte{32};
  EXPECT_FALSE(dns_parse_response(loop));
  auto fwd = good;
  fwd[33] = std::byte{40};
  EXPECT_FALSE(dns_parse_response(fwd));
  // Reserved label type 0x40.
  auto reserved = good;
  reserved[12] = std::byte{0x43};
  EXPECT_FALSE(dns_parse_response(reserved));
  // RDLENGTH beyond the message.
  auto rdlen = good;
  rdlen[43] = std::byte{0x20};
  EXPECT_FALSE(dns_parse_response(rdlen));
}

}  // namespace
}  // namespace utcp::app
