#include "utcp/types.hpp"

#include <gtest/gtest.h>

#include <map>
#include <set>

namespace {

using utcp::Endpoint;
using utcp::FourTuple;
using utcp::Handle;
using utcp::Ipv4Addr;
using utcp::Range;

TEST(Types, Ipv4FromOctets) {
  constexpr Ipv4Addr a = Ipv4Addr::from_octets(192, 0, 2, 1);
  static_assert(a.v == 0xC000'0201u);
  EXPECT_EQ(a.octet(0), 192);
  EXPECT_EQ(a.octet(3), 1);
  EXPECT_EQ(to_string(a), "192.0.2.1");
  EXPECT_EQ(to_string(Endpoint{a, 8080}), "192.0.2.1:8080");
}

TEST(Types, Ipv4FromString) {
  EXPECT_EQ(utcp::ipv4_from_string("198.18.0.2"), Ipv4Addr::from_octets(198, 18, 0, 2));
  EXPECT_EQ(utcp::ipv4_from_string("0.0.0.0"), Ipv4Addr{0});
  EXPECT_EQ(utcp::ipv4_from_string("255.255.255.255"), Ipv4Addr{0xffff'ffffu});
  for (const char* bad : {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.4 ", " 1.2.3.4", "1..2.3",
                          "a.b.c.d", "1.2.3.-4", "1.2.3.0004", "1.2.3.+4"}) {
    EXPECT_FALSE(utcp::ipv4_from_string(bad).has_value()) << bad;
  }
}

TEST(Types, OrderingIsByValue) {
  const Endpoint e1{Ipv4Addr{1}, 2}, e2{Ipv4Addr{1}, 3}, e3{Ipv4Addr{2}, 0};
  EXPECT_LT(e1, e2);
  EXPECT_LT(e2, e3);
  const FourTuple t1{e1, e2}, t2{e1, e3};
  EXPECT_LT(t1, t2);
  std::set<FourTuple> s{t2, t1};
  EXPECT_EQ(*s.begin(), t1);
  EXPECT_LT((Handle{1, 0, utcp::Proto::tcp}), (Handle{1, 1, utcp::Proto::tcp}));
  EXPECT_NE((Handle{1, 0, utcp::Proto::tcp}), (Handle{1, 0, utcp::Proto::udp}));
}

TEST(Types, Range) {
  constexpr Range r{10, 20};
  static_assert(r.size() == 10);
  EXPECT_FALSE(r.empty());
  EXPECT_TRUE(r.contains(10));
  EXPECT_FALSE(r.contains(20));
  EXPECT_TRUE((Range{5, 5}).empty());
  EXPECT_EQ((Range{6, 5}).size(), 0u);
}

TEST(Types, StateNames) {
  EXPECT_EQ(to_string(utcp::TcpState::syn_received), "syn_received");
  EXPECT_EQ(to_string(utcp::TcpState::time_wait), "time_wait");
  EXPECT_EQ(to_string(utcp::CaState::recovery), "recovery");
  EXPECT_EQ(to_string(utcp::Proto::udp), "udp");
  std::set<std::string_view> names;
  for (int i = 0; i < utcp::tcp_state_count; ++i) {
    names.insert(to_string(static_cast<utcp::TcpState>(i)));
  }
  EXPECT_EQ(names.size(), static_cast<std::size_t>(utcp::tcp_state_count));
  EXPECT_EQ(names.count("?"), 0u);
}

}  // namespace
