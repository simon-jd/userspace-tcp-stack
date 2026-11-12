#include "core/udp.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "core/stack_impl.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/udp.hpp"
#include "support/packet_builder.hpp"
#include "support/tcp_harness.hpp"
#include "utcp/checksum.hpp"
#include "utcp/stack.hpp"

namespace {

using utcp::Endpoint;
using utcp::Error;
using utcp::Handle;
using utcp::Ipv4Addr;
using utcp::Stack;
using utcp::Time;
using utcp::UdpRecv;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;

constexpr std::uint16_t port_a = 5000;
constexpr std::uint16_t port_b = 6000;

struct Pair {
  t::TcpHarness h;
  Handle sa, sb;
  Endpoint ea, eb;

  Pair() : Pair(t::TcpHarness::default_config(Side::a), t::TcpHarness::default_config(Side::b)) {}
  Pair(const utcp::StackConfig& a, const utcp::StackConfig& b) : h(a, b) {
    sa = *h.a().udp_open(Endpoint{{}, port_a});
    sb = *h.b().udp_open(Endpoint{h.addr(Side::b), port_b});
    ea = Endpoint{h.addr(Side::a), port_a};
    eb = Endpoint{h.addr(Side::b), port_b};
  }
};

std::optional<std::pair<UdpRecv, t::Bytes>> recv(Stack& s, Handle h, std::size_t cap = 2048) {
  t::Bytes buf(cap);
  const auto r = s.udp_recv_from(h, buf);
  if (!r) {
    EXPECT_EQ(r.error(), Error::would_block);
    return std::nullopt;
  }
  buf.resize(std::min(r->len, cap));
  return std::pair{*r, buf};
}

// m1-ip test 2: 1-, 1472- and 0-byte datagrams between two stacks.
TEST(Udp, DatagramsBetweenTwoStacks) {
  Pair p;
  for (const std::size_t n : {std::size_t{1}, std::size_t{1472}, std::size_t{0}}) {
    const t::Bytes payload = t::pattern(n, static_cast<std::uint8_t>(n));
    ASSERT_TRUE(p.h.a().udp_send_to(p.sa, p.eb, payload)) << n;
    p.h.settle();
    const auto r = recv(p.h.b(), p.sb);
    ASSERT_TRUE(r.has_value()) << n;
    EXPECT_EQ(r->first.len, n);
    EXPECT_EQ(r->first.from, p.ea);
    EXPECT_FALSE(r->first.truncated);
    EXPECT_EQ(r->second, payload);
    EXPECT_FALSE(recv(p.h.b(), p.sb).has_value());
  }
  // The 1472-byte datagram is exactly 1500 bytes on the wire, DF set.
  ASSERT_EQ(p.h.log().size(), 3u);
  EXPECT_EQ(p.h.log()[1].bytes.size(), 1500u);
  const auto ip = w::parse_ipv4(p.h.log()[1].bytes);
  ASSERT_TRUE(ip.has_value());
  EXPECT_TRUE(ip->h.df);
  EXPECT_EQ(ip->h.ttl, 64);
  EXPECT_EQ(ip->h.id, 0);
  EXPECT_EQ(p.h.a().stats().UdpOutDatagrams, 3u);
  EXPECT_EQ(p.h.b().stats().UdpInDatagrams, 3u);
  p.h.a().debug_check();
  p.h.b().debug_check();
}

TEST(Udp, MessageTooBigAbovePmtuMinus28) {
  Pair p;
  EXPECT_EQ(p.h.a().udp_send_to(p.sa, p.eb, t::pattern(1473)),
            std::unexpected(Error::message_too_big));
  EXPECT_EQ(p.h.a().udp_send_to(p.sa, p.eb, t::pattern(65508)),
            std::unexpected(Error::message_too_big));
  // With a lower path MTU to the destination.
  utcp::StackConfig cfg = t::TcpHarness::default_config(Side::a);
  utcp::StackImpl s(cfg);
  const Handle h = *s.udp.open(Endpoint{{}, 1234});
  const Ipv4Addr dst = Ipv4Addr::from_octets(192, 0, 2, 9);
  s.core.pmtu_lower(dst, 1400);
  EXPECT_TRUE(s.udp.send_to(h, Endpoint{dst, 53}, t::pattern(1372)));
  EXPECT_EQ(s.udp.send_to(h, Endpoint{dst, 53}, t::pattern(1373)),
            std::unexpected(Error::message_too_big));
  EXPECT_TRUE(s.udp.send_to(h, Endpoint{Ipv4Addr::from_octets(192, 0, 2, 10), 53},
                            t::pattern(1472)));
  EXPECT_EQ(s.core.stats().UdpOutDatagrams, 2u);
}

TEST(Udp, ReceiveQueueFullDropsAndCounts) {
  utcp::StackConfig b = t::TcpHarness::default_config(Side::b);
  b.udp.rcv_buf = 4096;  // four 1000-byte datagrams with their 8-byte records
  Pair p(t::TcpHarness::default_config(Side::a), b);
  for (int i = 0; i < 6; ++i) {
    ASSERT_TRUE(p.h.a().udp_send_to(p.sa, p.eb, t::pattern(1000, static_cast<std::uint8_t>(i))));
  }
  p.h.settle();
  const auto& st = p.h.b().stats();
  EXPECT_EQ(st.UdpInDatagrams, 4u);
  EXPECT_EQ(st.UdpRcvbufErrors, 2u);
  EXPECT_EQ(st.UdpInErrors, 2u);
  // Reading one makes room for one more; the queued ones come out in order.
  EXPECT_EQ(recv(p.h.b(), p.sb)->second, t::pattern(1000, 0));
  ASSERT_TRUE(p.h.a().udp_send_to(p.sa, p.eb, t::pattern(1000, 9)));
  p.h.settle();
  EXPECT_EQ(st.UdpInDatagrams, 5u);
  for (const std::uint8_t tag : {1, 2, 3, 9}) {
    EXPECT_EQ(recv(p.h.b(), p.sb)->second, t::pattern(1000, tag));
  }
  EXPECT_FALSE(recv(p.h.b(), p.sb).has_value());
  // All chunks went back.
  EXPECT_EQ(p.h.b().debug_usage().chunks_free, p.h.b().debug_usage().chunks);
  p.h.b().debug_check();
}

TEST(Udp, ChecksumZeroAcceptedBadChecksumDropped) {
  auto cfg = t::TcpHarness::default_config(Side::b);
  utcp::StackImpl s(cfg);
  s.advance(t::TcpHarness::default_start);
  const Handle h = *s.udp.open(Endpoint{{}, port_b});
  const Endpoint from{Ipv4Addr::from_octets(10, 0, 0, 1), 4444};
  const Endpoint to{cfg.local_addr, port_b};
  // RFC 768: a zero checksum field means none.
  s.receive(s.core.now(), t::udp_datagram(t::UdpSpec{from, to, t::pattern(20), t::UdpChecksum::none}));
  EXPECT_EQ(s.udp.queued(h), 1u);
  // A bad checksum is dropped and counted; no ICMP error.
  s.receive(s.core.now(),
            t::udp_datagram(t::UdpSpec{from, to, t::pattern(20), t::UdpChecksum::corrupt}));
  EXPECT_EQ(s.udp.queued(h), 1u);
  EXPECT_EQ(s.core.stats().UdpInCsumErrors, 1u);
  EXPECT_EQ(s.core.stats().UdpInErrors, 1u);
  EXPECT_EQ(s.core.tx_queue().size(), 0u);
  // With RxMeta::csum_verified the checksum is not checked (M4 offload).
  s.receive(s.core.now(),
            t::udp_datagram(t::UdpSpec{from, to, t::pattern(20), t::UdpChecksum::corrupt}),
            utcp::RxMeta{true, false, 0});
  EXPECT_EQ(s.udp.queued(h), 2u);
  // Length field below 8 or beyond the datagram.
  t::UdpSpec bad{from, to, t::pattern(20)};
  bad.len = 7;
  s.receive(s.core.now(), t::udp_datagram(bad));
  bad.len = 29;
  s.receive(s.core.now(), t::udp_datagram(bad));
  EXPECT_EQ(s.core.stats().UdpInErrors, 3u);
  EXPECT_EQ(s.udp.queued(h), 2u);
  s.debug_check();
}

// P23: a payload whose checksum computes to 0 is sent as 0xFFFF and accepted.
TEST(Udp, ComputedZeroChecksumIsSentAsFfff) {
  Pair p;
  // Choose the last payload word so that the one's-complement sum is 0xFFFF:
  // with that word 0 the checksum is c, so the word c brings the sum to
  // 0xFFFF and the checksum to 0.
  t::Bytes payload{std::byte{0x12}, std::byte{0x34}, std::byte{0}, std::byte{0}};
  const t::Bytes zero_word = t::udp(t::UdpSpec{p.ea, p.eb, payload, t::UdpChecksum::none});
  const std::uint16_t c = utcp::udp_checksum_ipv4(p.ea.addr.v, p.eb.addr.v, zero_word);
  payload[2] = static_cast<std::byte>(c >> 8);
  payload[3] = static_cast<std::byte>(c & 0xff);
  {
    t::Bytes probe = t::udp(t::UdpSpec{p.ea, p.eb, payload, t::UdpChecksum::none});
    ASSERT_EQ(utcp::ipv4_transport_checksum(p.ea.addr.v, p.eb.addr.v, utcp::ip_proto_udp, probe), 0);
  }
  ASSERT_TRUE(p.h.a().udp_send_to(p.sa, p.eb, payload));
  p.h.settle();
  ASSERT_EQ(p.h.log().size(), 1u);
  const t::Bytes& d = p.h.log()[0].bytes;
  EXPECT_EQ(w::load_be16(d, w::ipv4_header_len + 6), 0xffff);
  const auto r = recv(p.h.b(), p.sb);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->second, payload);
  EXPECT_EQ(p.h.b().stats().UdpInCsumErrors, 0u);
}

TEST(Udp, SocketApi) {
  utcp::StackImpl s(t::TcpHarness::default_config(Side::a));
  const Ipv4Addr us = s.core.local_addr();
  const auto h1 = s.udp.open(Endpoint{us, 53});
  ASSERT_TRUE(h1.has_value());
  EXPECT_EQ(h1->proto, utcp::Proto::udp);
  EXPECT_EQ(s.udp.open(Endpoint{{}, 53}), std::unexpected(Error::addr_in_use));
  EXPECT_EQ(s.udp.open(Endpoint{Ipv4Addr::from_octets(10, 9, 9, 9), 54}),
            std::unexpected(Error::addr_not_available));
  const auto h2 = s.udp.open(Endpoint{{}, 0});
  ASSERT_TRUE(h2.has_value());
  EXPECT_EQ(h2->slot, 1u);
  EXPECT_EQ(s.udp.send_to(*h1, Endpoint{{}, 9}, t::pattern(1)),
            std::unexpected(Error::invalid_argument));
  EXPECT_EQ(s.udp.send_to(*h1, Endpoint{us, 0}, t::pattern(1)),
            std::unexpected(Error::invalid_argument));
  t::Bytes buf(16);
  EXPECT_EQ(s.udp.recv_from(*h1, buf), std::unexpected(Error::would_block));
  ASSERT_TRUE(s.udp.close(*h1));
  EXPECT_EQ(s.udp.close(*h1), std::unexpected(Error::bad_handle));
  EXPECT_EQ(s.udp.recv_from(*h1, buf), std::unexpected(Error::bad_handle));
  EXPECT_EQ(s.udp.send_to(*h1, Endpoint{us, 9}, buf), std::unexpected(Error::bad_handle));
  // The lowest free slot is reused with a new generation; the old handle
  // stays invalid.
  const auto h3 = s.udp.open(Endpoint{{}, 53});
  ASSERT_TRUE(h3.has_value());
  EXPECT_EQ(h3->slot, h1->slot);
  EXPECT_EQ(h3->gen, h1->gen + 1);
  EXPECT_EQ(s.udp.recv_from(*h1, buf), std::unexpected(Error::bad_handle));
  // A TCP handle is not a UDP socket.
  EXPECT_EQ(s.udp.recv_from(Handle{h3->slot, h3->gen, utcp::Proto::tcp}, buf),
            std::unexpected(Error::bad_handle));
  EXPECT_EQ(s.debug_usage().udp_slots, 2u);
  EXPECT_EQ(s.core.slots_in_use(), 2u);
  s.debug_check();
}

TEST(Udp, SlotsAreSharedWithMaxConnections) {
  auto cfg = t::TcpHarness::default_config(Side::a);
  cfg.max_connections = 2;
  utcp::StackImpl s(cfg);
  const auto a = s.udp.open(Endpoint{});
  const auto b = s.udp.open(Endpoint{});
  ASSERT_TRUE(a && b);
  EXPECT_EQ(s.udp.open(Endpoint{}), std::unexpected(Error::no_buffers));
  ASSERT_TRUE(s.udp.close(*a));
  EXPECT_TRUE(s.udp.open(Endpoint{}).has_value());
}

TEST(Udp, TruncatedRead) {
  Pair p;
  ASSERT_TRUE(p.h.a().udp_send_to(p.sa, p.eb, t::pattern(100)));
  p.h.settle();
  const auto r = recv(p.h.b(), p.sb, 10);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->first.len, 100u);
  EXPECT_TRUE(r->first.truncated);
  EXPECT_EQ(r->second, t::pattern(10));
  EXPECT_FALSE(recv(p.h.b(), p.sb).has_value());  // the rest of it is gone
}

TEST(Udp, NoBuffersWhenTheTransmitQueueIsFull) {
  auto cfg = t::TcpHarness::default_config(Side::a);
  cfg.tx_queue_packets = 2;
  utcp::StackImpl s(cfg);
  const Handle h = *s.udp.open(Endpoint{});
  const Endpoint dst{Ipv4Addr::from_octets(10, 0, 0, 2), 9};
  EXPECT_TRUE(s.udp.send_to(h, dst, t::pattern(1)));
  EXPECT_TRUE(s.udp.send_to(h, dst, t::pattern(1)));
  EXPECT_EQ(s.udp.send_to(h, dst, t::pattern(1)), std::unexpected(Error::no_buffers));
  EXPECT_EQ(s.core.stats().UdpSndbufErrors, 1u);
  EXPECT_EQ(s.core.blocked().size(), 0u);  // UDP never joins the blocked FIFO
  ASSERT_TRUE(s.pop_transmit().has_value());
  EXPECT_TRUE(s.udp.send_to(h, dst, t::pattern(1)));
}

// m1-ip test 10 (harness part): drop, reorder and rewrite hooks between two
// stacks.
TEST(Udp, HarnessDropReorderRewrite) {
  Pair p;
  int n = 0;
  p.h.set_hook([&](Side from, t::Bytes& d) {
    EXPECT_EQ(from, Side::a);
    switch (n++) {
      case 0: return t::Verdict::drop;
      case 1: return t::Verdict::hold;  // delivered after the next one
      case 3: {
        // Rewrite the first payload byte and fix the checksums.
        d[w::ipv4_header_len + w::udp_header_len] = std::byte{0xEE};
        t::fix_checksums(d);
        return t::Verdict::deliver;
      }
      case 4:
        // Rewrite without fixing: the receiver drops it.
        d[w::ipv4_header_len + w::udp_header_len] = std::byte{0xEE};
        return t::Verdict::deliver;
      default: return t::Verdict::deliver;
    }
  });
  for (std::uint8_t i = 0; i < 5; ++i) {
    ASSERT_TRUE(p.h.a().udp_send_to(p.sa, p.eb, t::Bytes(4, std::byte{i})));
  }
  p.h.settle();
  EXPECT_EQ(p.h.held_count(), 1u);
  EXPECT_EQ(p.h.dropped(), 1u);
  p.h.release_all_held();
  p.h.settle();
  std::vector<t::Bytes> got;
  while (const auto r = recv(p.h.b(), p.sb)) {
    got.push_back(r->second);
  }
  const std::vector<t::Bytes> want{t::Bytes(4, std::byte{2}),
                                   t::Bytes{std::byte{0xEE}, std::byte{3}, std::byte{3}, std::byte{3}},
                                   t::Bytes(4, std::byte{1})};
  EXPECT_EQ(got, want);
  EXPECT_EQ(p.h.b().stats().UdpInCsumErrors, 1u);
  EXPECT_EQ(p.h.log().size(), 5u);
  EXPECT_EQ(p.h.delivered(), 4u);
}

TEST(Udp, HarnessDelayMovesTheClock) {
  Pair p;
  p.h.set_delay(Side::a, std::chrono::milliseconds(5));
  const Time start = p.h.now();
  ASSERT_TRUE(p.h.a().udp_send_to(p.sa, p.eb, t::pattern(3)));
  p.h.settle();
  EXPECT_FALSE(recv(p.h.b(), p.sb).has_value());
  p.h.run_until(start + std::chrono::milliseconds(4));
  EXPECT_FALSE(recv(p.h.b(), p.sb).has_value());
  p.h.run_until(start + std::chrono::milliseconds(5));
  EXPECT_TRUE(recv(p.h.b(), p.sb).has_value());
  EXPECT_EQ(p.h.b().now(), start + std::chrono::milliseconds(5));
}

TEST(Udp, IcmpErrorsAreCountedNotReported) {
  Pair p;
  // b closes its socket: a's next datagram gets port unreachable.
  ASSERT_TRUE(p.h.b().udp_close(p.sb));
  ASSERT_TRUE(p.h.a().udp_send_to(p.sa, p.eb, t::pattern(8)));
  p.h.settle();
  EXPECT_EQ(p.h.b().stats().UdpNoPorts, 1u);
  EXPECT_EQ(p.h.b().stats().IcmpOutDestUnreachs, 1u);
  EXPECT_EQ(p.h.a().stats().IcmpInDestUnreachs, 1u);
  EXPECT_EQ(p.h.a().stats().udp_icmp_errors, 1u);
  EXPECT_EQ(p.h.a().poll_event(), std::nullopt);
  t::Bytes buf(16);
  EXPECT_EQ(p.h.a().udp_recv_from(p.sa, buf), std::unexpected(Error::would_block));
}

}  // namespace
