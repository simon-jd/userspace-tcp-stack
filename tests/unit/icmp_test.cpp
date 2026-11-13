#include "core/icmp.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "core/stack_impl.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "support/packet_builder.hpp"
#include "support/tcp_harness.hpp"
#include "utcp/checksum.hpp"
#include "utcp/stack.hpp"

namespace {

using utcp::EchoReply;
using utcp::Endpoint;
using utcp::Error;
using utcp::Ipv4Addr;
using utcp::Seq32;
using utcp::StackImpl;
using utcp::Time;
using namespace std::chrono_literals;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;

const Ipv4Addr peer = Ipv4Addr::from_octets(192, 0, 2, 50);
const Time t0{5'000'000'000};

utcp::StackConfig config() {
  utcp::StackConfig c = t::TcpHarness::default_config(Side::a);
  c.tx_queue_packets = 2048;
  return c;
}

std::vector<t::Bytes> drain(StackImpl& s) {
  std::vector<t::Bytes> out;
  while (auto p = s.pop_transmit()) {
    const auto b = p->buf.bytes();
    out.emplace_back(b.begin(), b.end());
  }
  return out;
}

t::Bytes expected_icmp(Ipv4Addr src, Ipv4Addr dst, const t::Bytes& message) {
  t::IpSpec ip;
  ip.src = src;
  ip.dst = dst;
  ip.proto = utcp::ip_proto_icmp;
  ip.ttl = 64;
  ip.id = 0;
  ip.df = true;
  return t::ipv4(ip, message);
}

t::Bytes unbound_udp(Ipv4Addr from, Ipv4Addr to, std::size_t payload = 0) {
  return t::udp_datagram(t::UdpSpec{Endpoint{from, 4000}, Endpoint{to, 9}, t::pattern(payload)});
}

// m1-ip test 1: one reply, byte for byte the hand-built datagram.
TEST(Icmp, EchoReplyIsByteForByte) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const t::Bytes payload = t::pattern(56, 9);
  s.receive(t0, t::icmp_echo_request(peer, us, 0x1234, 7, payload));
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0], expected_icmp(us, peer, t::icmp(w::icmp_echo_reply, 0, 0x1234'0007u, payload)));
  EXPECT_EQ(s.core.stats().IcmpInEchos, 1u);
  EXPECT_EQ(s.core.stats().IcmpOutEchoReps, 1u);
  EXPECT_EQ(s.core.stats().IcmpOutMsgs, 1u);
  // A request with IP options: the reply has none.
  t::IpSpec ip;
  ip.src = peer;
  ip.dst = us;
  ip.proto = utcp::ip_proto_icmp;
  ip.options = t::Bytes{std::byte{1}, std::byte{1}, std::byte{1}, std::byte{0}};
  s.receive(t0, t::ipv4(ip, t::icmp(w::icmp_echo_request, 0, 0x0001'0002u, payload)));
  const auto out2 = drain(s);
  ASSERT_EQ(out2.size(), 1u);
  EXPECT_EQ(out2[0], expected_icmp(us, peer, t::icmp(w::icmp_echo_reply, 0, 0x0001'0002u, payload)));
  s.debug_check();
}

TEST(Icmp, EchoBetweenTwoStacks) {
  t::TcpHarness h;
  h.set_delay(Side::a, 3ms);
  h.set_delay(Side::b, 4ms);
  const Time start = h.now();
  ASSERT_TRUE(h.a().icmp_echo(h.addr(Side::b), 9, 3, t::pattern(32)));
  ASSERT_TRUE(h.a().icmp_echo(h.addr(Side::b), 9, 4, t::pattern(0)));
  h.run_for(10ms);
  const auto r1 = h.a().poll_echo_reply();
  const auto r2 = h.a().poll_echo_reply();
  ASSERT_TRUE(r1.has_value() && r2.has_value());
  EXPECT_EQ(*r1, (EchoReply{9, 3, h.addr(Side::b), 32, start + 7ms}));
  EXPECT_EQ(*r2, (EchoReply{9, 4, h.addr(Side::b), 0, start + 7ms}));
  EXPECT_EQ(h.a().poll_echo_reply(), std::nullopt);
  EXPECT_EQ(h.b().poll_echo_reply(), std::nullopt);
  EXPECT_EQ(h.a().stats().IcmpOutEchos, 2u);
  EXPECT_EQ(h.a().stats().IcmpInEchoReps, 2u);
  EXPECT_EQ(h.b().stats().IcmpOutEchoReps, 2u);
  EXPECT_EQ(h.a().debug_usage().echo_replies_queued, 0u);
}

TEST(Icmp, EchoApiErrors) {
  auto cfg = config();
  cfg.tx_queue_packets = 1;
  StackImpl s(cfg);
  EXPECT_EQ(s.icmp.echo(Ipv4Addr{}, 1, 1, t::pattern(1)), std::unexpected(Error::invalid_argument));
  EXPECT_EQ(s.icmp.echo(peer, 1, 1, t::pattern(1473)), std::unexpected(Error::message_too_big));
  EXPECT_TRUE(s.icmp.echo(peer, 1, 1, t::pattern(1472)));
  EXPECT_EQ(s.icmp.echo(peer, 1, 2, t::pattern(1)), std::unexpected(Error::no_buffers));
  EXPECT_EQ(s.core.stats().IcmpOutEchos, 1u);
}

TEST(Icmp, EchoReplyOffAndQueueLimit) {
  auto cfg = config();
  cfg.icmp.echo_reply = false;
  StackImpl s(cfg);
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  s.receive(t0, t::icmp_echo_request(peer, us, 1, 1, t::pattern(8)));
  EXPECT_TRUE(drain(s).empty());
  EXPECT_EQ(s.core.stats().IcmpInEchos, 1u);
  // 70 replies arrive: 64 are queued, 6 dropped and counted.
  for (std::uint16_t i = 0; i < 70; ++i) {
    t::IpSpec ip;
    ip.src = peer;
    ip.dst = us;
    ip.proto = utcp::ip_proto_icmp;
    s.receive(t0 + std::chrono::microseconds(i),
              t::ipv4(ip, t::icmp(w::icmp_echo_reply, 0, (5u << 16) | i, t::pattern(i))));
  }
  EXPECT_EQ(s.icmp.echo_replies_queued(), 64u);
  EXPECT_EQ(s.core.stats().echo_replies_dropped, 6u);
  for (std::uint16_t i = 0; i < 64; ++i) {
    const auto r = s.icmp.poll_echo_reply();
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(*r, (EchoReply{5, i, peer, i, t0 + std::chrono::microseconds(i)}));
  }
  EXPECT_EQ(s.icmp.poll_echo_reply(), std::nullopt);
}

TEST(Icmp, EchoReplyLargerThanThePathMtuIsNotSent) {
  StackImpl s(config());
  s.advance(t0);
  s.core.pmtu_lower(peer, 600);
  s.receive(t0, t::icmp_echo_request(peer, s.core.local_addr(), 1, 1, t::pattern(1000)));
  EXPECT_TRUE(drain(s).empty());
  EXPECT_EQ(s.core.stats().IcmpOutErrors, 1u);
  s.receive(t0, t::icmp_echo_request(peer, s.core.local_addr(), 1, 2, t::pattern(572)));
  EXPECT_EQ(drain(s).size(), 1u);  // 600 bytes fit
}

// m1-ip test 3: UDP to an unbound port gets 3/3 quoting the IP header and the
// 8 UDP header bytes (the whole datagram here); a longer datagram is quoted
// up to 548 bytes (576-byte error, RFC 1812 §4.3.2.3, Linux icmp_send).
TEST(Icmp, PortUnreachableQuotesTheDatagram) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const t::Bytes d = unbound_udp(peer, us);
  ASSERT_EQ(d.size(), 28u);
  s.receive(t0, d);
  auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0], expected_icmp(us, peer, t::icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0, d)));
  EXPECT_EQ(s.core.stats().UdpNoPorts, 1u);
  EXPECT_EQ(s.core.stats().IcmpOutDestUnreachs, 1u);

  const t::Bytes big = unbound_udp(peer, us, 1000);
  t::Bytes padded = big;
  padded.resize(big.size() + 6, std::byte{0xAA});  // link padding is not quoted
  s.receive(t0 + 1s, padded);
  out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].size(), 576u);
  const t::Bytes quote(big.begin(), big.begin() + 548);
  EXPECT_EQ(out[0], expected_icmp(us, peer, t::icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0, quote)));
  // With a path MTU below 576 back to the source, the error fits it.
  s.core.pmtu_lower(peer, 552);
  s.receive(t0 + 2s, big);
  out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0].size(), 552u);
}

TEST(Icmp, UnknownProtocolGetsProtocolUnreachable) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const t::Bytes d = t::raw_datagram(peer, us, 253, t::pattern(40));
  s.receive(t0, d);
  const auto out = drain(s);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0], expected_icmp(us, peer, t::icmp(w::icmp_dest_unreach, w::icmp_proto_unreach, 0, d)));
  EXPECT_EQ(s.core.stats().IpInUnknownProtos, 1u);
  EXPECT_EQ(s.core.stats().IpInDelivers, 0u);
}

// m1-ip test 3: 1000 triggers within 1 ms give exactly the burst of 50, then
// one error per ms (rate_per_s 1000).
TEST(Icmp, ErrorsAreRateLimited) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const t::Bytes d = unbound_udp(peer, us);
  for (int i = 0; i < 1000; ++i) {
    s.receive(t0 + std::chrono::microseconds(i), d);
  }
  EXPECT_EQ(drain(s).size(), 50u);
  EXPECT_EQ(s.core.stats().IcmpOutRateLimitGlobal, 950u);
  for (int ms = 1; ms <= 20; ++ms) {
    for (int k = 0; k < 10; ++k) {
      s.receive(t0 + std::chrono::milliseconds(ms) + std::chrono::microseconds(100 * k), d);
    }
    EXPECT_EQ(drain(s).size(), 1u) << ms;
  }
  EXPECT_EQ(s.core.stats().IcmpOutDestUnreachs, 70u);
  EXPECT_EQ(s.core.stats().UdpNoPorts, 1200u);
  // After a quiet second the full burst is back (capped at 50).
  for (int i = 0; i < 60; ++i) {
    s.receive(t0 + 2s, d);
  }
  EXPECT_EQ(drain(s).size(), 50u);
  // Echo replies are not limited.
  for (std::uint16_t i = 0; i < 100; ++i) {
    s.receive(t0 + 2s, t::icmp_echo_request(peer, us, 1, i, t::pattern(4)));
  }
  EXPECT_EQ(drain(s).size(), 100u);
}

TEST(Icmp, RateLimiterArithmetic) {
  utcp::IcmpRateLimiter r(1000, 50);
  int n = 0;
  while (r.allow(t0)) {
    ++n;
  }
  EXPECT_EQ(n, 50);
  EXPECT_FALSE(r.allow(t0 + 999us));
  EXPECT_TRUE(r.allow(t0 + 1ms));
  EXPECT_FALSE(r.allow(t0 + 1ms));
  EXPECT_FALSE(r.allow(t0 + 1500us));
  EXPECT_TRUE(r.allow(t0 + 2ms));
  EXPECT_FALSE(r.allow(t0 + 1ms));  // an earlier time refills nothing
  // Long idle: capped at the burst.
  EXPECT_TRUE(r.allow(t0 + 1000s));
  EXPECT_EQ(r.tokens(), 49u);
  // 3 per second: one token every 333.33 ms, exactly.
  utcp::IcmpRateLimiter slow(3, 1);
  EXPECT_TRUE(slow.allow(t0));
  EXPECT_FALSE(slow.allow(t0 + 333'333'333ns));
  EXPECT_TRUE(slow.allow(t0 + 333'333'334ns));
  // No refill and no burst.
  utcp::IcmpRateLimiter none(0, 2);
  EXPECT_TRUE(none.allow(t0));
  EXPECT_TRUE(none.allow(t0));
  EXPECT_FALSE(none.allow(t0 + 1000s));
  utcp::IcmpRateLimiter zero(1000, 0);
  EXPECT_FALSE(zero.allow(t0 + 1s));
}

// RFC 1122 §3.2.2: no error to a source that is not one host.
TEST(Icmp, NoErrorsToNonUnicastSources) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  for (const Ipv4Addr src : {Ipv4Addr{}, Ipv4Addr::from_octets(0, 1, 2, 3),
                             Ipv4Addr::from_octets(127, 0, 0, 1), Ipv4Addr::from_octets(224, 0, 0, 1),
                             Ipv4Addr::from_octets(240, 0, 0, 1),
                             Ipv4Addr::from_octets(255, 255, 255, 255)}) {
    s.receive(t0, unbound_udp(src, us));
    s.receive(t0, t::raw_datagram(src, us, 253, t::pattern(4)));
    s.receive(t0, t::icmp_echo_request(src, us, 1, 1, t::pattern(4)));
  }
  EXPECT_TRUE(drain(s).empty());
  EXPECT_EQ(s.core.stats().UdpNoPorts, 6u);
  EXPECT_EQ(s.icmp.rate_limiter().tokens(), 50u);  // no token spent
  EXPECT_TRUE(utcp::is_unicast_source(Ipv4Addr::from_octets(223, 255, 255, 254)));
  EXPECT_TRUE(utcp::is_unicast_source(Ipv4Addr::from_octets(1, 0, 0, 0)));
}

TEST(Icmp, PlateauTable) {
  // RFC 1191 §7 Table 7-1.
  EXPECT_EQ(utcp::pmtu_plateau_below(1500), 1492);
  EXPECT_EQ(utcp::pmtu_plateau_below(1492), 1006);
  EXPECT_EQ(utcp::pmtu_plateau_below(1493), 1492);
  EXPECT_EQ(utcp::pmtu_plateau_below(65535), 32000);
  EXPECT_EQ(utcp::pmtu_plateau_below(4000), 2002);
  EXPECT_EQ(utcp::pmtu_plateau_below(576), 508);
  EXPECT_EQ(utcp::pmtu_plateau_below(69), 68);
  EXPECT_EQ(utcp::pmtu_plateau_below(68), 68);
  EXPECT_EQ(utcp::pmtu_plateau_below(0), 68);
  EXPECT_EQ(utcp::frag_needed_mtu(1400, 1500, 552), 1400);
  EXPECT_EQ(utcp::frag_needed_mtu(0, 1500, 552), 1492);
  EXPECT_EQ(utcp::frag_needed_mtu(0, 1000, 552), 552);  // plateau 508, raised to min_pmtu
  EXPECT_EQ(utcp::frag_needed_mtu(68, 1500, 552), 552);
}

t::Bytes tcp_offending(Ipv4Addr us, std::uint32_t seq, std::size_t payload) {
  t::TcpSpec spec;
  spec.src = Endpoint{us, 40000};
  spec.dst = Endpoint{peer, 80};
  spec.seq = Seq32(seq);
  spec.ack = Seq32(1);
  spec.flags = w::tcp_ack;
  spec.payload = t::pattern(payload);
  return t::tcp_datagram(spec);
}

// The error handed to TcpEngine::on_icmp_error (§4.7, §4.13).
TEST(Icmp, TcpErrorFromQuote) {
  const Ipv4Addr us = Ipv4Addr::from_octets(10, 0, 0, 1);
  const t::Bytes seg = tcp_offending(us, 0x12345678, 1460);
  const auto q = w::parse_icmp_quote(std::span<const std::byte>(seg).first(28));
  ASSERT_TRUE(q.has_value());
  const auto frag = w::icmp_unreach_header(w::icmp_frag_needed, 1400);
  auto e = utcp::tcp_icmp_error(frag, *q, 1500, 552);
  EXPECT_EQ(e.type, w::icmp_dest_unreach);
  EXPECT_EQ(e.code, w::icmp_frag_needed);
  EXPECT_EQ(e.tuple, (utcp::FourTuple{Endpoint{us, 40000}, Endpoint{peer, 80}}));
  EXPECT_EQ(e.seq, Seq32(0x12345678));
  EXPECT_EQ(e.new_pmtu, 1400);
  // Never above the cache's current value (another connection lowered it):
  // then it equals that value and is no reduction.
  EXPECT_EQ(utcp::tcp_icmp_error(frag, *q, 1300, 552).new_pmtu, 1300);
  EXPECT_EQ(utcp::tcp_icmp_error(frag, *q, 1400, 552).new_pmtu, 1400);
  // An expired entry reads as the interface MTU, so the value can be above a
  // connection's PMTU (say 1400): the engine compares it with tcb.pmtu.
  EXPECT_EQ(utcp::tcp_icmp_error(w::icmp_unreach_header(w::icmp_frag_needed, 1450), *q, 1500, 552)
                .new_pmtu,
            1450);
  // A next-hop MTU above the cache or below min_pmtu is clamped into
  // [min_pmtu, cache].
  EXPECT_EQ(utcp::tcp_icmp_error(w::icmp_unreach_header(w::icmp_frag_needed, 9000), *q, 1500, 552)
                .new_pmtu,
            1500);
  EXPECT_EQ(utcp::tcp_icmp_error(w::icmp_unreach_header(w::icmp_frag_needed, 100), *q, 1500, 552)
                .new_pmtu,
            552);
  // Next-hop MTU 0: plateau below the quoted 1500 bytes.
  EXPECT_EQ(utcp::tcp_icmp_error(w::icmp_unreach_header(w::icmp_frag_needed, 0), *q, 1500, 552).new_pmtu,
            1492);
  // Other errors carry no MTU.
  EXPECT_EQ(utcp::tcp_icmp_error(w::icmp_unreach_header(w::icmp_port_unreach, 0), *q, 1500, 552).new_pmtu,
            0);
  const w::IcmpHeader ttl{w::icmp_time_exceeded, 0, 0, 0};
  EXPECT_EQ(utcp::tcp_icmp_error(ttl, *q, 1500, 552).new_pmtu, 0);
  EXPECT_EQ(utcp::tcp_icmp_error(ttl, *q, 1500, 552).type, w::icmp_time_exceeded);
}

// Received errors: counted by type; malformed ones dropped; TCP quotes go to
// the engine (which finds no connection for them here), and nothing is sent
// back.
TEST(Icmp, ReceivedErrorsAreCountedAndDispatched) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const Ipv4Addr router = Ipv4Addr::from_octets(192, 0, 2, 254);
  const t::Bytes seg = tcp_offending(us, 1000, 100);
  auto receive_icmp = [&](const t::Bytes& message) {
    t::IpSpec ip;
    ip.src = router;
    ip.dst = us;
    ip.proto = utcp::ip_proto_icmp;
    s.receive(t0, t::ipv4(ip, message));
  };
  const auto& st = s.core.stats();
  receive_icmp(t::icmp(w::icmp_dest_unreach, w::icmp_frag_needed, 1400, seg));
  receive_icmp(t::icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0,
                       std::span<const std::byte>(seg).first(28)));
  receive_icmp(t::icmp(w::icmp_time_exceeded, 0, 0, std::span<const std::byte>(seg).first(28)));
  EXPECT_EQ(st.IcmpInDestUnreachs, 2u);
  EXPECT_EQ(st.IcmpInTimeExcds, 1u);
  EXPECT_EQ(st.IcmpInErrors, 0u);
  // TCP errors do not touch the cache: the engine does after its sequence
  // check (RFC 5927 §4.1).
  EXPECT_EQ(s.core.pmtu(peer), 1500);
  // A quote shorter than the IPv4 header + 8 bytes.
  receive_icmp(t::icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0,
                       std::span<const std::byte>(seg).first(27)));
  EXPECT_EQ(st.IcmpInErrors, 1u);
  // Bad checksum; shorter than the 8-byte header.
  receive_icmp(t::icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0, seg, true));
  EXPECT_EQ(st.IcmpInCsumErrors, 1u);
  EXPECT_EQ(st.IcmpInErrors, 2u);
  receive_icmp(t::Bytes(7, std::byte{0}));
  EXPECT_EQ(st.IcmpInErrors, 3u);
  // Source quench (RFC 6633) and redirect: counted, ignored.
  receive_icmp(t::icmp(w::icmp_source_quench, 0, 0, std::span<const std::byte>(seg).first(28)));
  receive_icmp(t::icmp(w::icmp_redirect, 1, router.v, std::span<const std::byte>(seg).first(28)));
  EXPECT_EQ(st.IcmpInSrcQuenchs, 1u);
  EXPECT_EQ(st.IcmpInRedirects, 1u);
  // A quote of someone else's datagram is ignored.
  const t::Bytes foreign = tcp_offending(Ipv4Addr::from_octets(10, 9, 9, 9), 1, 10);
  receive_icmp(t::icmp(w::icmp_dest_unreach, w::icmp_frag_needed, 600, foreign));
  EXPECT_EQ(st.IcmpInMsgs, 9u);
  EXPECT_TRUE(drain(s).empty());  // ICMP errors are never answered
  s.debug_check();
}

// Records what IcmpLayer hands to TCP.
class TcpErrorRecorder final : public utcp::TcpIcmpSink {
public:
  void on_icmp_error(Time now, const utcp::TcpIcmpError& e) override {
    times.push_back(now);
    got.push_back(e);
  }
  std::vector<Time> times;
  std::vector<utcp::TcpIcmpError> got;
};

// Received errors quoting TCP reach TcpEngine::on_icmp_error through
// Stack::receive with the quoted tuple and sequence number (§4.7, §4.13), as
// Linux icmp_unreach/tcp_v4_err: destination unreachable codes 0-15, time
// exceeded and parameter problem; not codes above 15, source quench,
// redirects, or quotes of other hosts' or other protocols' datagrams.
TEST(Icmp, TcpErrorsReachTheEngineThroughReceive) {
  StackImpl s(config());
  TcpErrorRecorder rec;
  s.icmp.set_tcp_sink(&rec);
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const Ipv4Addr router = Ipv4Addr::from_octets(192, 0, 2, 254);
  const t::Bytes seg = tcp_offending(us, 1000, 100);
  const auto quote = std::span<const std::byte>(seg).first(28);
  auto receive_icmp = [&](std::uint8_t type, std::uint8_t code, std::uint32_t rest,
                          std::span<const std::byte> body) {
    t::IpSpec ip;
    ip.src = router;
    ip.dst = us;
    ip.proto = utcp::ip_proto_icmp;
    s.receive(s.core.now(), t::ipv4(ip, t::icmp(type, code, rest, body)));
  };
  const utcp::FourTuple tuple{Endpoint{us, 40000}, Endpoint{peer, 80}};
  receive_icmp(w::icmp_dest_unreach, w::icmp_frag_needed, 1400, seg);
  ASSERT_EQ(rec.got.size(), 1u);
  EXPECT_EQ(rec.times[0], t0);
  EXPECT_EQ(rec.got[0].type, w::icmp_dest_unreach);
  EXPECT_EQ(rec.got[0].code, w::icmp_frag_needed);
  EXPECT_EQ(rec.got[0].tuple, tuple);
  EXPECT_EQ(rec.got[0].seq, Seq32(1000));
  EXPECT_EQ(rec.got[0].new_pmtu, 1400);
  // The IP layer leaves the cache alone (the engine lowers it after its
  // sequence check); new_pmtu follows the cache.
  EXPECT_EQ(s.core.pmtu(peer), 1500);
  s.core.pmtu_lower(peer, 1300);
  receive_icmp(w::icmp_dest_unreach, w::icmp_frag_needed, 1400, seg);
  ASSERT_EQ(rec.got.size(), 2u);
  EXPECT_EQ(rec.got[1].new_pmtu, 1300);
  // After the entry expires the cache reads 1500 again.
  s.advance(t0 + 10min);
  receive_icmp(w::icmp_dest_unreach, w::icmp_frag_needed, 1450, seg);
  ASSERT_EQ(rec.got.size(), 3u);
  EXPECT_EQ(rec.got[2].new_pmtu, 1450);
  EXPECT_EQ(rec.times[2], t0 + 10min);
  // Other errors carry no MTU.
  receive_icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0, quote);
  receive_icmp(w::icmp_dest_unreach, 15, 0, quote);  // precedence cutoff, the last code
  receive_icmp(w::icmp_time_exceeded, 0, 0, quote);
  receive_icmp(utcp::icmp_parameter_problem, 0, 20u << 24, quote);
  ASSERT_EQ(rec.got.size(), 7u);
  const std::vector<std::pair<std::uint8_t, std::uint8_t>> want{
      {w::icmp_dest_unreach, w::icmp_port_unreach},
      {w::icmp_dest_unreach, 15},
      {w::icmp_time_exceeded, 0},
      {utcp::icmp_parameter_problem, 0}};
  for (std::size_t i = 0; i < want.size(); ++i) {
    EXPECT_EQ(rec.got[3 + i].type, want[i].first);
    EXPECT_EQ(rec.got[3 + i].code, want[i].second);
    EXPECT_EQ(rec.got[3 + i].tuple, tuple);
    EXPECT_EQ(rec.got[3 + i].seq, Seq32(1000));
    EXPECT_EQ(rec.got[3 + i].new_pmtu, 0);
  }
  EXPECT_EQ(s.core.stats().IcmpInParmProbs, 1u);
  // Not dispatched.
  const auto dest_unreachs = s.core.stats().IcmpInDestUnreachs;
  receive_icmp(w::icmp_dest_unreach, 16, 0, quote);  // above NR_ICMP_UNREACH
  receive_icmp(w::icmp_dest_unreach, 255, 0, quote);
  EXPECT_EQ(s.core.stats().IcmpInDestUnreachs, dest_unreachs + 2);  // counted all the same
  receive_icmp(w::icmp_source_quench, 0, 0, quote);
  receive_icmp(w::icmp_redirect, 1, router.v, quote);
  receive_icmp(13, 0, 0, quote);  // timestamp request: ignored
  const t::Bytes foreign = tcp_offending(Ipv4Addr::from_octets(10, 9, 9, 9), 1, 10);
  receive_icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0,
               std::span<const std::byte>(foreign).first(28));
  const t::Bytes udp = t::udp_datagram(t::UdpSpec{Endpoint{us, 7}, Endpoint{peer, 7}, t::pattern(4)});
  receive_icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0, udp);
  receive_icmp(w::icmp_dest_unreach, w::icmp_port_unreach, 0, quote.first(27));  // short quote
  EXPECT_EQ(rec.got.size(), 7u);
  EXPECT_TRUE(drain(s).empty());
  s.debug_check();
}

// UDP gets the same set: parameter problem is counted for it, codes above
// 15 are not.
TEST(Icmp, UdpErrorsFollowTheSameCodeRules) {
  StackImpl s(config());
  s.advance(t0);
  const Ipv4Addr us = s.core.local_addr();
  const t::Bytes udp = t::udp_datagram(t::UdpSpec{Endpoint{us, 7}, Endpoint{peer, 7}, t::pattern(4)});
  auto receive_icmp = [&](std::uint8_t type, std::uint8_t code) {
    s.receive(t0, t::icmp_error(peer, us, type, code, 0, udp, 28));
  };
  receive_icmp(utcp::icmp_parameter_problem, 0);
  EXPECT_EQ(s.core.stats().udp_icmp_errors, 1u);
  receive_icmp(w::icmp_dest_unreach, 16);
  EXPECT_EQ(s.core.stats().udp_icmp_errors, 1u);
  receive_icmp(w::icmp_dest_unreach, w::icmp_port_unreach);
  EXPECT_EQ(s.core.stats().udp_icmp_errors, 2u);
  EXPECT_EQ(s.core.stats().IcmpInParmProbs, 1u);
  EXPECT_EQ(s.core.stats().IcmpInDestUnreachs, 2u);
}

}  // namespace
