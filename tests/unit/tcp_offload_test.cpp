#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "support/packet_builder.hpp"
#include "support/tcp_harness.hpp"
#include "utcp/tun_device.hpp"

namespace {

using namespace std::chrono_literals;
using namespace utcp;
namespace t = utcp::test;
namespace w = utcp::wire;

constexpr std::uint16_t mss = 1460;
constexpr std::uint32_t peer_isn = 0xffff'fc00u;
constexpr std::uint32_t our_isn = 123;
constexpr std::uint16_t port = 8080;

struct ConnectedStack {
  static StackConfig config() {
    StackConfig c = t::TcpHarness::default_config(t::Side::a);
    c.tcp.test_isn = our_isn;
    c.tcp.timestamps = false;
    c.tcp.initial_cwnd = 4;
    return c;
  }

  const Time now{1'000'000'000};
  explicit ConnectedStack(const StackConfig& cfg = config()) : stack(cfg) {}
  Stack stack;
  const Endpoint peer{Ipv4Addr::from_octets(192, 0, 2, 2), 41000};
  const Endpoint local{stack.config().local_addr, port};
  Handle server{};

  void connect() {
    const auto listener = stack.tcp_listen(local, 1);
    ASSERT_TRUE(listener);
    t::TcpSpec syn(peer, local);
    syn.seq = Seq32{peer_isn};
    syn.flags = w::tcp_syn;
    syn.opt.mss = mss;
    stack.receive(now, t::tcp_datagram(syn));
    ASSERT_TRUE(stack.pop_transmit());
    t::TcpSpec ack = incoming(0);
    stack.receive(now, t::tcp_datagram(ack));
    const auto accepted = stack.tcp_accept(*listener);
    ASSERT_TRUE(accepted);
    server = *accepted;
    ASSERT_FALSE(stack.pop_transmit());
  }

  t::TcpSpec incoming(std::uint32_t offset) const {
    t::TcpSpec seg(peer, local);
    seg.seq = Seq32{peer_isn} + (1 + offset);
    seg.ack = Seq32{our_isn + 1};
    seg.flags = w::tcp_ack;
    return seg;
  }
};

TEST(TcpOffload, InOrderGroDeliversWrappedSequenceAndCountsEachSegment) {
  ConnectedStack c;
  ASSERT_NO_FATAL_FAILURE(c.connect());
  auto data = c.incoming(0);
  data.flags |= w::tcp_psh;
  data.payload = t::pattern(2 * mss + 13);
  data.corrupt_checksum = true;  // the trusted host already checked the L4 checksum
  const auto before = c.stack.tcp_info(c.server).value();
  const std::uint64_t packets = c.stack.stats().TcpInSegs;

  c.stack.receive(c.now, t::tcp_datagram(data), RxMeta{true, false, mss});

  const auto after = c.stack.tcp_info(c.server).value();
  EXPECT_EQ(after.segs_in - before.segs_in, 3u);
  EXPECT_EQ(after.data_segs_in - before.data_segs_in, 3u);
  EXPECT_EQ(c.stack.stats().TcpInSegs - packets, 3u);
  auto ack = c.stack.pop_transmit();
  ASSERT_TRUE(ack);
  const auto ip = w::parse_ipv4(ack->buf.bytes());
  ASSERT_TRUE(ip);
  const auto tcp = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
  ASSERT_TRUE(tcp);
  EXPECT_EQ(tcp->h.ack.raw(), 1910u);
  auto got = t::Bytes(data.payload.size());
  EXPECT_EQ(c.stack.tcp_recv(c.server, got).value_or(0), data.payload.size());
  EXPECT_EQ(got, data.payload);
}

TEST(TcpOffload, OutOfOrderGroUsesLogicalReceivePath) {
  ConnectedStack c;
  ASSERT_NO_FATAL_FAILURE(c.connect());
  auto data = c.incoming(mss);
  data.payload = t::pattern(2 * mss, 21);
  const std::uint64_t ofo = c.stack.stats().TcpExtTCPOFOQueue;
  c.stack.receive(c.now, t::tcp_datagram(data), RxMeta{true, false, mss});
  EXPECT_EQ(c.stack.stats().TcpExtTCPOFOQueue - ofo, 2u);
  auto got = t::Bytes(3 * mss);
  EXPECT_FALSE(c.stack.tcp_recv(c.server, got));
  auto first = c.incoming(0);
  first.payload = t::pattern(mss, 42);
  c.stack.receive(c.now + 1ms, t::tcp_datagram(first));
  ASSERT_EQ(c.stack.tcp_recv(c.server, got).value_or(0), got.size());
  first.payload.insert(first.payload.end(), data.payload.begin(), data.payload.end());
  EXPECT_EQ(got, first.payload);
}

TEST(TcpOffload, PartialChecksumPlacesPseudoHeaderSumInOrdinaryPackets) {
  auto cfg = ConnectedStack::config();
  cfg.tcp_checksum_offload = true;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  const auto data = t::pattern(51);
  ASSERT_EQ(c.stack.tcp_send(c.server, data).value_or(0), data.size());
  auto sent = c.stack.pop_transmit();
  ASSERT_TRUE(sent);
  EXPECT_TRUE(sent->csum_partial);
  EXPECT_EQ(sent->gso_size, 0u);
  auto ip = w::parse_ipv4(sent->buf.bytes());
  ASSERT_TRUE(ip);
  // 10.0.0.1 + 192.0.2.2 + TCP(6) + L4 length(71) in one's complement.
  EXPECT_EQ(w::load_be16(ip->payload, 16), 0xcc50);
  const auto tcp = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, false);
  ASSERT_TRUE(tcp);
  EXPECT_EQ(t::Bytes(tcp->payload.begin(), tcp->payload.end()), data);
}

TEST(TcpOffload, FreshGsoIsBoundedByTheLogicalCwndAndRetainsPerSegmentRecovery) {
  auto cfg = ConnectedStack::config();
  cfg.tcp_checksum_offload = true;
  cfg.tcp_gso_buffers = 2;
  cfg.tcp.pacing = Pacing::never;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  const auto data = t::pattern(6 * mss + 5);
  ASSERT_EQ(c.stack.tcp_send(c.server, data).value_or(0), data.size());
  auto sent = c.stack.pop_transmit();
  ASSERT_TRUE(sent);
  EXPECT_EQ(sent->gso_size, mss);
  EXPECT_TRUE(sent->csum_partial);
  auto ip = w::parse_ipv4(sent->buf.bytes());
  ASSERT_TRUE(ip);
  auto tcp = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, false);
  ASSERT_TRUE(tcp);
  EXPECT_EQ(tcp->payload.size(), 4u * mss);
  EXPECT_EQ(t::Bytes(tcp->payload.begin(), tcp->payload.end()),
            t::Bytes(data.begin(), data.begin() + 4 * mss));
  EXPECT_EQ(c.stack.tcp_info(c.server)->unacked, 4u);
  EXPECT_EQ(c.stack.tcp_info(c.server)->data_segs_out, 4u);
  EXPECT_FALSE(c.stack.pop_transmit());

  // Withhold all ACKs. A timer-driven retransmission is one logical segment.
  Time deadline = c.stack.next_deadline();
  ASSERT_NE(deadline, Time::never());
  c.stack.advance(deadline);
  auto retry = c.stack.pop_transmit();
  ASSERT_TRUE(retry);
  EXPECT_EQ(retry->gso_size, 0u);
  ip = w::parse_ipv4(retry->buf.bytes());
  ASSERT_TRUE(ip);
  tcp = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, false);
  ASSERT_TRUE(tcp);
  EXPECT_EQ(tcp->payload.size(), mss);
  EXPECT_EQ(c.stack.stats().TcpRetransSegs, 1u);
}

TEST(TcpOffload, InOrderGroFallsBackUnderChunkPressure) {
  auto cfg = ConnectedStack::config();
  cfg.chunk_limit = 1;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  auto data = c.incoming(0);
  constexpr auto segments_that_fit = utcp::ring_chunk_bytes / mss;
  data.payload = t::pattern((segments_that_fit + 1) * mss, 21);
  c.stack.receive(c.now, t::tcp_datagram(data), RxMeta{true, false, mss});
  auto got = t::Bytes(segments_that_fit * mss);
  ASSERT_EQ(c.stack.tcp_recv(c.server, got).value_or(0), got.size());
  EXPECT_EQ(got, t::Bytes(data.payload.begin(), data.payload.begin() + segments_that_fit * mss));
}

TEST(TcpOffload, HeldLargePacketFallsBackToOrdinaryFramesWithoutDroppingData) {
  auto cfg = ConnectedStack::config();
  cfg.tcp_checksum_offload = true;
  cfg.tcp_gso_buffers = 1;
  cfg.tcp.pacing = Pacing::never;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  const auto data = t::pattern(8 * mss);
  ASSERT_EQ(c.stack.tcp_send(c.server, data).value_or(0), data.size());
  const auto held = c.stack.pop_transmit();
  ASSERT_TRUE(held);
  ASSERT_EQ(held->gso_size, mss);

  auto ack = c.incoming(0);
  ack.ack += 4 * mss;
  c.stack.receive(c.now + 1ms, t::tcp_datagram(ack));
  for (std::uint32_t i = 4; i < 8; ++i) {
    auto p = c.stack.pop_transmit();
    ASSERT_TRUE(p);
    EXPECT_EQ(p->gso_size, 0u);
    EXPECT_TRUE(p->csum_partial);
    const auto ip = w::parse_ipv4(p->buf.bytes());
    ASSERT_TRUE(ip);
    const auto tcp = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, false);
    ASSERT_TRUE(tcp);
    EXPECT_EQ(tcp->h.seq.raw(), our_isn + 1 + i * mss);
    EXPECT_EQ(t::Bytes(tcp->payload.begin(), tcp->payload.end()),
              t::Bytes(data.begin() + i * mss, data.begin() + (i + 1) * mss));
  }
  EXPECT_FALSE(c.stack.pop_transmit());
}

TEST(TcpOffload, PacedGsoFitsTheCurrentBurstAndWaitsForTheNextGate) {
  auto cfg = ConnectedStack::config();
  cfg.tcp_checksum_offload = true;
  cfg.tcp_gso_buffers = 16;
  cfg.tcp.pacing = Pacing::always;
  cfg.tcp.test_fixed_pacing_rate = 100'000;
  cfg.tcp.gso_max_size = 2 * mss;
  cfg.tcp.initial_cwnd = 16;
  cfg.tcp.snd_buf_init = 64 * 1024;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  const auto data = t::pattern(12 * mss + 7);
  ASSERT_EQ(c.stack.tcp_send(c.server, data).value_or(0), data.size());
  for (unsigned i = 0; i < 5; ++i) {
    auto p = c.stack.pop_transmit();
    ASSERT_TRUE(p);
    ASSERT_EQ(p->gso_size, mss);
    EXPECT_EQ(p->buf.size(), 40u + 2 * mss);
  }
  EXPECT_FALSE(c.stack.pop_transmit());
  EXPECT_EQ(c.stack.tcp_info(c.server)->data_segs_out, 10u);
  const auto gate = c.stack.next_deadline();
  ASSERT_GT(gate, c.now + 1ns);
  c.stack.advance(gate - 1ns);
  EXPECT_FALSE(c.stack.pop_transmit());
  c.stack.advance(gate);
  auto p = c.stack.pop_transmit();
  ASSERT_TRUE(p);
  EXPECT_EQ(p->gso_size, mss);
  EXPECT_EQ(p->buf.size(), 40u + 2 * mss);
}

TEST(TcpOffload, DecodeVnetChecksOffsetsTypeStrideAndDatagramLength) {
  ConnectedStack c;
  auto data = c.incoming(0);
  data.payload = t::pattern(2 * mss + 1);
  // flags: NEEDS_CSUM; TCPv4; 64-byte linear hint; stride 1460; start 20; offset 16.
  t::Bytes frame{std::byte{1}, std::byte{1}, std::byte{64}, std::byte{0}, std::byte{180},
                 std::byte{5}, std::byte{20}, std::byte{0}, std::byte{16}, std::byte{0}};
  const auto ip = t::tcp_datagram(data);
  frame.insert(frame.end(), ip.begin(), ip.end());
  const auto good = decode_tun_vnet(frame, TunOffload::tcpv4);
  ASSERT_TRUE(good);
  EXPECT_EQ(good->segments, 3u);
  EXPECT_EQ(good->meta.gso_size, mss);
  EXPECT_TRUE(good->meta.csum_partial);
  EXPECT_EQ(t::Bytes(good->ip.begin(), good->ip.end()), ip);
  EXPECT_FALSE(decode_tun_vnet(frame, TunOffload::checksum));
  EXPECT_FALSE(decode_tun_vnet(std::span(frame).first(frame.size() - 1), TunOffload::tcpv4));

  for (const auto& [at, bad] :
       {std::pair{0u, std::byte{3}}, std::pair{1u, std::byte{4}}, std::pair{3u, std::byte{32}},
        std::pair{5u, std::byte{64}}, std::pair{6u, std::byte{24}}, std::pair{8u, std::byte{6}}}) {
    const auto old = frame[at];
    frame[at] = bad;
    EXPECT_FALSE(decode_tun_vnet(frame, TunOffload::tcpv4)) << at;
    frame[at] = old;
  }
  frame[0] = std::byte{2}; // DATA_VALID may not supply partial checksum offsets.
  EXPECT_FALSE(decode_tun_vnet(frame, TunOffload::tcpv4));
  frame[6] = frame[8] = std::byte{0};
  const auto verified = decode_tun_vnet(frame, TunOffload::tcpv4);
  ASSERT_TRUE(verified);
  EXPECT_TRUE(verified->meta.csum_verified);
  EXPECT_FALSE(verified->meta.csum_partial);
}

}  // namespace
