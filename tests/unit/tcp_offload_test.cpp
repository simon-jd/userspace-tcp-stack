#include <gtest/gtest.h>

#include <algorithm>
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

  void receive_piece(std::uint32_t off, std::span<const std::byte> bytes, bool fin = false) {
    auto s = incoming(off);
    s.payload.assign(bytes.begin(), bytes.end());
    if (fin) {
      s.flags |= w::tcp_fin;
    }
    stack.receive(now, t::tcp_datagram(s));
  }

  t::TcpSpec incoming(std::uint32_t offset) const {
    t::TcpSpec seg(peer, local);
    seg.seq = Seq32{peer_isn} + (1 + offset);
    seg.ack = Seq32{our_isn + 1};
    seg.flags = w::tcp_ack;
    return seg;
  }
};

TEST(TcpOffload, VnetGroFrameUsesTheOriginalPayloadAcrossChunks) {
  ConnectedStack c;
  ASSERT_NO_FATAL_FAILURE(c.connect());
  auto seg = c.incoming(0);
  seg.payload = t::pattern(3 * mss + 17, 129);
  const auto ip = t::tcp_datagram(seg);
  t::Bytes frame(tun_vnet_header_size);
  frame[0] = std::byte{2};  // DATA_VALID, TCPv4, little-endian stride.
  frame[1] = std::byte{1};
  frame[2] = std::byte{40};
  frame[4] = static_cast<std::byte>(mss & 255u);
  frame[5] = static_cast<std::byte>(mss >> 8);
  frame.insert(frame.end(), ip.begin(), ip.end());
  const auto decoded = decode_tun_vnet(frame, TunOffload::tcpv4);
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->ip.data(), frame.data() + tun_vnet_header_size);
  EXPECT_EQ(decoded->segments, 4u);
  c.stack.receive(c.now, decoded->ip, decoded->meta);
  t::Bytes got(seg.payload.size());
  ASSERT_EQ(c.stack.tcp_recv(c.server, got).value_or(0), got.size());
  EXPECT_EQ(got, seg.payload);
}

TEST(TcpOffload, PartialSendAndShortReadsKeepTheAcceptedBytes) {
  auto cfg = ConnectedStack::config();
  cfg.chunk_limit = 1;
  cfg.tcp.nodelay = true;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  const auto data = t::pattern(5059, 171);
  constexpr std::uint32_t accepted = 4096;
  ASSERT_EQ(c.stack.tcp_send(c.server, data).value_or(0), accepted);
  t::Bytes on_wire;
  while (const auto packet = c.stack.pop_transmit()) {
    const auto ip = w::parse_ipv4(packet->buf.bytes());
    ASSERT_TRUE(ip);
    const auto tcp = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
    ASSERT_TRUE(tcp);
    ASSERT_EQ(tcp->h.seq.raw(), our_isn + 1 + on_wire.size());
    on_wire.insert(on_wire.end(), tcp->payload.begin(), tcp->payload.end());
  }
  ASSERT_EQ(on_wire, t::Bytes(data.begin(), data.begin() + accepted));
  auto ack = c.incoming(0);
  ack.ack += accepted;
  c.stack.receive(c.now, t::tcp_datagram(ack));
  const auto peer_data = t::pattern(accepted, 57);
  for (std::uint32_t off = 0; off < accepted; off += mss) {
    c.receive_piece(off, std::span(peer_data).subspan(off, std::min<std::size_t>(mss, accepted - off)));
  }
  t::Bytes got(accepted);
  ASSERT_EQ(c.stack.tcp_recv(c.server, std::span(got).first(517)).value_or(0), 517u);
  ASSERT_EQ(c.stack.tcp_recv(c.server, std::span(got).subspan(517)).value_or(0), accepted - 517);
  EXPECT_EQ(got, peer_data);
}

TEST(TcpOffload, ReadShutdownWithUnreadPrefixAndPendingFinPreservesAdmission) {
  auto cfg = ConnectedStack::config();
  cfg.chunk_limit = 3;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  constexpr std::uint32_t prefix = 4500, gap_end = 8192, end = gap_end + 41;
  const auto data = t::pattern(end, 91);
  auto feed = [&](std::uint32_t start, std::uint32_t stop) {
    for (auto off = start; off < stop; off += mss) {
      c.receive_piece(off, std::span(data).subspan(off, std::min<std::uint32_t>(mss, stop - off)));
    }
  };
  feed(0, prefix);
  t::Bytes got(73);
  ASSERT_EQ(c.stack.tcp_recv(c.server, got).value_or(0), 73u);
  EXPECT_EQ(got, t::Bytes(data.begin(), data.begin() + 73));
  c.receive_piece(gap_end, std::span(data).subspan(gap_end), true);
  EXPECT_EQ(c.stack.tcp_info(c.server)->state, TcpState::established);
  EXPECT_EQ(c.stack.debug_usage().chunks_free, 0u);
  ASSERT_TRUE(c.stack.tcp_shutdown(c.server, Shutdown::read));
  EXPECT_EQ(c.stack.debug_usage().chunks_free, 1u);
  EXPECT_EQ(c.stack.tcp_recv(c.server, got).value_or(99), 0u);
  feed(prefix, gap_end);
  const auto info = c.stack.tcp_info(c.server);
  ASSERT_TRUE(info);
  EXPECT_EQ(info->state, TcpState::close_wait);
  EXPECT_EQ(info->bytes_received, end);
  EXPECT_EQ(c.stack.debug_usage().chunks_free, 3u);
  EXPECT_EQ(c.stack.tcp_recv(c.server, got).value_or(99), 0u);
  std::uint32_t last_ack = 0;
  while (const auto packet = c.stack.pop_transmit()) {
    const auto ip = w::parse_ipv4(packet->buf.bytes());
    ASSERT_TRUE(ip);
    const auto tcp = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
    ASSERT_TRUE(tcp);
    last_ack = tcp->h.ack.raw();
  }
  EXPECT_EQ(last_ack, peer_isn + 1u + end + 1u);
  c.stack.debug_check();
}

TEST(TcpOffload, ReadShutdownStillChargesOutOfOrderChunksAndPrunesOnHoleFill) {
  auto cfg = ConnectedStack::config();
  cfg.chunk_limit = 1;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  ASSERT_TRUE(c.stack.tcp_shutdown(c.server, Shutdown::read));
  const auto block = t::pattern(4096, 19);
  c.receive_piece(4096, std::span(block).first(17));
  EXPECT_EQ(c.stack.debug_usage().chunks - c.stack.debug_usage().chunks_free, 1u);
  c.receive_piece(8192, std::span(block).first(23));
  EXPECT_EQ(c.stack.stats().TcpExtTCPOFODrop, 1u);
  EXPECT_EQ(c.stack.tcp_info(c.server)->bytes_received, 0u);
  for (std::uint32_t off = 0; off < block.size(); off += mss) {
    c.receive_piece(off, std::span(block).subspan(off, std::min<std::size_t>(mss, block.size() - off)));
  }
  EXPECT_EQ(c.stack.stats().TcpExtOfoPruned, 1u);
  EXPECT_EQ(c.stack.tcp_info(c.server)->bytes_received, 4096u);
  c.receive_piece(4096, std::span(block).first(17), true);
  EXPECT_EQ(c.stack.tcp_info(c.server)->bytes_received, 4113u);
  EXPECT_EQ(c.stack.tcp_info(c.server)->state, TcpState::close_wait);
  EXPECT_EQ(c.stack.debug_usage().chunks_free, 1u);
  c.stack.debug_check();
}

TEST(TcpOffload, ShutdownBothDiscardsUnreadDataAndSendsFin) {
  ConnectedStack c;
  ASSERT_NO_FATAL_FAILURE(c.connect());
  c.receive_piece(0, t::pattern(183, 121), true);
  ASSERT_EQ(c.stack.tcp_info(c.server)->state, TcpState::close_wait);
  ASSERT_TRUE(c.stack.tcp_shutdown(c.server, Shutdown::both));
  EXPECT_EQ(c.stack.tcp_info(c.server)->state, TcpState::last_ack);
  EXPECT_EQ(c.stack.debug_usage().chunks_free, 1u);
  bool fin = false;
  while (const auto packet = c.stack.pop_transmit()) {
    const auto ip = w::parse_ipv4(packet->buf.bytes());
    ASSERT_TRUE(ip);
    const auto tcp = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
    ASSERT_TRUE(tcp);
    fin |= (tcp->h.flags & w::tcp_fin) != 0;
  }
  EXPECT_TRUE(fin);
}

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
  // Deliver the same valid out-of-order data again. Neither copy may
  // replace the first bytes, and only the missing prefix remains to insert.
  c.stack.receive(c.now, t::tcp_datagram(data), RxMeta{true, false, mss});
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
  cfg.tx_headroom = tun_vnet_header_size;
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
  const auto before_framing = sent->buf.bytes();
  EXPECT_EQ(prepend_tun_vnet(*sent), 4u);
  const auto decoded = decode_tun_vnet(sent->buf.bytes(), TunOffload::tcpv4);
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->ip.data(), before_framing.data());
  EXPECT_EQ(decoded->ip.size(), before_framing.size());
  EXPECT_EQ(decoded->segments, 4u);
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
  const auto offset = tcp->h.seq.raw() - our_isn - 1u;
  ASSERT_LE(offset + mss, 4u * mss);
  EXPECT_EQ(t::Bytes(tcp->payload.begin(), tcp->payload.end()),
            t::Bytes(data.begin() + offset, data.begin() + offset + mss));
  EXPECT_EQ(c.stack.stats().TcpRetransSegs, 1u);
}

TEST(TcpOffload, InOrderGroFallsBackUnderChunkPressure) {
  auto cfg = ConnectedStack::config();
  cfg.chunk_limit = 1;
  ConnectedStack c(cfg);
  ASSERT_NO_FATAL_FAILURE(c.connect());
  auto data = c.incoming(0);
  data.payload = t::pattern(3 * mss, 21);
  c.stack.receive(c.now, t::tcp_datagram(data), RxMeta{true, false, mss});
  auto got = t::Bytes(2 * mss);
  ASSERT_EQ(c.stack.tcp_recv(c.server, got).value_or(0), got.size());
  EXPECT_EQ(got, t::Bytes(data.payload.begin(), data.payload.begin() + 2 * mss));
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
