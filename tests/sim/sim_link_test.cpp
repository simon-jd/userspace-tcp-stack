// Link segment statistics, rate and queue, corruption and the MTU router
// (m1-sim acceptance tests 1-4).
#include <gtest/gtest.h>

#include <bit>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "core/wire/udp.hpp"
#include "utcp/checksum.hpp"
#include "utcp/random.hpp"
#include "utcp/sim/datagram.hpp"
#include "utcp/sim/digest.hpp"
#include "utcp/sim/link.hpp"

namespace utcp::sim {
namespace {

using namespace std::chrono_literals;

constexpr std::uint64_t million = 1'000'000;

struct Delivery {
  Time t;
  std::vector<std::byte> bytes;
  DeliveryInfo info;
};

// Records what a segment emits.
class RecordingSink final : public LinkSink {
public:
  explicit RecordingSink(bool keep_bytes = true) : keep_(keep_bytes) {}
  void deliver(Time t, std::span<const std::byte> d, const DeliveryInfo& info) override {
    deliveries.push_back(Delivery{t, keep_ ? std::vector<std::byte>(d.begin(), d.end())
                                           : std::vector<std::byte>{},
                                  info});
  }
  void reply(Time t, std::span<const std::byte> icmp) override {
    replies.push_back(Delivery{t, std::vector<std::byte>(icmp.begin(), icmp.end()), {}});
  }
  std::vector<Delivery> deliveries;
  std::vector<Delivery> replies;

private:
  bool keep_;
};

// Counts deliveries and remembers the last time only.
class CountingSink final : public LinkSink {
public:
  void deliver(Time t, std::span<const std::byte>, const DeliveryInfo& info) override {
    ++delivered;
    duplicates += info.duplicate ? 1u : 0u;
    if (t < last) {
      ++overtaken;
    }
    last = t;
  }
  void reply(Time, std::span<const std::byte>) override { ++replies; }
  std::uint64_t delivered = 0, duplicates = 0, overtaken = 0, replies = 0;
  Time last{};
};

std::vector<std::byte> tcp_packet(std::uint32_t seq, std::size_t payload_len, bool df = true,
                                  bool timestamps = false) {
  TcpSegmentSpec s;
  if (timestamps) {
    s.opt.ts = wire::Timestamps{seq * 3, seq * 5};
  }
  s.src = Endpoint{node_addr(0), 40000};
  s.dst = Endpoint{node_addr(1), 5000};
  s.seq = seq;
  s.ack = 1000;
  s.flags = wire::tcp_ack | wire::tcp_psh;
  s.window = 512;
  s.df = df;
  std::vector<std::byte> payload(payload_len);
  for (std::size_t i = 0; i < payload_len; ++i) {
    payload[i] = static_cast<std::byte>(seq + i);
  }
  s.payload = payload;
  return build_tcp(s);
}

std::vector<std::byte> udp_packet(std::uint32_t n, std::size_t payload_len) {
  std::vector<std::byte> payload(payload_len);
  for (std::size_t i = 0; i < payload_len; ++i) {
    payload[i] = static_cast<std::byte>(n * 7 + i);
  }
  return build_udp(Endpoint{node_addr(0), 40001}, Endpoint{node_addr(1), 7}, payload,
                   static_cast<std::uint16_t>(n));
}

const Seed master = Seed::from_u64(42);

// --- Test 1: statistics over 1e6 packets with fixed seeds.

TEST(SimLink, BernoulliLossWithinPointOnePercent) {
  LinkParams p;
  p.loss_ppm = 10'000;  // 1 %
  Link link(p, master, "a>b");
  CountingSink sink;
  const auto d = udp_packet(1, 16);
  Time t{1'000'000'000};
  for (std::uint64_t i = 0; i < million; ++i) {
    link.send(t, d, sink);
    t += 1us;
  }
  const std::uint64_t lost = million - sink.delivered;
  EXPECT_EQ(link.stats().lost, lost);
  // 1 % +- 0.1 % absolute: 9000..11000 of 1e6.
  EXPECT_GE(lost, 9'000u);
  EXPECT_LE(lost, 11'000u);
}

TEST(SimLink, DuplicationWithinPointOnePercent) {
  LinkParams p;
  p.dup_ppm = 10'000;
  p.dup_extra_delay = 50us;
  Link link(p, master, "a>b");
  CountingSink sink;
  const auto d = udp_packet(2, 16);
  Time t{1'000'000'000};
  for (std::uint64_t i = 0; i < million; ++i) {
    link.send(t, d, sink);
    t += 1us;
  }
  EXPECT_EQ(sink.duplicates, link.stats().duplicated);
  EXPECT_EQ(sink.delivered, million + sink.duplicates);
  EXPECT_GE(sink.duplicates, 9'000u);
  EXPECT_LE(sink.duplicates, 11'000u);
}

TEST(SimLink, NoReorderMeansNoOvertaking) {
  LinkParams p;
  p.delay = 10ms;
  p.jitter = 10ms;  // jitter far above the 1 us spacing
  p.dup_ppm = 50'000;
  p.dup_extra_delay = 3ms;
  p.allow_reorder = false;
  Link link(p, master, "a>b");
  CountingSink sink;
  const auto d = udp_packet(3, 16);
  Time t{1'000'000'000};
  for (std::uint64_t i = 0; i < million; ++i) {
    link.send(t, d, sink);
    t += 1us;
  }
  EXPECT_EQ(sink.overtaken, 0u);
  EXPECT_GT(sink.duplicates, 0u);

  // The same link with reordering allowed does reorder (the check above is
  // not vacuous).
  p.allow_reorder = true;
  Link reorder(p, master, "a>b");
  CountingSink sink2;
  t = Time{1'000'000'000};
  for (std::uint64_t i = 0; i < 10'000; ++i) {
    reorder.send(t, d, sink2);
    t += 1us;
  }
  EXPECT_GT(sink2.overtaken, 0u);
}

TEST(SimLink, GilbertElliottMeanBurstWithinFivePercent) {
  LinkParams p;
  p.burst.p_ppm = 10'000;   // good -> bad
  p.burst.r_ppm = 250'000;  // bad -> good: mean burst 4 datagrams
  p.burst.loss_bad_ppm = 1'000'000;
  Link link(p, master, "a>b");
  const auto d = udp_packet(4, 16);
  Time t{1'000'000'000};
  std::uint64_t bursts = 0, burst_packets = 0, run = 0;
  for (std::uint64_t i = 0; i < million; ++i) {
    CountingSink sink;
    link.send(t, d, sink);
    t += 1us;
    if (sink.delivered == 0) {
      ++run;
    } else if (run > 0) {
      ++bursts;
      burst_packets += run;
      run = 0;
    }
  }
  ASSERT_GT(bursts, 1000u);
  EXPECT_EQ(link.stats().burst_lost, link.stats().lost);
  // mean = burst_packets / bursts, configured 1e6 / r_ppm = 4; within 5 %:
  // 3.8 <= mean <= 4.2.
  EXPECT_GE(burst_packets * 10, bursts * 38);
  EXPECT_LE(burst_packets * 10, bursts * 42);
}

// --- Test 2: rate and drop-tail queue.

TEST(SimLink, RateSpacesFullPacketsExactly) {
  LinkParams p;
  p.rate_bps = 10'000'000;  // 10 Mbit/s: 1500 bytes take 1.2 ms
  p.queue_bytes = 0;        // unlimited
  Link link(p, master, "a>b");
  RecordingSink sink(false);
  const auto d = tcp_packet(1, 1460);
  ASSERT_EQ(d.size(), 1500u);
  const Time t0{5'000'000'000};
  for (int i = 0; i < 100; ++i) {
    link.send(t0, d, sink);
  }
  ASSERT_EQ(sink.deliveries.size(), 100u);
  EXPECT_EQ(sink.deliveries[0].t, t0 + 1200us);
  for (std::size_t i = 1; i < sink.deliveries.size(); ++i) {
    EXPECT_EQ(sink.deliveries[i].t - sink.deliveries[i - 1].t, 1200us) << i;
  }
}

TEST(SimLink, RateKeepsSubNanosecondRemainder) {
  // 3 bytes at 7 bit/s: 24/7 s each; over 7 back-to-back datagrams exactly 24 s.
  LinkParams p;
  p.rate_bps = 7;
  Link link(p, master, "a>b");
  RecordingSink sink(false);
  const std::vector<std::byte> d(3);
  const Time t0{1'000'000'000};
  for (int i = 0; i < 7; ++i) {
    link.send(t0, d, sink);
  }
  ASSERT_EQ(sink.deliveries.size(), 7u);
  EXPECT_EQ(sink.deliveries.back().t, t0 + 24s);
}

TEST(SimLink, DropTailAtQueueBytes) {
  LinkParams p;
  p.rate_bps = 10'000'000;
  p.queue_bytes = 10 * 1500;
  Link link(p, master, "a>b");
  RecordingSink sink(false);
  const auto d = tcp_packet(1, 1460);
  const Time t0{5'000'000'000};
  for (int i = 0; i < 20; ++i) {
    link.send(t0, d, sink);
  }
  EXPECT_EQ(sink.deliveries.size(), 10u);
  EXPECT_EQ(link.stats().queue_drops, 10u);
  EXPECT_EQ(link.queued_bytes(t0), 15'000u);
  // When the first datagram has left, exactly one more fits.
  const Time t1 = t0 + 1200us;
  EXPECT_EQ(link.queued_bytes(t1), 13'500u);
  link.send(t1, d, sink);
  link.send(t1, d, sink);
  EXPECT_EQ(sink.deliveries.size(), 11u);
  EXPECT_EQ(link.stats().queue_drops, 11u);
  // It leaves after the ten queued before it.
  EXPECT_EQ(sink.deliveries.back().t, t0 + 11 * 1200us);
}

// --- Test 3: corruption.

bool m0_rejects(std::span<const std::byte> d) {
  const auto ip = wire::parse_ipv4(d);
  if (!ip) {
    return true;
  }
  if (ip->h.proto == ip_proto_tcp) {
    return !wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true).has_value();
  }
  if (ip->h.proto == ip_proto_udp) {
    return !wire::parse_udp(ip->payload, ip->h.src, ip->h.dst, true).has_value();
  }
  return false;  // the protocol field itself is covered by the header checksum
}

bool m0_checksums_pass(std::span<const std::byte> d) {
  const auto ip = wire::parse_ipv4(d);
  if (!ip) {
    return ip.error() != wire::ParseError::bad_checksum;
  }
  if (ip->h.proto == ip_proto_tcp) {
    const auto t = wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
    return t || t.error() != wire::ParseError::bad_checksum;
  }
  if (ip->h.proto == ip_proto_udp) {
    const auto u = wire::parse_udp(ip->payload, ip->h.src, ip->h.dst, true);
    return u || u.error() != wire::ParseError::bad_checksum;
  }
  return true;
}

int differing_bits(std::span<const std::byte> a, std::span<const std::byte> b) {
  int n = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    n += std::popcount(std::to_integer<unsigned>(a[i] ^ b[i]));
  }
  return n;
}

TEST(SimLink, BitFlipsDifferInOneBitAndM0RejectsAll) {
  LinkParams p;
  p.bitflip_ppm = 1'000'000;  // every datagram
  Link link(p, master, "a>b");
  Rng sizes = Rng::derive(master, "test/sizes");
  std::uint64_t tcp = 0, udp = 0;
  Time t{1'000'000'000};
  for (std::uint32_t i = 0; i < 200'000; ++i) {
    const bool is_tcp = (i & 1) == 0;
    const auto d = is_tcp ? tcp_packet(i * 1000, sizes.below(1461))
                          : udp_packet(i, sizes.below(1473));
    RecordingSink sink;
    link.send(t, d, sink);
    t += 1us;
    ASSERT_EQ(sink.deliveries.size(), 1u);
    const auto& got = sink.deliveries[0];
    ASSERT_EQ(got.info.corruption, Corruption::bitflip);
    ASSERT_EQ(got.bytes.size(), d.size());
    ASSERT_EQ(differing_bits(got.bytes, d), 1) << i;
    ASSERT_TRUE(m0_rejects(got.bytes)) << "flip not detected in datagram " << i;
    ASSERT_FALSE(checksums_valid(got.bytes)) << i;
    (is_tcp ? tcp : udp) += 1;
  }
  EXPECT_EQ(tcp, 100'000u);
  EXPECT_EQ(udp, 100'000u);
}

TEST(SimLink, FlipNeverZeroesTheUdpChecksum) {
  // A datagram whose UDP checksum field has a single bit set: flipping that
  // bit would make it 0 (no checksum, RFC 768), so it is never chosen. The
  // first two payload bytes are chosen to give such a checksum.
  auto d = udp_packet(1, 2);
  bool found = false;
  for (std::uint32_t v = 0; v < 65536 && !found; ++v) {
    wire::store_be16(d, 28, static_cast<std::uint16_t>(v));
    fix_checksums(d);
    found = std::popcount(wire::load_be16(d, 26)) == 1;
  }
  ASSERT_TRUE(found);
  ASSERT_TRUE(checksums_valid(d));
  Rng rng = Rng::derive(master, "test/flip");
  std::uint64_t in_field = 0;
  for (int i = 0; i < 20'000; ++i) {
    auto c = d;
    const std::size_t bit = flip_one_bit(c, rng);
    ASSERT_NE(wire::load_be16(c, 26), 0u);
    ASSERT_FALSE(checksums_valid(c));
    in_field += bit / 8 == 26 || bit / 8 == 27 ? 1u : 0u;
  }
  EXPECT_GT(in_field, 0u);  // the other 15 bits of the field are still flipped
}

TEST(SimLink, GarbagePassesEveryChecksumCheck) {
  LinkParams p;
  p.garbage_ppm = 1'000'000;
  Link link(p, master, "a>b");
  Rng sizes = Rng::derive(master, "test/sizes");
  Time t{1'000'000'000};
  std::uint64_t replays = 0, changed = 0;
  for (std::uint32_t i = 0; i < 100'000; ++i) {
    const auto d = (i % 3) != 0 ? tcp_packet(i * 1000, sizes.below(1449), true, i % 3 == 2)
                                : udp_packet(i, sizes.below(1473));
    RecordingSink sink;
    link.send(t, d, sink);
    t += 1us;
    ASSERT_GE(sink.deliveries.size(), 1u);
    for (const auto& got : sink.deliveries) {
      ASSERT_EQ(got.info.corruption, Corruption::garbage);
      ASSERT_TRUE(checksums_valid(got.bytes)) << i;
      ASSERT_TRUE(m0_checksums_pass(got.bytes)) << i;
      replays += got.info.replay ? 1u : 0u;
      changed += got.bytes != d ? 1u : 0u;
    }
  }
  EXPECT_GT(replays, 1000u);
  EXPECT_GT(changed, 90'000u);
}

TEST(SimLink, GarbageCoversEveryKind) {
  Rng rng = Rng::derive(master, "test/garbage");
  std::array<std::uint64_t, 10> seen{};
  for (std::uint32_t i = 0; i < 30'000; ++i) {
    auto d = i % 3 == 0 ? udp_packet(i, 100) : tcp_packet(i, 100, true, i % 3 == 2);
    GarbageKind kind = GarbageKind::payload;
    const std::size_t len = mutate_garbage(d, d.size(), rng, kind);
    ASSERT_LE(len, d.size());
    ASSERT_TRUE(checksums_valid(std::span<const std::byte>(d).first(len)));
    ++seen[static_cast<std::size_t>(kind)];
  }
  for (std::size_t k = 0; k < seen.size(); ++k) {
    if (static_cast<GarbageKind>(k) == GarbageKind::replay) {
      EXPECT_EQ(seen[k], 0u);  // chosen by Link, not by mutate_garbage
    } else {
      EXPECT_GT(seen[k], 0u) << "kind " << k;
    }
  }
}

TEST(SimLink, GarbageDrawOrderIsFixed) {
  // §13.1: one draw per statement, so the g++ and clang builds mutate the
  // same bytes (two draws in the arguments of one call are evaluated in an
  // unspecified order). A copy of the stream replays the documented order of
  // the UDP `ports` case: the case, which port, then its value.
  const auto base = udp_packet(5, 64);
  std::uint32_t ports = 0;
  for (std::uint32_t i = 0; i < 300; ++i) {
    Rng rng = Rng::derive(master, "test/order/" + std::to_string(i));
    Rng ref = rng;
    auto d = base;
    GarbageKind kind = GarbageKind::payload;
    const std::size_t len = mutate_garbage(d, d.size(), rng, kind);
    if (ref.below(3) != 0) {
      continue;  // truncate or payload
    }
    ASSERT_EQ(kind, GarbageKind::ports);
    const std::size_t at = 20 + 2 * std::size_t{ref.below(2)};
    const auto v = static_cast<std::uint16_t>(ref.below(65536));
    const std::size_t other = at == 20 ? 22 : 20;
    EXPECT_EQ(wire::load_be16(d, at), v) << i;
    EXPECT_EQ(wire::load_be16(d, other), wire::load_be16(base, other)) << i;
    EXPECT_EQ(len, base.size());
    EXPECT_EQ(rng.state(), ref.state()) << i;  // nothing else drawn
    ++ports;
  }
  EXPECT_GT(ports, 50u);
}

TEST(SimLink, CorruptionOutputIsTheSameInEveryBuild) {
  // A digest of 6000 bit flips and garbage mutations of TCP (with and without
  // options), UDP and ICMP datagrams of many sizes. Both compilers' builds
  // run this test against the same value, so an evaluation-order difference
  // anywhere in the corruption code fails one of them.
  Rng rng = Rng::derive(master, "test/golden");
  RunDigest h;
  for (std::uint32_t i = 0; i < 6000; ++i) {
    std::vector<std::byte> d;
    switch (i % 4) {
      case 0: d = udp_packet(i, i % 300); break;
      case 1: d = tcp_packet(i * 7919, i % 300); break;
      case 2: d = tcp_packet(i * 7919, i % 300, true, true); break;
      default: {
        const std::vector<std::byte> body(i % 100, std::byte{0x33});
        d = build_icmp_echo(node_addr(0), node_addr(1), wire::icmp_echo_request,
                            static_cast<std::uint16_t>(i), 1, body, 9);
        break;
      }
    }
    std::size_t len = d.size();
    std::uint32_t tag = 100;
    if ((i / 4) % 2 == 0) {
      tag = static_cast<std::uint32_t>(flip_one_bit(d, rng));
    } else {
      GarbageKind kind = GarbageKind::payload;
      len = mutate_garbage(d, d.size(), rng, kind);
      tag = static_cast<std::uint32_t>(kind);
    }
    h.packet(tag, Time{i}, std::span<const std::byte>(d).first(len));
  }
  const auto hex = RunDigest::hex(h.value());
  EXPECT_EQ(std::string(hex.data(), hex.size()), "895771f004314abf");
}

// --- Test 4: MTU.

TEST(SimLink, DfAboveMtuAnsweredWithFragNeeded) {
  LinkParams p;
  p.mtu = 1000;
  p.send_frag_needed = true;
  p.router_addr = Ipv4Addr::from_octets(198, 18, 0, 254);
  Link link(p, master, "a>r");
  RecordingSink sink;
  const auto big = tcp_packet(77, 1400);  // 1440 bytes, DF
  const Time t0{2'000'000'000};
  link.send(t0, big, sink);
  EXPECT_TRUE(sink.deliveries.empty());
  ASSERT_EQ(sink.replies.size(), 1u);
  EXPECT_EQ(sink.replies[0].t, t0);
  const auto& icmp = sink.replies[0].bytes;
  const auto ip = wire::parse_ipv4(icmp);
  ASSERT_TRUE(ip.has_value());
  EXPECT_EQ(ip->h.proto, ip_proto_icmp);
  EXPECT_EQ(ip->h.src, p.router_addr);
  EXPECT_EQ(ip->h.dst, node_addr(0));
  const auto m = wire::parse_icmp(ip->payload, true);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->h.type, wire::icmp_dest_unreach);
  EXPECT_EQ(m->h.code, wire::icmp_frag_needed);
  EXPECT_EQ(m->h.next_hop_mtu(), 1000u);
  // The quote: the offending datagram's first bytes, as many as fit in 576.
  ASSERT_EQ(m->body.size(), wire::icmp_max_quote);
  EXPECT_TRUE(std::equal(m->body.begin(), m->body.end(), big.begin()));
  EXPECT_LE(icmp.size(), 576u);
  const auto q = wire::parse_icmp_quote(m->body);
  ASSERT_TRUE(q.has_value());
  EXPECT_EQ(wire::load_be32(q->l4, 4), 77u);  // the quoted TCP sequence number

  // A short datagram is quoted whole.
  RecordingSink sink2;
  const auto mid = tcp_packet(5, 990);  // 1030 bytes
  link.send(t0, mid, sink2);
  ASSERT_EQ(sink2.replies.size(), 1u);
  const auto ip2 = wire::parse_ipv4(sink2.replies[0].bytes);
  ASSERT_TRUE(ip2.has_value());
  const auto m2 = wire::parse_icmp(ip2->payload, true);
  ASSERT_TRUE(m2.has_value());
  EXPECT_EQ(m2->body.size(), std::min<std::size_t>(mid.size(), wire::icmp_max_quote));

  // At the MTU, the datagram passes.
  RecordingSink sink3;
  link.send(t0, tcp_packet(9, 960), sink3);
  EXPECT_EQ(sink3.deliveries.size(), 1u);
  EXPECT_TRUE(sink3.replies.empty());
  EXPECT_EQ(link.stats().mtu_drops, 2u);
  EXPECT_EQ(link.stats().frag_needed, 2u);
}

TEST(SimLink, NonDfAboveMtuDroppedSilently) {
  LinkParams p;
  p.mtu = 1000;
  p.send_frag_needed = true;
  Link link(p, master, "a>r");
  RecordingSink sink;
  link.send(Time{1'000'000'000}, tcp_packet(1, 1400, false), sink);
  EXPECT_TRUE(sink.deliveries.empty());
  EXPECT_TRUE(sink.replies.empty());
  EXPECT_EQ(link.stats().mtu_drops, 1u);
}

TEST(SimLink, SpoofedFragNeededQuoteRandomSequence) {
  LinkParams p;
  p.icmp_spoof_ppm = 1'000'000;
  Link link(p, master, "a>b");
  RecordingSink sink;
  const auto d = tcp_packet(1234, 100);
  link.send(Time{1'000'000'000}, d, sink);
  EXPECT_EQ(sink.deliveries.size(), 1u);  // the datagram continues
  ASSERT_EQ(sink.replies.size(), 1u);
  const auto ip = wire::parse_ipv4(sink.replies[0].bytes);
  ASSERT_TRUE(ip.has_value());
  const auto m = wire::parse_icmp(ip->payload, true);
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->h.code, wire::icmp_frag_needed);
  const auto q = wire::parse_icmp_quote(m->body);
  ASSERT_TRUE(q.has_value());
  EXPECT_EQ(q->ip.src, node_addr(0));
  EXPECT_GE(m->h.next_hop_mtu(), 68u);
}

}  // namespace
}  // namespace utcp::sim
