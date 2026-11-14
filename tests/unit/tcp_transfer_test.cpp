// m1-tcp-core acceptance test 2: bulk transfer, sequence wrap, D-SACK
// generation and the FIN at the sequence-to-offset boundary (DESIGN §3.2,
// §4.4, §4.10).
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "common/sha256.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "support/packet_builder.hpp"
#include "support/tcp_harness.hpp"
#include "tcp_test_util.hpp"
#include "utcp/checksum.hpp"
#include "utcp/config.hpp"
#include "utcp/stack.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::Endpoint;
using utcp::Handle;
using utcp::Seq32;
using utcp::StackConfig;
using utcp::TcpState;
using utcp::Time;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;

constexpr std::uint16_t port = 80;

struct Parsed {
  w::Ipv4Header ip;
  w::TcpView v;
};

std::optional<Parsed> parse(std::span<const std::byte> d) {
  const auto ip = w::parse_ipv4(d);
  if (!ip || ip->h.proto != utcp::ip_proto_tcp) {
    return std::nullopt;
  }
  const auto v = w::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
  if (!v) {
    return std::nullopt;
  }
  return Parsed{ip->h, *v};
}

bool has(const w::TcpView& v, std::uint16_t f) { return (v.h.flags & f) == f; }

StackConfig config_mode(Side s, int mode) {
  StackConfig c = t::TcpHarness::default_config(s);
  c.tcp.sack = (mode & 1) != 0;
  c.tcp.timestamps = (mode & 2) != 0;
  c.tcp.window_scaling = (mode & 4) != 0;
  return c;
}

struct Pair {
  Handle listener, client, server;
};

std::optional<Pair> open(t::TcpHarness& h) {
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 16, {});
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  if (!l || !c) {
    return std::nullopt;
  }
  h.run_for(100ms);
  const auto s = h.b().tcp_accept(*l);
  if (!s) {
    return std::nullopt;
  }
  return Pair{*l, *c, *s};
}

std::string digest(std::span<const std::byte> d) { return utcp::app::sha256_hex(d); }

// One direction of a transfer.
struct Flow {
  utcp::Stack* tx = nullptr;
  Handle txh;
  utcp::Stack* rx = nullptr;
  Handle rxh;
  t::Bytes data;
  std::size_t sent = 0;
  t::Bytes got;
  bool eof = false;
  bool shut = false;
};

Flow flow(utcp::Stack& tx, Handle txh, utcp::Stack& rx, Handle rxh, t::Bytes data) {
  Flow f;
  f.tx = &tx;
  f.txh = txh;
  f.rx = &rx;
  f.rxh = rxh;
  f.data = std::move(data);
  return f;
}

// Moves both flows to completion (each side shuts down writing after its
// last byte, reads to EOF), then closes both. Returns false on a stall.
bool run_transfer(t::TcpHarness& h, Flow& f1, Flow& f2, Duration limit) {
  std::array<std::byte, 65536> buf{};
  const Time end = h.now() + limit;
  while (h.now() < end) {
    for (Flow* f : {&f1, &f2}) {
      while (f->sent < f->data.size()) {
        const auto r = f->tx->tcp_send(f->txh, std::span(f->data).subspan(f->sent));
        if (!r) {
          break;
        }
        f->sent += *r;
      }
      if (f->sent == f->data.size() && !f->shut) {
        f->shut = f->tx->tcp_shutdown(f->txh, utcp::Shutdown::write).has_value();
      }
      for (;;) {
        const auto r = f->rx->tcp_recv(f->rxh, buf);
        if (!r) {
          break;
        }
        if (*r == 0) {
          f->eof = true;
          break;
        }
        f->got.insert(f->got.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*r));
      }
    }
    if (f1.eof && f2.eof) {
      return true;
    }
    h.run_for(1ms);
    h.clear_log();
  }
  return false;
}

// 10 MB each way in every SACK/TS/WS combination; the SHA-256 digests match.
class TcpTransferCombos : public ::testing::TestWithParam<int> {};

TEST_P(TcpTransferCombos, TenMegabytesEachWay) {
  const int ma = GetParam();
  const t::Bytes ab = t::pattern(10'000'000, 11), ba = t::pattern(10'000'000, 29);
  const std::string dab = digest(ab), dba = digest(ba);
  for (int mb = 0; mb < 8; ++mb) {
    SCOPED_TRACE("a mode " + std::to_string(ma) + ", b mode " + std::to_string(mb));
    t::TcpHarness h(config_mode(Side::a, ma), config_mode(Side::b, mb));
    h.set_delay(Side::a, 500us);
    h.set_delay(Side::b, 500us);
    const auto p = open(h);
    ASSERT_TRUE(p);
    Flow f1 = flow(h.a(), p->client, h.b(), p->server, ab);
    Flow f2 = flow(h.b(), p->server, h.a(), p->client, ba);
    ASSERT_TRUE(run_transfer(h, f1, f2, 120s));
    EXPECT_EQ(digest(f1.got), dab);
    EXPECT_EQ(digest(f2.got), dba);
    ASSERT_TRUE(h.a().tcp_close(p->client));
    ASSERT_TRUE(h.b().tcp_close(p->server));
    h.run_for(200s);
    EXPECT_EQ(h.a().debug_usage().tcp_slots, 0u);
    EXPECT_EQ(h.b().debug_usage().tcp_slots, 1u);  // the listener
    EXPECT_EQ(h.a().debug_usage().time_wait_entries + h.b().debug_usage().time_wait_entries, 0u);
    h.a().debug_check();
    h.b().debug_check();
  }
}

INSTANTIATE_TEST_SUITE_P(AllModes, TcpTransferCombos, ::testing::Range(0, 8));

// test_isn = 0xFFFFF000 on both sides: both sequence spaces wrap within the
// first 4 KiB.
TEST(TcpTransfer, SequenceWrap) {
  StackConfig ca = t::TcpHarness::default_config(Side::a);
  StackConfig cb = t::TcpHarness::default_config(Side::b);
  ca.tcp.test_isn = cb.tcp.test_isn = 0xFFFF'F000u;
  t::TcpHarness h(ca, cb);
  h.set_delay(Side::a, 500us);
  h.set_delay(Side::b, 500us);
  // Every third data segment of a is lost once: retransmission and SACK
  // across the wrap.
  int n = 0;
  h.set_hook([&](Side from, t::Bytes& d) {
    const auto p = parse(d);
    if (from == Side::a && p && !p->v.payload.empty() && ++n % 3 == 0 && n < 100) {
      return t::Verdict::drop;
    }
    return t::Verdict::deliver;
  });
  const auto p = open(h);
  ASSERT_TRUE(p);
  Flow f1 = flow(h.a(), p->client, h.b(), p->server, t::pattern(1'000'000, 5));
  Flow f2 = flow(h.b(), p->server, h.a(), p->client, t::pattern(1'000'000, 9));
  ASSERT_TRUE(run_transfer(h, f1, f2, 120s));
  EXPECT_EQ(digest(f1.got), digest(f1.data));
  EXPECT_EQ(digest(f2.got), digest(f2.data));
  EXPECT_GT(h.a().tcp_info(p->client)->total_retrans, 0u);
  h.a().debug_check();
  h.b().debug_check();
}

// The latest segment `from` sent.
std::optional<Parsed> last_from(const t::TcpHarness& h, Side from, t::Bytes& keep) {
  for (auto it = h.log().rbegin(); it != h.log().rend(); ++it) {
    if (it->from == from) {
      keep = it->bytes;
      return parse(keep);
    }
  }
  return std::nullopt;
}

// The datagrams `from` sent after log entry `start`.
std::vector<t::Bytes> sent_since(const t::TcpHarness& h, Side from, std::size_t start) {
  std::vector<t::Bytes> out;
  for (std::size_t i = start; i < h.log().size(); ++i) {
    if (h.log()[i].from == from) {
      out.push_back(h.log()[i].bytes);
    }
  }
  return out;
}

// Exactly one segment from `from` since `start`: a pure ACK of `ack` without
// SACK blocks.
void expect_one_plain_ack(const t::TcpHarness& h, Side from, std::size_t start, Seq32 ack) {
  const auto sent = sent_since(h, from, start);
  ASSERT_EQ(sent.size(), 1u);
  const auto q = parse(sent[0]);
  ASSERT_TRUE(q);
  EXPECT_EQ(q->v.h.flags & (w::tcp_syn | w::tcp_fin | w::tcp_rst), 0);
  EXPECT_TRUE(has(q->v, w::tcp_ack));
  EXPECT_TRUE(q->v.payload.empty());
  EXPECT_EQ(q->v.h.ack, ack);
  EXPECT_EQ(q->v.opt.sack_count, 0);
}

// RFC 2883 §4 covers payload only (§3.2): a retransmitted FIN, a
// retransmitted SYN-ACK reaching an established client and a zero-length
// segment at RCV.NXT - 1 are ACKed without a D-SACK block. Duplicate data
// gets one.
TEST(TcpTransfer, DsackOnlyForPayload) {
  t::TcpHarness h;
  const auto p = open(h);
  ASSERT_TRUE(p);
  // The SYN-ACK b sent, and an ACK a sent, kept for re-injection.
  t::Bytes synack, a_ack;
  for (const t::Sent& s : h.log()) {
    const auto q = parse(s.bytes);
    if (s.from == Side::b && q && has(q->v, w::tcp_syn | w::tcp_ack)) {
      synack = s.bytes;
    }
    if (s.from == Side::a && q && !has(q->v, w::tcp_syn)) {
      a_ack = s.bytes;
    }
  }
  ASSERT_FALSE(synack.empty());
  ASSERT_FALSE(a_ack.empty());
  // Duplicate data: a D-SACK.
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(1000)));
  h.settle();
  t::Bytes data;
  for (const t::Sent& s : h.log()) {
    const auto q = parse(s.bytes);
    if (s.from == Side::a && q && !q->v.payload.empty()) {
      data = s.bytes;
    }
  }
  ASSERT_FALSE(data.empty());
  h.run_for(1s);
  t::Bytes keep;
  h.b().receive(h.now(), data);
  h.settle();
  auto r = last_from(h, Side::b, keep);
  ASSERT_TRUE(r);
  ASSERT_EQ(r->v.opt.sack_count, 1);
  EXPECT_EQ(r->v.opt.sack[0].second - r->v.opt.sack[0].first, 1000u);
  EXPECT_EQ(r->v.opt.sack[0].second, r->v.h.ack);
  // The retransmitted SYN-ACK at the established client: one plain ACK.
  h.run_for(1s);
  const Seq32 a_rcv_nxt = parse(synack)->v.h.seq + 1;
  std::size_t start = h.log().size();
  h.a().receive(h.now(), synack);
  h.settle();
  expect_one_plain_ack(h, Side::a, start, a_rcv_nxt);
  // A zero-length segment at RCV.NXT - 1 (a keepalive probe), with a's
  // current timestamp as a real keepalive carries (an older one would fail
  // PAWS: no reply under linux_compat, §4.4 step 1).
  h.run_for(1s);
  {
    const auto q = parse(a_ack);
    ASSERT_TRUE(q);
    t::Bytes keep_a;
    const auto latest = last_from(h, Side::a, keep_a);
    ASSERT_TRUE(latest && latest->v.opt.ts);
    const std::uint32_t seq = h.a().tcp_info(p->client)->bytes_acked + q->v.h.seq.raw() - 1;
    t::TcpSpec probe(Endpoint{h.addr(Side::a), q->v.h.sport}, Endpoint{h.addr(Side::b), q->v.h.dport});
    probe.seq = Seq32{seq};
    probe.ack = latest->v.h.ack;
    probe.flags = w::tcp_ack;
    probe.window = latest->v.h.window;
    probe.opt.ts = w::Timestamps{latest->v.opt.ts->val + 1000, latest->v.opt.ts->ecr};
    start = h.log().size();
    h.b().receive(h.now(), t::tcp_datagram(probe));
    h.settle();
    expect_one_plain_ack(h, Side::b, start, Seq32{seq + 1});
  }
  // The retransmitted FIN.
  ASSERT_TRUE(h.a().tcp_shutdown(p->client, utcp::Shutdown::write));
  h.settle();
  t::Bytes fin;
  for (const t::Sent& s : h.log()) {
    const auto q = parse(s.bytes);
    if (s.from == Side::a && q && has(q->v, w::tcp_fin)) {
      fin = s.bytes;
    }
  }
  ASSERT_FALSE(fin.empty());
  EXPECT_EQ(h.b().tcp_info(p->server)->state, TcpState::close_wait);
  h.run_for(1s);
  start = h.log().size();
  h.b().receive(h.now(), fin);
  h.settle();
  expect_one_plain_ack(h, Side::b, start, parse(fin)->v.h.seq + 1);
  h.a().debug_check();
  h.b().debug_check();
}

// §3.2: an ACK and a SACK block covering our FIN are clipped to the payload
// end and complete the FIN (FIN-WAIT-2).
TEST(TcpTransfer, AckAndSackCoveringFinAreClipped) {
  StackConfig ca = t::TcpHarness::default_config(Side::a);
  StackConfig cb = t::TcpHarness::default_config(Side::b);
  ca.tcp.timestamps = cb.tcp.timestamps = false;
  t::TcpHarness h(ca, cb);
  const auto p = open(h);
  ASSERT_TRUE(p);
  // From here b's segments to a are dropped; a's peer is played by hand.
  h.set_hook([](Side from, t::Bytes&) {
    return from == Side::b ? t::Verdict::drop : t::Verdict::deliver;
  });
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(3000)));
  ASSERT_TRUE(h.a().tcp_shutdown(p->client, utcp::Shutdown::write));
  h.settle();
  // a's SYN: its ISS; b's SYN-ACK: b's ISS.
  Seq32 a_iss, b_nxt;
  for (const t::Sent& s : h.log()) {
    const auto q = parse(s.bytes);
    if (q && has(q->v, w::tcp_syn)) {
      if (s.from == Side::a) {
        a_iss = q->v.h.seq;
      } else {
        b_nxt = q->v.h.seq + 1;
      }
    }
  }
  const Seq32 fin_seq = a_iss + 1 + 3000;  // our FIN's sequence number
  EXPECT_EQ(h.a().tcp_info(p->client)->state, TcpState::fin_wait_1);
  const Endpoint ea{h.addr(Side::a), 0}, eb{h.addr(Side::b), port};
  t::TcpSpec sack(Endpoint{eb.addr, port}, Endpoint{ea.addr, 0});
  // a's local port: from the client's tuple in the log.
  for (const t::Sent& s : h.log()) {
    const auto q = parse(s.bytes);
    if (s.from == Side::a && q) {
      sack.dst.port = q->v.h.sport;
    }
  }
  // A SACK block over the last 1000 bytes and the FIN; SEG.ACK below it.
  sack.seq = b_nxt;
  sack.ack = a_iss + 1 + 1000;
  sack.flags = w::tcp_ack;
  sack.opt.sack[0] = {a_iss + 1 + 2000, fin_seq + 1};
  sack.opt.sack_count = 1;
  h.a().receive(h.now(), t::tcp_datagram(sack));
  h.a().debug_check();
  EXPECT_EQ(h.a().tcp_info(p->client)->state, TcpState::fin_wait_1);
  // The block was taken, clipped to the payload end: the last data segment
  // (offsets 2920..3000) is SACKed, nothing was discarded.
  EXPECT_EQ(h.a().tcp_info(p->client)->sacked, 1u);
  EXPECT_EQ(h.a().stats().TcpExtTCPSACKDiscard, 0u);
  // The cumulative ACK of everything, FIN included.
  t::TcpSpec ack = sack;
  ack.ack = fin_seq + 1;
  ack.opt.sack_count = 0;
  h.a().receive(h.now(), t::tcp_datagram(ack));
  h.a().debug_check();
  const auto ia = h.a().tcp_info(p->client);
  EXPECT_EQ(ia->state, TcpState::fin_wait_2);
  EXPECT_EQ(ia->bytes_acked, 3000u);
  EXPECT_EQ(ia->unacked, 0u);
}

// Linux tcp_ack (old_ack): an ACK below SND.UNA, reordered behind a newer
// one, moves nothing but still has its D-SACK counted and its SACK blocks
// tagged.
TEST(TcpTransfer, OldAckKeepsSackAndDsack) {
  namespace tc = utcp::test::tcpt;
  tc::Scripted c;
  ASSERT_TRUE(c.accept());
  const std::uint32_t mss = c.stack().tcp_info(c.h)->snd_mss;
  ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(6 * std::size_t{mss})));
  ASSERT_EQ(c.out().size(), 6u);
  const Seq32 una = c.their;
  t::TcpSpec newer = c.spec(w::tcp_ack);
  newer.ack = una + 2 * mss;
  c.send(newer);
  t::TcpSpec old = c.spec(w::tcp_ack);
  old.ack = una + mss;
  old.opt.sack[0] = {una, una + 100};  // D-SACK: below its SEG.ACK
  old.opt.sack[1] = {una + 4 * mss, una + 5 * mss};
  old.opt.sack_count = 2;
  c.send(old);
  const auto i = c.stack().tcp_info(c.h);
  EXPECT_EQ(c.stack().stats().TcpExtTCPDSACKRecv, 1u);
  EXPECT_EQ(i->dsack_dups, 1u);
  EXPECT_EQ(i->sacked, 1u);
  EXPECT_EQ(i->unacked, 4u);
  EXPECT_EQ(i->bytes_acked, 2u * mss);
  c.stack().debug_check();
}

// An ACK that advances SND.UNA takes its window even when its SEQ is below
// SND.WL1, as from a repacketized retransmission by the peer (Linux
// tcp_may_update_window); the stack then sends nothing past SND.UNA + that
// window (simulator seed 5 sent 1424 bytes past it).
TEST(TcpTransfer, AdvancingAckWithOlderSeqTakesItsWindow) {
  namespace tc = utcp::test::tcpt;
  tc::Scripted c;  // peer window scale 7
  ASSERT_TRUE(c.accept(Seq32{10'000}, 1000));  // 1000 << 7 bytes
  const Seq32 p0 = c.nxt;
  c.send_data(100);
  c.send_data(100);  // SND.WL1 = p0 + 100
  c.d().run_for(1s);
  (void)c.out();
  const std::uint32_t mss = c.stack().tcp_info(c.h)->snd_mss;
  ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(3 * std::size_t{mss})));
  ASSERT_EQ(c.out().size(), 3u);
  const Seq32 una = c.their;
  // The peer resends from p0 (below SND.WL1) with 100 new bytes, ACKs one
  // segment and offers 2 << 7 = 256 bytes.
  t::TcpSpec re = c.spec(w::tcp_ack | w::tcp_psh);
  re.seq = p0;
  re.ack = una + mss;
  re.window = 2;
  re.payload = t::pattern(300);
  c.nxt = p0 + 300;
  c.send(re);
  EXPECT_EQ(c.stack().tcp_info(c.h)->snd_wnd, 256u);
  ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(4 * std::size_t{mss})));
  c.d().run_for(10ms);
  const Seq32 right = una + mss + 256;
  for (const tc::Parsed& q : c.out()) {
    if (q.v.payload.empty()) {
      continue;  // the ACK of the peer's segment
    }
    const Seq32 end = q.v.h.seq + static_cast<std::uint32_t>(q.v.payload.size());
    EXPECT_FALSE(after(end, right)) << "data ends " << (end - right) << " past the window";
  }
  EXPECT_EQ(tc::drain(c.stack(), c.h).size(), 300u);
  c.stack().debug_check();
}


// TcpExtTCPOrigDataSent counts each segment of new data (and a FIN sent
// for the first time) once, as Linux tcp_event_new_data_sent; the interop
// run A-N3-s2l showed 1,381,424 for 690,715 segments (counted twice).
TEST(TcpTransfer, OrigDataSentCountsEachNewSegmentOnce) {
  t::TcpHarness h(t::TcpHarness::default_config(Side::a), t::TcpHarness::default_config(Side::b));
  h.set_delay(Side::a, 500us);
  h.set_delay(Side::b, 500us);
  const auto p = open(h);
  ASSERT_TRUE(p);
  h.clear_log();
  const std::uint64_t before = h.a().stats().TcpExtTCPOrigDataSent;
  const t::Bytes data = t::pattern(100'000, 3);
  std::size_t sent = 0;
  std::size_t segs = 0;
  std::array<std::byte, 65536> buf{};
  bool shut = false;
  for (int i = 0; i < 2000; ++i) {
    while (sent < data.size()) {
      const auto r = h.a().tcp_send(p->client, std::span(data).subspan(sent));
      if (!r) {
        break;
      }
      sent += *r;
    }
    if (sent == data.size() && !shut) {
      shut = h.a().tcp_shutdown(p->client, utcp::Shutdown::write).has_value();
    }
    while (h.b().tcp_recv(p->server, buf).value_or(0) > 0) {
    }
    h.run_for(1ms);
    for (const auto& e : h.log()) {
      if (e.from != Side::a) {
        continue;
      }
      const auto q = parse(e.bytes);
      if (q && (!q->v.payload.empty() || has(q->v, w::tcp_fin))) {
        ++segs;
      }
    }
    h.clear_log();
  }
  ASSERT_TRUE(shut);
  EXPECT_EQ(h.a().stats().TcpRetransSegs, 0u);
  EXPECT_GE(segs, 100'000u / 1460u);
  EXPECT_EQ(h.a().stats().TcpExtTCPOrigDataSent - before, segs);
  h.a().debug_check();
}

}  // namespace
