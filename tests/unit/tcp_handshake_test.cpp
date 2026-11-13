// m1-tcp-core acceptance test 1: the handshake (DESIGN §4.4, §4.5, §4.8).
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/tcp/rcv_window.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "support/packet_builder.hpp"
#include "support/tcp_harness.hpp"
#include "utcp/checksum.hpp"
#include "utcp/config.hpp"
#include "utcp/stack.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::Endpoint;
using utcp::Handle;
using utcp::Ipv4Addr;
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

// The TCP segment in a datagram (views into `d`).
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

bool is_syn(const w::TcpView& v) { return has(v, w::tcp_syn) && !has(v, w::tcp_ack); }
bool is_synack(const w::TcpView& v) { return has(v, w::tcp_syn | w::tcp_ack); }

// Log entries from `from` that satisfy `pred`, oldest first.
template <class Pred>
std::vector<const t::Sent*> find(const t::TcpHarness& h, Side from, Pred pred) {
  std::vector<const t::Sent*> out;
  for (const t::Sent& s : h.log()) {
    if (s.from != from) {
      continue;
    }
    const auto p = parse(s.bytes);
    if (p && pred(p->v)) {
      out.push_back(&s);
    }
  }
  return out;
}

StackConfig config(Side s, utcp::ProfileId profile = utcp::ProfileId::linux_compat) {
  StackConfig c = t::TcpHarness::default_config(s);
  c.tcp = utcp::tcp_config(profile);
  return c;
}

// SACK, TS and WS on or off from the bits of `mode`.
StackConfig config_mode(Side s, int mode) {
  StackConfig c = config(s);
  c.tcp.sack = (mode & 1) != 0;
  c.tcp.timestamps = (mode & 2) != 0;
  c.tcp.window_scaling = (mode & 4) != 0;
  return c;
}

std::uint8_t offered_shift(const StackConfig& c) {
  return std::min(utcp::effective_rcv_wscale(c.tcp), utcp::max_rcv_wscale(c.tcp.rcv_buf_init));
}

struct Pair {
  Handle listener, client, server;
};

// b listens on `port`, a connects; runs `d`, then accepts.
std::optional<Pair> open(t::TcpHarness& h, Duration d = 100ms) {
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 16, {});
  if (!l) {
    return std::nullopt;
  }
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  if (!c) {
    return std::nullopt;
  }
  h.run_for(d);
  const auto s = h.b().tcp_accept(*l);
  if (!s) {
    return std::nullopt;
  }
  return Pair{*l, *c, *s};
}

TcpState state(utcp::Stack& s, Handle h) {
  const auto i = s.tcp_info(h);
  return i ? i->state : TcpState::closed;
}

// Reads everything readable.
t::Bytes drain(utcp::Stack& s, Handle h) {
  t::Bytes out;
  std::array<std::byte, 4096> buf{};
  for (;;) {
    const auto r = s.tcp_recv(h, buf);
    if (!r || *r == 0) {
      return out;
    }
    out.insert(out.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*r));
  }
}

// All 64 combinations of SACK, TS and WS on the two sides (§4.5).
TEST(TcpHandshake, OptionCombinationsNegotiateAsDesigned) {
  for (int ma = 0; ma < 8; ++ma) {
    for (int mb = 0; mb < 8; ++mb) {
      SCOPED_TRACE("a mode " + std::to_string(ma) + ", b mode " + std::to_string(mb));
      const StackConfig ca = config_mode(Side::a, ma), cb = config_mode(Side::b, mb);
      t::TcpHarness h(ca, cb);
      bool held = false;
      h.set_hook([&](Side from, t::Bytes& d) {
        const auto p = parse(d);
        if (from == Side::a && p && !p->v.payload.empty() && !held) {
          held = true;
          return t::Verdict::hold;  // the first data segment: the next two arrive out of order
        }
        return t::Verdict::deliver;
      });
      const auto p = open(h);
      ASSERT_TRUE(p);
      const bool sack = ca.tcp.sack && cb.tcp.sack;
      const bool ts = ca.tcp.timestamps && cb.tcp.timestamps;
      const bool ws = ca.tcp.window_scaling && cb.tcp.window_scaling;
      const auto ia = h.a().tcp_info(p->client), ib = h.b().tcp_info(p->server);
      ASSERT_TRUE(ia && ib);
      EXPECT_EQ(ia->state, TcpState::established);
      EXPECT_EQ(ib->state, TcpState::established);
      EXPECT_EQ(ia->rcv_wscale, ws ? offered_shift(ca) : 0);
      EXPECT_EQ(ia->snd_wscale, ws ? offered_shift(cb) : 0);
      EXPECT_EQ(ib->rcv_wscale, ws ? offered_shift(cb) : 0);
      EXPECT_EQ(ib->snd_wscale, ws ? offered_shift(ca) : 0);
      const std::uint32_t mss = ts ? 1448 : 1460;
      EXPECT_EQ(ia->snd_mss, mss);
      EXPECT_EQ(ib->snd_mss, mss);
      EXPECT_EQ(ia->adv_mss, 1460u);
      // The SYN offers the configuration; the SYN-ACK echoes what both support.
      const auto syn = find(h, Side::a, is_syn);
      const auto synack = find(h, Side::b, is_synack);
      ASSERT_EQ(syn.size(), 1u);
      ASSERT_EQ(synack.size(), 1u);
      const w::TcpOptions so = parse(syn[0]->bytes)->v.opt;
      const w::TcpOptions ao = parse(synack[0]->bytes)->v.opt;
      EXPECT_EQ(so.mss, std::optional<std::uint16_t>{1460});
      EXPECT_EQ(so.sack_permitted, ca.tcp.sack);
      EXPECT_EQ(so.ts.has_value(), ca.tcp.timestamps);
      EXPECT_EQ(so.wscale.has_value(), ca.tcp.window_scaling);
      EXPECT_EQ(ao.mss, std::optional<std::uint16_t>{1460});
      EXPECT_EQ(ao.sack_permitted, sack);
      EXPECT_EQ(ao.ts.has_value(), ts);
      EXPECT_EQ(ao.wscale.has_value(), ws);
      if (ts) {
        EXPECT_EQ(ao.ts->ecr, so.ts->val);
      }
      // Three full segments with the first held: SACK blocks iff negotiated,
      // timestamps on every later segment iff negotiated.
      const t::Bytes data = t::pattern(3 * std::size_t{mss}, 3);
      const auto n = h.a().tcp_send(p->client, data);
      ASSERT_TRUE(n);
      ASSERT_EQ(*n, data.size());
      h.settle();
      ASSERT_EQ(h.held_count(), 1u);
      const auto dup = find(h, Side::b, [](const w::TcpView& v) {
        return !has(v, w::tcp_syn) && v.payload.empty();
      });
      ASSERT_FALSE(dup.empty());
      const w::TcpView last = parse(dup.back()->bytes)->v;
      EXPECT_EQ(last.opt.sack_count > 0, sack);
      EXPECT_EQ(last.opt.ts.has_value(), ts);
      h.release_all_held();
      h.run_for(500ms);
      EXPECT_EQ(drain(h.b(), p->server), data);
      for (const t::Sent* s : find(h, Side::a, [](const w::TcpView& v) {
             return !has(v, w::tcp_syn);
           })) {
        EXPECT_EQ(parse(s->bytes)->v.opt.ts.has_value(), ts);
      }
      h.a().debug_check();
      h.b().debug_check();
    }
  }
}

// Simultaneous open with SYN-ACKs crossing in flight (RFC 9293 §3.5 figure
// 8; §4.4 step 0): both complete, each sends one SYN-ACK.
TEST(TcpHandshake, SimultaneousOpenWithCrossingSynAcks) {
  t::TcpHarness h;
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  const auto ca = h.a().tcp_connect(Endpoint{h.addr(Side::b), 5000}, {}, 4000);
  const auto cb = h.b().tcp_connect(Endpoint{h.addr(Side::a), 4000}, {}, 5000);
  ASSERT_TRUE(ca && cb);
  h.run_for(100ms);
  EXPECT_EQ(state(h.a(), *ca), TcpState::established);
  EXPECT_EQ(state(h.b(), *cb), TcpState::established);
  const t::Bytes x = t::pattern(1000, 1), y = t::pattern(2000, 2);
  ASSERT_TRUE(h.a().tcp_send(*ca, x));
  ASSERT_TRUE(h.b().tcp_send(*cb, y));
  h.run_for(5s);
  EXPECT_EQ(drain(h.b(), *cb), x);
  EXPECT_EQ(drain(h.a(), *ca), y);
  EXPECT_EQ(find(h, Side::a, is_syn).size(), 1u);
  EXPECT_EQ(find(h, Side::b, is_syn).size(), 1u);
  EXPECT_EQ(find(h, Side::a, is_synack).size(), 1u);
  EXPECT_EQ(find(h, Side::b, is_synack).size(), 1u);
  // ev_connected on both.
  for (utcp::Stack* s : {&h.a(), &h.b()}) {
    bool connected = false;
    while (const auto e = s->poll_event()) {
      connected = connected || (e->events & utcp::ev_connected) != 0;
    }
    EXPECT_TRUE(connected);
  }
  h.a().debug_check();
  h.b().debug_check();
}

// One stack driven segment by segment from a peer at 10.0.0.1.
class Driven {
public:
  Driven() : s_(t::TcpHarness::default_config(Side::b)) {
    const auto l = s_.tcp_listen(Endpoint{{}, port}, 16, {});
    EXPECT_TRUE(l.has_value());
    listener_ = l.value_or(Handle{});
  }
  utcp::Stack& stack() { return s_; }
  Endpoint local() const { return Endpoint{s_.config().local_addr, port}; }
  static Endpoint peer(std::uint16_t p) { return Endpoint{Ipv4Addr::from_octets(10, 0, 0, 1), p}; }
  void send(const t::TcpSpec& spec) { s_.receive(now_, t::tcp_datagram(spec)); }
  // Datagrams the stack sent since the last call.
  std::vector<t::Bytes> out() {
    std::vector<t::Bytes> v;
    while (auto p = s_.pop_transmit()) {
      const auto b = p->buf.bytes();
      v.emplace_back(b.begin(), b.end());
    }
    return v;
  }
  Handle listener() const { return listener_; }

private:
  utcp::Stack s_;
  Time now_{1'000'000'000};
  Handle listener_;
};

// A SYN with ECE|CWR (RFC 3168 ECN setup) or AE|CWR|ECE (AccECN) gets a
// SYN-ACK with all three clear; data then goes Not-ECT. SYN data is not
// acknowledged (no TCP Fast Open).
TEST(TcpHandshake, EcnSetupAndSynDataAreNotTaken) {
  Driven d;
  const std::array<std::uint16_t, 2> ecn{w::tcp_ece | w::tcp_cwr,
                                         w::tcp_ae | w::tcp_cwr | w::tcp_ece};
  for (std::size_t i = 0; i < ecn.size(); ++i) {
    SCOPED_TRACE(i);
    const auto peer = Driven::peer(static_cast<std::uint16_t>(40000 + i));
    t::TcpSpec syn(peer, d.local());
    syn.seq = Seq32{1000};
    syn.flags = static_cast<std::uint16_t>(w::tcp_syn | ecn[i]);
    syn.opt.mss = 1460;
    syn.payload = t::pattern(100);
    d.send(syn);
    const auto out = d.out();
    ASSERT_EQ(out.size(), 1u);
    const auto p = parse(out[0]);
    ASSERT_TRUE(p);
    EXPECT_EQ(p->v.h.flags, w::tcp_syn | w::tcp_ack);
    EXPECT_EQ(p->v.h.ack, Seq32{1001});  // the 100 SYN bytes are not acknowledged
    EXPECT_EQ(p->ip.tos & 3, 0);
    t::TcpSpec ack(peer, d.local());
    ack.seq = Seq32{1001};
    ack.ack = p->v.h.seq + 1;
    ack.flags = w::tcp_ack;
    d.send(ack);
    const auto s = d.stack().tcp_accept(d.listener());
    ASSERT_TRUE(s);
    std::array<std::byte, 16> buf{};
    EXPECT_EQ(d.stack().tcp_recv(*s, buf).error(), utcp::Error::would_block);
    ASSERT_TRUE(d.stack().tcp_send(*s, t::pattern(500)));
    const auto data = d.out();
    ASSERT_EQ(data.size(), 1u);
    const auto q = parse(data[0]);
    ASSERT_TRUE(q);
    EXPECT_EQ(q->v.payload.size(), 500u);
    EXPECT_EQ(q->ip.tos & 3, 0);  // Not-ECT
    EXPECT_EQ(q->v.h.flags & (w::tcp_ece | w::tcp_cwr | w::tcp_ae), 0);
  }
  d.stack().debug_check();
}

// §4.13: peer MSS 0 or absent -> 536; below the floor -> 48 (36 payload
// bytes with timestamps).
TEST(TcpHandshake, PeerMssFloor) {
  struct Case {
    std::optional<std::uint16_t> mss;
    bool ts;
    std::uint32_t want;
  };
  const std::array<Case, 8> cases{{{std::nullopt, false, 536},
                                   {0, false, 536},
                                   {1, false, 48},
                                   {12, false, 48},
                                   {48, false, 48},
                                   {1, true, 36},
                                   {12, true, 36},
                                   {1460, true, 1448}}};
  Driven d;
  for (std::size_t i = 0; i < cases.size(); ++i) {
    const Case& c = cases[i];
    SCOPED_TRACE(i);
    const auto peer = Driven::peer(static_cast<std::uint16_t>(41000 + i));
    t::TcpSpec syn(peer, d.local());
    syn.seq = Seq32{5000};
    syn.flags = w::tcp_syn;
    syn.opt.mss = c.mss;
    if (c.ts) {
      syn.opt.ts = w::Timestamps{100, 0};
    }
    d.send(syn);
    const auto out = d.out();
    ASSERT_EQ(out.size(), 1u);
    const auto p = parse(out[0]);
    ASSERT_TRUE(p);
    t::TcpSpec ack(peer, d.local());
    ack.seq = Seq32{5001};
    ack.ack = p->v.h.seq + 1;
    ack.flags = w::tcp_ack;
    if (c.ts) {
      ASSERT_TRUE(p->v.opt.ts);
      ack.opt.ts = w::Timestamps{101, p->v.opt.ts->val};
    }
    d.send(ack);
    const auto s = d.stack().tcp_accept(d.listener());
    ASSERT_TRUE(s);
    EXPECT_EQ(d.stack().tcp_info(*s)->snd_mss, c.want);
  }
  d.stack().debug_check();
}

// A lost SYN-ACK: the client's retransmitted SYN gets a SYN-ACK at once
// (§4.4 step 0) and the handshake completes at the client's 1 s
// retransmission. The server's own SYN-ACK timer is moved to 3 s so the
// reply is step 0's.
TEST(TcpHandshake, LostSynAckAnsweredAtClientRetransmission) {
  StackConfig cb = config(Side::b);
  cb.tcp.rto_initial = 3s;
  t::TcpHarness h(config(Side::a), cb);
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  bool dropped = false;
  h.set_hook([&](Side from, t::Bytes& d) {
    const auto p = parse(d);
    if (from == Side::b && p && is_synack(p->v) && !dropped) {
      dropped = true;
      return t::Verdict::drop;
    }
    return t::Verdict::deliver;
  });
  const Time t0 = h.now();
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 16, {});
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  ASSERT_TRUE(l && c);
  h.run_until(t0 + 990ms);
  EXPECT_EQ(state(h.a(), *c), TcpState::syn_sent);
  h.run_until(t0 + 1s + 25ms);
  EXPECT_EQ(state(h.a(), *c), TcpState::established);
  const auto syns = find(h, Side::a, is_syn);
  const auto synacks = find(h, Side::b, is_synack);
  ASSERT_EQ(syns.size(), 2u);
  ASSERT_EQ(synacks.size(), 2u);
  EXPECT_EQ(syns[1]->t, t0 + 1s);
  EXPECT_EQ(synacks[1]->t, t0 + 1s + 10ms);  // at the retransmitted SYN's arrival
  h.run_for(10s);
  EXPECT_EQ(find(h, Side::b, is_synack).size(), 2u);
  EXPECT_TRUE(h.b().tcp_accept(*l).has_value());
  h.a().debug_check();
  h.b().debug_check();
}

// §4.8: both sides take an RTT sample from the handshake; a retransmitted
// SYN gives none without timestamps (RTO then 3 s, RFC 6298 §5.7) and one
// from TSecr with them.
TEST(TcpHandshake, HandshakeRttSamples) {
  {
    t::TcpHarness h;
    h.set_delay(Side::a, 10ms);
    h.set_delay(Side::b, 10ms);
    const auto p = open(h);
    ASSERT_TRUE(p);
    EXPECT_EQ(h.a().tcp_info(p->client)->srtt, 20ms);
    EXPECT_EQ(h.b().tcp_info(p->server)->srtt, 20ms);
  }
  for (const bool ts : {false, true}) {
    SCOPED_TRACE(ts);
    StackConfig ca = config(Side::a), cb = config(Side::b);
    ca.tcp.timestamps = cb.tcp.timestamps = ts;
    t::TcpHarness h(ca, cb);
    h.set_delay(Side::a, 10ms);
    h.set_delay(Side::b, 10ms);
    bool dropped = false;
    h.set_hook([&](Side from, t::Bytes& d) {
      const auto q = parse(d);
      if (from == Side::a && q && is_syn(q->v) && !dropped) {
        dropped = true;
        return t::Verdict::drop;
      }
      return t::Verdict::deliver;
    });
    const auto p = open(h, 2s);
    ASSERT_TRUE(p);
    const auto ia = h.a().tcp_info(p->client);
    if (ts) {
      EXPECT_EQ(ia->srtt, 20ms);
    } else {
      EXPECT_EQ(ia->srtt, Duration::zero());
      EXPECT_EQ(ia->rto, 3s);
    }
    EXPECT_EQ(h.b().tcp_info(p->server)->srtt, 20ms);  // b saw one SYN
  }
}

// RFC 5681 §3.1 / Linux tcp_init_transfer: IW = 1 after one SYN
// retransmission (rfc) or after two (linux_compat).
TEST(TcpHandshake, InitialWindowAfterSynLoss) {
  struct Case {
    utcp::ProfileId profile;
    int drops;
    std::uint32_t cwnd;
  };
  const std::array<Case, 5> cases{{{utcp::ProfileId::rfc, 0, 3},
                                   {utcp::ProfileId::rfc, 1, 1},
                                   {utcp::ProfileId::linux_compat, 0, 10},
                                   {utcp::ProfileId::linux_compat, 1, 10},
                                   {utcp::ProfileId::linux_compat, 2, 1}}};
  for (const Case& c : cases) {
    SCOPED_TRACE(std::to_string(static_cast<int>(c.profile)) + "/" + std::to_string(c.drops));
    t::TcpHarness h(config(Side::a, c.profile), config(Side::b, c.profile));
    int dropped = 0;
    h.set_hook([&](Side from, t::Bytes& d) {
      const auto q = parse(d);
      if (from == Side::a && q && is_syn(q->v) && dropped < c.drops) {
        ++dropped;
        return t::Verdict::drop;
      }
      return t::Verdict::deliver;
    });
    const auto p = open(h, 10s);
    ASSERT_TRUE(p);
    EXPECT_EQ(h.a().tcp_info(p->client)->cwnd, c.cwnd);
  }
}

}  // namespace
