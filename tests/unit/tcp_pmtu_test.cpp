// m1-tcp-robust acceptance test 4 and the engine's PMTU and MSS rules
// (DESIGN §4.7, §4.13): frag-needed handling with the RFC 5927 sequence
// check, its trace kind, the PMTU cache, retransmissions cut to the current
// MSS (Linux tcp_v4_mtu_reduced, tcp_simple_retransmit, tcp_retransmit_skb),
// and ICMP hard and soft errors (RFC 1122 §4.2.3.9, RFC 5461 §4).
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "core/wire/icmp.hpp"
#include "tcp_test_util.hpp"
#include "utcp/trace.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Endpoint;
using utcp::Error;
using utcp::StackConfig;
using utcp::TcpState;
using utcp::TxKind;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;
using namespace utcp::test::tcpt;

class TxSink : public utcp::TraceSink {
public:
  void on_event(const utcp::TraceEvent& e) override {
    if (e.kind == utcp::TraceKind::tx) {
      kinds.push_back(e.tx);
    }
  }
  std::vector<TxKind> kinds;
};

std::size_t count(const std::vector<TxKind>& v, TxKind k) {
  std::size_t n = 0;
  for (const TxKind x : v) {
    n += x == k ? 1u : 0u;
  }
  return n;
}

// RFC 1191 §6, §4.13: a frag-needed for an in-flight segment lowers the
// connection's PMTU and the cache; the segments too large for the new MSS are
// resent at once as pmtu_rexmit, under cwnd. A frag-needed that does not
// lower the connection's PMTU changes nothing and is counted.
TEST(TcpPmtu, FragNeededResendsAsPmtuRexmit) {
  StackConfig ca = config(Side::a);
  ca.trace_mask = utcp::trace_bit(utcp::TraceKind::tx);
  t::TcpHarness h(ca, config(Side::b));
  TxSink sink;
  h.a().set_trace_sink(&sink);
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  const auto p = open(h);
  ASSERT_TRUE(p);
  bool holding = true;
  h.set_hook([&](Side from, t::Bytes& d) {
    const auto q = parse(d);
    return from == Side::a && q && is_data(q->v) && holding ? t::Verdict::hold
                                                           : t::Verdict::deliver;
  });
  const std::uint32_t mss = h.a().tcp_info(p->client)->snd_mss;
  ASSERT_EQ(mss, 1448u);
  const t::Bytes data = t::pattern(4 * std::size_t{mss}, 5);
  ASSERT_TRUE(h.a().tcp_send(p->client, data));
  h.settle();
  ASSERT_EQ(h.held_count(), 4u);
  // A router on the path cannot forward them: it drops them and says so.
  const t::Bytes offending = h.held(0);
  h.drop_held();
  holding = false;
  sink.kinds.clear();
  const std::size_t log_mark = h.log().size();
  const auto router = utcp::Ipv4Addr::from_octets(10, 0, 0, 254);
  h.a().receive(h.now(), t::icmp_error(router, h.addr(Side::a), w::icmp_dest_unreach,
                                       w::icmp_frag_needed, 1400, offending));
  h.settle();
  auto i = h.a().tcp_info(p->client);
  EXPECT_EQ(i->pmtu, 1400);
  EXPECT_EQ(i->snd_mss, 1348u);  // 1400 - 40 - 12
  EXPECT_EQ(count(sink.kinds, TxKind::rexmit), 0u);
  EXPECT_GT(count(sink.kinds, TxKind::pmtu_rexmit), 0u);
  h.run_for(2s);
  EXPECT_EQ(drain(h.b(), p->server), data);
  EXPECT_EQ(h.a().tcp_info(p->client)->unacked, 0u);
  EXPECT_EQ(count(sink.kinds, TxKind::rto_rexmit), 0u);
  // Every segment resent fits the new PMTU.
  std::size_t resent = 0;
  for (std::size_t k = log_mark; k < h.log().size(); ++k) {
    const t::Sent& s = h.log()[k];
    if (s.from == Side::a) {
      EXPECT_LE(s.bytes.size(), 1400u);
      const auto q = parse(s.bytes);
      resent += q && is_data(q->v) ? q->v.payload.size() : 0u;
    }
  }
  EXPECT_EQ(resent, data.size());
  // Not a reduction (the IP layer clamps 1450 to the cached 1400): ignored
  // and counted.
  holding = true;
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(1000, 6)));
  h.settle();
  ASSERT_EQ(h.held_count(), 1u);
  h.a().receive(h.now(), t::icmp_error(router, h.addr(Side::a), w::icmp_dest_unreach,
                                       w::icmp_frag_needed, 1450, h.held(0)));
  EXPECT_EQ(h.a().stats().icmp_pmtu_not_reduced, 1u);
  EXPECT_EQ(h.a().tcp_info(p->client)->pmtu, 1400);
  holding = false;
  h.release_all_held();
  h.run_for(1s);
  // The cache took the value: a new connection to b starts at 1400.
  const auto c2 = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  ASSERT_TRUE(c2);
  EXPECT_EQ(h.a().tcp_info(*c2)->pmtu, 1400);
  h.a().set_trace_sink(nullptr);
  h.a().debug_check();
  h.b().debug_check();
}

// Linux tcp_retransmit_skb: a segment sent at the full MSS is cut when it is
// resent while our ACKs carry SACK blocks (tcp_current_mss), so no datagram
// exceeds the MTU.
TEST(TcpPmtu, RetransmissionCutWhileSendingSackBlocks) {
  t::TcpHarness h;
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  const auto p = open(h);
  ASSERT_TRUE(p);
  int a_drops = 1, b_drops = 2;
  std::optional<utcp::Seq32> b_first;
  h.set_hook([&](Side from, t::Bytes& d) {
    const auto q = parse(d);
    if (!q || !is_data(q->v)) {
      return t::Verdict::deliver;
    }
    // a's first data segment, and b's first data segment twice: a holds
    // out-of-order data (and SACKs it) when it retransmits its own.
    if (from == Side::a && a_drops > 0) {
      --a_drops;
      return t::Verdict::drop;
    }
    if (from == Side::b) {
      if (!b_first) {
        b_first = q->v.h.seq;
      }
      if (q->v.h.seq == *b_first && b_drops > 0) {
        --b_drops;
        return t::Verdict::drop;
      }
    }
    return t::Verdict::deliver;
  });
  const std::uint32_t mss = h.a().tcp_info(p->client)->snd_mss;
  const t::Bytes x = t::pattern(3 * std::size_t{mss}, 1), y = t::pattern(3 * std::size_t{mss}, 2);
  ASSERT_TRUE(h.a().tcp_send(p->client, x));
  ASSERT_TRUE(h.b().tcp_send(p->server, y));
  h.run_for(5s);
  EXPECT_EQ(drain(h.b(), p->server), x);
  EXPECT_EQ(drain(h.a(), p->client), y);
  bool cut = false;
  for (const t::Sent& s : h.log()) {
    EXPECT_LE(s.bytes.size(), 1500u);
    const auto q = parse(s.bytes);
    if (s.from == Side::a && q && is_data(q->v) && q->v.opt.sack_count > 0 &&
        q->v.payload.size() < mss) {
      cut = true;
    }
  }
  EXPECT_TRUE(cut);
  EXPECT_GT(h.a().stats().TcpRetransSegs, 0u);
  h.a().debug_check();
  h.b().debug_check();
}

const auto router = utcp::Ipv4Addr::from_octets(10, 0, 0, 254);

// The quoted datagram with its TCP sequence number moved by `delta`.
t::Bytes with_seq_moved(const t::Bytes& d, std::int64_t delta) {
  t::Bytes out = d;
  const std::size_t at = 20 + 4;  // IPv4 header without options, then TCP seq
  std::uint32_t seq = 0;
  for (std::size_t k = 0; k < 4; ++k) {
    seq = (seq << 8) | std::to_integer<std::uint32_t>(out[at + k]);
  }
  seq += static_cast<std::uint32_t>(delta);
  for (std::size_t k = 0; k < 4; ++k) {
    out[at + k] = static_cast<std::byte>(seq >> (8 * (3 - k)));
  }
  return out;
}

// §4.13 (Linux tcp_simple_retransmit): a PMTU drop marks the in-flight
// segments larger than the new MSS lost and enters Loss without cutting
// cwnd; they are split and resent under cwnd, so the flight never exceeds
// cwnd.
TEST(TcpPmtu, DropEntersLossWithoutCwndCutAndResendsUnderCwnd) {
  StackConfig ca = config(Side::a);
  ca.trace_mask = utcp::trace_bit(utcp::TraceKind::tx);
  t::TcpHarness h(ca, config(Side::b));
  TxSink sink;
  h.a().set_trace_sink(&sink);
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  utcp::TcpSocketOptions big;
  big.snd_buf = 1 << 20;
  const auto p = open(h, 100ms, big);
  ASSERT_TRUE(p);
  bool holding = true;
  h.set_hook([&](Side from, t::Bytes& d) {
    const auto q = parse(d);
    return from == Side::a && q && is_data(q->v) && holding ? t::Verdict::hold
                                                           : t::Verdict::deliver;
  });
  const auto i0 = *h.a().tcp_info(p->client);
  ASSERT_EQ(i0.cwnd, 10u);
  const t::Bytes data = t::pattern(20 * std::size_t{i0.snd_mss}, 7);
  ASSERT_EQ(h.a().tcp_send(p->client, data), data.size());
  h.settle();
  ASSERT_EQ(h.held_count(), 10u);
  const t::Bytes offending = h.held(3);
  h.drop_held();
  sink.kinds.clear();
  h.a().receive(h.now(), t::icmp_error(router, h.addr(Side::a), w::icmp_dest_unreach,
                                       w::icmp_frag_needed, 1400, offending));
  h.settle();
  const auto i1 = *h.a().tcp_info(p->client);
  EXPECT_EQ(i1.pmtu, 1400u);
  EXPECT_EQ(i1.snd_mss, 1348u);
  EXPECT_EQ(i1.ca_state, utcp::CaState::loss);
  EXPECT_EQ(i1.cwnd, i0.cwnd);
  EXPECT_EQ(i1.ssthresh, i0.ssthresh);  // max(ssthresh, 3/4 cwnd): still infinite
  // Ten segments of 1448 are now eleven of at most 1348: ten go out, under
  // cwnd, as pmtu_rexmit; the in-flight count stays at cwnd.
  ASSERT_EQ(h.held_count(), 10u);
  for (std::size_t k = 0; k < h.held_count(); ++k) {
    EXPECT_LE(h.held(k).size(), 1400u);
  }
  EXPECT_EQ(count(sink.kinds, TxKind::pmtu_rexmit), 10u);
  EXPECT_EQ(count(sink.kinds, TxKind::data), 0u);
  EXPECT_EQ(i1.unacked - i1.lost + i1.retrans, i1.cwnd);
  holding = false;
  h.release_all_held();
  h.run_for(3s);
  const t::Bytes got = drain(h.b(), p->server);
  EXPECT_EQ(got.size(), data.size());
  EXPECT_TRUE(got == data);
  EXPECT_EQ(count(sink.kinds, TxKind::rto_rexmit), 0u);
  EXPECT_EQ(h.a().stats().TcpExtTCPTimeouts, 0u);
  const auto i2 = *h.a().tcp_info(p->client);
  EXPECT_EQ(i2.unacked, 0u);
  EXPECT_EQ(i2.ca_state, utcp::CaState::open);
  EXPECT_GE(i2.cwnd, i0.cwnd);
  h.a().set_trace_sink(nullptr);
  h.a().debug_check();
}

// RFC 5927 §4.1 (Linux tcp_v4_err): an ICMP error quoting a sequence number
// outside [SND.UNA, SND.NXT) is ignored and counted; the PMTU, the MSS and
// the cache keep their values, and soft errors are not stored.
TEST(TcpPmtu, ForgedErrorOutsideTheFlightIgnored) {
  t::TcpHarness h;
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  const auto p = open(h);
  ASSERT_TRUE(p);
  bool holding = true;
  h.set_hook([&](Side from, t::Bytes& d) {
    const auto q = parse(d);
    return from == Side::a && q && is_data(q->v) && holding ? t::Verdict::hold
                                                           : t::Verdict::deliver;
  });
  const std::uint32_t mss = h.a().tcp_info(p->client)->snd_mss;
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(2 * std::size_t{mss})));
  h.settle();
  ASSERT_EQ(h.held_count(), 2u);
  const t::Bytes first = h.held(0);
  // SND.NXT (just past the flight) and SND.UNA - 1.
  const std::int64_t past = 2 * std::int64_t{mss};
  for (const std::int64_t delta : {past, std::int64_t{-1}, std::int64_t{1} << 30}) {
    h.a().receive(h.now(), t::icmp_error(router, h.addr(Side::a), w::icmp_dest_unreach,
                                         w::icmp_frag_needed, 1400, with_seq_moved(first, delta)));
    h.a().receive(h.now(), t::icmp_error(router, h.addr(Side::a), w::icmp_dest_unreach,
                                         w::icmp_host_unreach, 0, with_seq_moved(first, delta)));
  }
  EXPECT_EQ(h.a().stats().icmp_seq_invalid, 6u);
  const auto i = *h.a().tcp_info(p->client);
  EXPECT_EQ(i.pmtu, 1500u);
  EXPECT_EQ(i.snd_mss, mss);
  EXPECT_EQ(i.ca_state, utcp::CaState::open);
  EXPECT_EQ(h.a().take_error(p->client), std::nullopt);
  // The cache did not take the forged value either.
  const auto c2 = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  ASSERT_TRUE(c2);
  EXPECT_EQ(h.a().tcp_info(*c2)->pmtu, 1500u);
  // The last byte in flight is inside the range.
  h.drop_held();
  holding = false;
  h.a().receive(h.now(), t::icmp_error(router, h.addr(Side::a), w::icmp_dest_unreach,
                                       w::icmp_frag_needed, 1400,
                                       with_seq_moved(first, past - 1)));
  EXPECT_EQ(h.a().tcp_info(p->client)->pmtu, 1400u);
  EXPECT_EQ(h.a().stats().icmp_seq_invalid, 6u);
  h.run_for(2s);
  EXPECT_EQ(drain(h.b(), p->server).size(), 2 * std::size_t{mss});
  EXPECT_EQ(h.a().stats().TcpExtTCPTimeouts, 0u);
  h.a().debug_check();
}

// RFC 1122 §4.2.3.9, RFC 5461 §4, §4.7: in SYN-SENT, protocol and port
// unreachable fail the connect with connection_refused; other unreachables
// are soft errors, reported if the connect later times out.
TEST(TcpPmtu, UnreachableInSynSent) {
  for (const std::uint8_t code : {w::icmp_port_unreach, w::icmp_proto_unreach,
                                  w::icmp_host_unreach}) {
    SCOPED_TRACE(static_cast<int>(code));
    t::TcpHarness h;
    std::optional<t::Bytes> syn;
    h.set_hook([&](Side from, t::Bytes& d) {
      const auto q = parse(d);
      if (from == Side::a && q && is_syn(q->v)) {
        if (!syn) {
          syn = d;
        }
        return t::Verdict::drop;
      }
      return t::Verdict::deliver;
    });
    ASSERT_TRUE(h.b().tcp_listen(Endpoint{{}, port}, 4, {}));
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    ASSERT_TRUE(c);
    h.settle();
    ASSERT_TRUE(syn.has_value());
    h.a().receive(h.now(), t::icmp_error(h.addr(Side::b), h.addr(Side::a), w::icmp_dest_unreach,
                                         code, 0, *syn));
    if (code == w::icmp_host_unreach) {
      EXPECT_EQ(state(h.a(), *c), TcpState::syn_sent);
      h.run_for(300s);
      EXPECT_EQ(state(h.a(), *c), TcpState::closed);
      EXPECT_EQ(h.a().take_error(*c), Error::host_unreachable);
    } else {
      EXPECT_EQ(state(h.a(), *c), TcpState::closed);
      EXPECT_EQ(h.a().take_error(*c), Error::connection_refused);
      EXPECT_EQ(h.a().stats().TcpExtTCPSynRetrans, 0u);
    }
    EXPECT_EQ(h.a().stats().icmp_seq_invalid, 0u);
    h.a().debug_check();
  }
}

// RFC 5461 §4: in a synchronized state every unreachable is soft. The
// connection carries on; the error is reported like SO_ERROR, and it is the
// error of a later timeout unless an acceptable ACK cleared it (Linux
// tcp_ack clears sk_err_soft).
TEST(TcpPmtu, UnreachableInEstablishedIsSoft) {
  t::TcpHarness h;
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  const auto p = open(h);
  ASSERT_TRUE(p);
  bool holding = true, dead = false;
  h.set_hook([&](Side from, t::Bytes& d) {
    if (dead) {
      return t::Verdict::drop;
    }
    const auto q = parse(d);
    return from == Side::a && q && is_data(q->v) && holding ? t::Verdict::hold
                                                           : t::Verdict::deliver;
  });
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(1000, 1)));
  h.settle();
  ASSERT_EQ(h.held_count(), 1u);
  h.a().receive(h.now(), t::icmp_error(h.addr(Side::b), h.addr(Side::a), w::icmp_dest_unreach,
                                       w::icmp_port_unreach, 0, h.held(0)));
  EXPECT_EQ(state(h.a(), p->client), TcpState::established);
  holding = false;
  h.release_all_held();
  h.run_for(1s);
  EXPECT_EQ(drain(h.b(), p->server), t::pattern(1000, 1));
  // The ACK of the data cleared the soft error.
  EXPECT_EQ(h.a().take_error(p->client), std::nullopt);
  // Another one, then the path dies: the timeout reports it.
  holding = true;
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(1000, 2)));
  h.settle();
  ASSERT_EQ(h.held_count(), 1u);
  h.a().receive(h.now(), t::icmp_error(router, h.addr(Side::a), w::icmp_dest_unreach,
                                       w::icmp_host_unreach, 0, h.held(0)));
  h.drop_held();
  dead = true;
  h.run_for(1200s);
  EXPECT_EQ(state(h.a(), p->client), TcpState::closed);
  EXPECT_EQ(h.a().take_error(p->client), Error::host_unreachable);
  h.a().debug_check();
}

}  // namespace
