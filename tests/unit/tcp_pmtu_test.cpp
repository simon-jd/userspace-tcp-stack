// The engine's PMTU and MSS rules (DESIGN §4.13): frag-needed handling and
// its trace kind, the PMTU cache, and retransmissions cut to the current MSS
// (Linux tcp_v4_mtu_reduced, tcp_simple_retransmit, tcp_retransmit_skb).
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
using utcp::StackConfig;
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

}  // namespace
