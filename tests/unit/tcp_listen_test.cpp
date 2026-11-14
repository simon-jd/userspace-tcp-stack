// m1-tcp-core acceptance test 6: listeners, refused connects, many
// connections, and blocked connections resuming (DESIGN §3.4, §3.5, §4.3).
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "tcp_test_util.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Endpoint;
using utcp::Error;
using utcp::Handle;
using utcp::StackConfig;
using utcp::TcpState;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;
using namespace utcp::test::tcpt;

// §3.5 tcp_listen, Linux tcp_conn_request / sk_acceptq_is_full: with more
// than `backlog` connections waiting for tcp_accept, SYNs are dropped
// (TcpExtListenOverflows); the client's SYN retransmission gets in once the
// application accepts.
TEST(TcpListen, FullBacklogDropsSyn) {
  t::TcpHarness h;
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 2, {});
  ASSERT_TRUE(l);
  std::vector<Handle> clients;
  for (int i = 0; i < 4; ++i) {
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    ASSERT_TRUE(c);
    clients.push_back(*c);
    h.run_for(100ms);
  }
  // Linux admits backlog + 1 (the queue is full when it holds more than
  // backlog).
  for (int i = 0; i < 3; ++i) {
    EXPECT_EQ(state(h.a(), clients[static_cast<std::size_t>(i)]), TcpState::established) << i;
  }
  EXPECT_EQ(state(h.a(), clients[3]), TcpState::syn_sent);
  EXPECT_EQ(find(h, Side::b, is_synack).size(), 3u);
  EXPECT_EQ(h.b().stats().TcpExtListenOverflows, 1u);
  EXPECT_EQ(h.b().stats().TcpExtListenDrops, 1u);
  EXPECT_TRUE(find(h, Side::b, is_rst).empty());
  ASSERT_TRUE(h.b().tcp_accept(*l));
  h.run_for(1s);  // the SYN retransmission, 1 s after the first
  EXPECT_EQ(state(h.a(), clients[3]), TcpState::established);
  for (int i = 0; i < 3; ++i) {
    EXPECT_TRUE(h.b().tcp_accept(*l)) << i;
  }
  EXPECT_EQ(h.b().tcp_accept(*l).error(), Error::would_block);
  h.a().debug_check();
  h.b().debug_check();
}

// Linux tcp_v4_syn_recv_sock / tcp_check_req with tcp_abort_on_overflow =
// 0: a child whose handshake completes while the accept queue holds more than
// backlog has its ACK dropped and stays in SYN-RECEIVED; the client's answer
// to the next SYN-ACK retransmission completes it once there is room.
TEST(TcpListen, CompletingAckDroppedWhileQueueFull) {
  t::TcpHarness h;
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 2, {});
  ASSERT_TRUE(l);
  std::vector<Handle> clients;
  auto connect = [&] {
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    ASSERT_TRUE(c);
    clients.push_back(*c);
  };
  connect();
  h.run_for(100ms);
  connect();
  h.run_for(100ms);
  // Queue at backlog: both SYNs of the next pair are taken, the first ACK
  // fills the queue past backlog, the second is dropped.
  const utcp::Time t0 = h.now();
  connect();
  connect();
  h.run_for(100ms);
  for (const Handle c : clients) {
    EXPECT_EQ(state(h.a(), c), TcpState::established);  // the clients do not know
  }
  EXPECT_EQ(h.b().stats().TcpExtListenOverflows, 1u);
  EXPECT_EQ(h.b().stats().TcpExtListenDrops, 1u);
  std::size_t accepted = 0;
  while (h.b().tcp_accept(*l)) {
    ++accepted;
  }
  EXPECT_EQ(accepted, 3u);
  // The child's SYN-ACK timer (1 s after its SYN arrived) resends; the
  // client's challenge ACK completes the handshake.
  h.run_until(t0 + 10ms + 1s + 20ms);
  EXPECT_TRUE(h.b().tcp_accept(*l));
  EXPECT_EQ(h.a().stats().TcpExtTCPSYNChallenge, 1u);
  EXPECT_TRUE(find(h, Side::b, is_rst).empty());
  h.a().debug_check();
  h.b().debug_check();
}

// RFC 9293 §3.10.7.1 and §3.10.7.3: a SYN to a port without a listener gets
// <SEQ=0><ACK=SEG.SEQ+1><CTL=RST,ACK>, which fails the connect.
TEST(TcpListen, ConnectToClosedPortIsRefused) {
  t::TcpHarness h;
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), 9}, {});
  ASSERT_TRUE(c);
  h.run_for(100ms);
  const auto rst = find(h, Side::b, is_rst);
  ASSERT_EQ(rst.size(), 1u);
  const auto syn = find(h, Side::a, is_syn);
  ASSERT_EQ(syn.size(), 1u);
  const auto r = parse(rst[0]->bytes);
  EXPECT_TRUE(has(r->v, w::tcp_ack));
  EXPECT_EQ(r->v.h.ack, parse(syn[0]->bytes)->v.h.seq + 1);
  EXPECT_EQ(state(h.a(), *c), TcpState::closed);
  EXPECT_NE(events_of(h.a(), *c) & utcp::ev_error, 0);
  EXPECT_EQ(h.a().take_error(*c), Error::connection_refused);
  EXPECT_EQ(h.a().stats().TcpAttemptFails, 1u);
  ASSERT_TRUE(h.a().tcp_close(*c));
  EXPECT_EQ(h.a().debug_usage().tcp_slots, 0u);
}

// 1000 connections through one listener, each moving data both ways and
// closing; nothing is left once TIME-WAIT ends.
TEST(TcpListen, ThousandConcurrentConnections) {
  constexpr std::size_t n = 1000;
  t::TcpHarness h;
  h.set_delay(Side::a, 1ms);
  h.set_delay(Side::b, 1ms);
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, n, {});
  ASSERT_TRUE(l);
  std::vector<Handle> clients, servers;
  for (std::size_t i = 0; i < n; ++i) {
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    ASSERT_TRUE(c) << i;
    clients.push_back(*c);
  }
  h.run_for(100ms);
  while (const auto s = h.b().tcp_accept(*l)) {
    servers.push_back(*s);
  }
  ASSERT_EQ(servers.size(), n);
  EXPECT_EQ(h.a().debug_usage().tcp_slots, n);
  EXPECT_EQ(h.b().debug_usage().tcp_slots, n + 1);
  // Each pair: 3000 bytes each way, keyed by the connection's index.
  for (std::size_t i = 0; i < n; ++i) {
    const auto seed = static_cast<std::uint8_t>(i);
    ASSERT_TRUE(h.a().tcp_send(clients[i], t::pattern(3000, seed)));
    ASSERT_TRUE(h.b().tcp_send(servers[i], t::pattern(3000, static_cast<std::uint8_t>(seed + 1))));
  }
  h.run_for(2s);
  for (std::size_t i = 0; i < n; ++i) {
    const auto seed = static_cast<std::uint8_t>(i);
    ASSERT_EQ(drain(h.b(), servers[i]), t::pattern(3000, seed)) << i;
    ASSERT_EQ(drain(h.a(), clients[i]), t::pattern(3000, static_cast<std::uint8_t>(seed + 1)))
        << i;
  }
  for (std::size_t i = 0; i < n; ++i) {
    ASSERT_TRUE(h.a().tcp_close(clients[i]));
  }
  h.run_for(1s);
  for (std::size_t i = 0; i < n; ++i) {
    ASSERT_TRUE(h.b().tcp_close(servers[i]));
  }
  h.run_for(1s);
  EXPECT_EQ(h.a().debug_usage().time_wait_entries, n);
  EXPECT_EQ(h.b().debug_usage().tcp_slots, 1u);
  h.run_for(60s);
  const utcp::StackUsage ua = h.a().debug_usage(), ub = h.b().debug_usage();
  EXPECT_EQ(ua.tcp_slots, 0u);
  EXPECT_EQ(ua.time_wait_entries, 0u);
  EXPECT_EQ(ua.conn_timers_armed, 0u);
  EXPECT_EQ(ub.conn_timers_armed, 0u);
  EXPECT_EQ(ua.chunks, ua.chunks_free);
  EXPECT_EQ(ub.chunks, ub.chunks_free);
  EXPECT_EQ(ua.pool_buffers, ua.pool_buffers_free);
  EXPECT_EQ(h.a().stats().TcpOutRsts + h.b().stats().TcpOutRsts, 0u);
  h.a().debug_check();
  h.b().debug_check();
}

// §3.4: with tx_queue_packets = 8, connections that find the transmit queue
// full join the blocked FIFO and resume when the host drains it; every byte
// arrives.
TEST(TcpListen, BlockedConnectionsResumeWhenTheHostDrains) {
  StackConfig ca = config(Side::a);
  ca.tx_queue_packets = 8;
  t::TcpHarness h(ca, config(Side::b));
  h.set_delay(Side::a, 2ms);
  h.set_delay(Side::b, 2ms);
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 16, {});
  ASSERT_TRUE(l);
  constexpr std::size_t n = 4;
  std::vector<Handle> clients, servers;
  for (std::size_t i = 0; i < n; ++i) {
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    ASSERT_TRUE(c);
    clients.push_back(*c);
  }
  h.run_for(100ms);
  while (const auto s = h.b().tcp_accept(*l)) {
    servers.push_back(*s);
  }
  ASSERT_EQ(servers.size(), n);
  std::vector<t::Bytes> data, got(n);
  std::vector<std::size_t> sent(n, 0);
  for (std::size_t i = 0; i < n; ++i) {
    data.push_back(t::pattern(300'000, static_cast<std::uint8_t>(i * 7)));
  }
  std::uint32_t max_blocked = 0;
  for (int round = 0; round < 3000; ++round) {
    for (std::size_t i = 0; i < n; ++i) {
      if (sent[i] < data[i].size()) {
        const auto r = h.a().tcp_send(clients[i], std::span(data[i]).subspan(sent[i]));
        if (r) {
          sent[i] += *r;
        }
      }
    }
    max_blocked = std::max(max_blocked, h.a().debug_usage().blocked_conns);
    h.run_for(1ms);
    bool done = true;
    for (std::size_t i = 0; i < n; ++i) {
      const t::Bytes part = drain(h.b(), servers[i]);
      got[i].insert(got[i].end(), part.begin(), part.end());
      done = done && got[i].size() == data[i].size();
    }
    if (done) {
      break;
    }
  }
  EXPECT_GT(max_blocked, 0u);
  for (std::size_t i = 0; i < n; ++i) {
    EXPECT_EQ(got[i], data[i]) << i;
  }
  EXPECT_EQ(h.a().debug_usage().blocked_conns, 0u);
  h.a().debug_check();
  h.b().debug_check();
}

// Linux tcp_rcv_state_process (TCP_LISTEN): a SYN with FIN is dropped; no
// SYN-ACK, no child.
TEST(TcpListen, SynFinDropped) {
  Driven d;
  ASSERT_TRUE(d.stack().tcp_listen(Endpoint{{}, port}, 4, {}));
  t::TcpSpec syn(Driven::peer(40000), d.local());
  syn.seq = utcp::Seq32{1000};
  syn.flags = w::tcp_syn | w::tcp_fin;
  syn.opt.mss = 1460;
  d.send(syn);
  EXPECT_TRUE(d.out().empty());
  EXPECT_EQ(d.stack().debug_usage().tcp_slots, 1u);
  syn.flags = w::tcp_syn;
  d.send(syn);
  const auto out = d.out();
  ASSERT_EQ(out.size(), 1u);
  EXPECT_TRUE(is_synack(parse(out[0])->v));
}

// §4.4 LISTEN: at most `backlog` children in SYN-RECEIVED (no SYN cookies),
// the only bound on half-open children under a SYN flood. Further SYNs are
// dropped silently and counted; the children go after their SYN-ACK
// retries.
TEST(TcpListen, SynQueueBoundedByBacklog) {
  Driven d;
  ASSERT_TRUE(d.stack().tcp_listen(Endpoint{{}, port}, 4, {}));
  for (std::uint16_t i = 0; i < 5; ++i) {
    t::TcpSpec syn(Driven::peer(static_cast<std::uint16_t>(41000 + i)), d.local());
    syn.seq = utcp::Seq32{1000u * (i + 1u)};
    syn.flags = w::tcp_syn;
    syn.opt.mss = 1460;
    d.send(syn);
  }
  std::size_t synacks = 0, rsts = 0;
  for (const t::Bytes& b : d.out()) {
    const auto q = parse(b);
    ASSERT_TRUE(q);
    synacks += is_synack(q->v) ? 1 : 0;
    rsts += is_rst(q->v) ? 1 : 0;
  }
  EXPECT_EQ(synacks, 4u);
  EXPECT_EQ(rsts, 0u);
  EXPECT_EQ(d.stack().stats().TcpExtListenDrops, 1u);
  EXPECT_EQ(d.stack().stats().TcpExtListenOverflows, 0u);
  EXPECT_EQ(d.stack().debug_usage().tcp_slots, 5u);  // the listener and 4 children
  d.run_for(70s);
  EXPECT_EQ(d.stack().debug_usage().tcp_slots, 1u);
  d.stack().debug_check();
}

// §3.5 tcp_close on a listener (Linux inet_csk_listen_stop): established
// children not accepted get an RST <SEQ=SND.NXT>, a child in SYN-RECEIVED
// goes silently, and nothing of the listener remains.
TEST(TcpListen, ClosingListenerResetsUnacceptedChildren) {
  t::TcpHarness h;
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 16, {});
  ASSERT_TRUE(l);
  std::vector<Handle> clients;
  for (int i = 0; i < 2; ++i) {
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    ASSERT_TRUE(c);
    clients.push_back(*c);
  }
  h.run_for(100ms);
  // The third client's completing ACK is lost: its child stays in
  // SYN-RECEIVED (the client is established).
  h.set_hook([](Side from, t::Bytes& d) {
    const auto q = parse(d);
    return from == Side::a && q && is_pure_ack(q->v) ? t::Verdict::drop : t::Verdict::deliver;
  });
  const auto c3 = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  ASSERT_TRUE(c3);
  h.run_for(100ms);
  h.set_hook(nullptr);
  EXPECT_EQ(state(h.a(), *c3), TcpState::established);
  EXPECT_EQ(h.b().debug_usage().tcp_slots, 4u);
  // Each child's SND.NXT is its ISS + 1 (no data sent), by client port.
  std::vector<std::pair<std::uint16_t, utcp::Seq32>> snd_nxt;
  for (const t::Sent* s : find(h, Side::b, is_synack)) {
    const auto q = parse(s->bytes);
    snd_nxt.emplace_back(q->v.h.dport, q->v.h.seq + 1);
  }
  h.clear_log();
  ASSERT_TRUE(h.b().tcp_close(*l));
  h.settle();
  const auto rst = find(h, Side::b, is_rst);
  ASSERT_EQ(rst.size(), 2u);
  for (std::size_t i = 0; i < 2; ++i) {
    // The clients take an RST only at SEQ = RCV.NXT (RFC 5961 §3.2).
    EXPECT_EQ(state(h.a(), clients[i]), TcpState::closed) << i;
    EXPECT_EQ(h.a().take_error(clients[i]), Error::connection_reset) << i;
  }
  for (const t::Sent* s : rst) {
    const auto q = parse(s->bytes);
    const auto it = std::ranges::find(snd_nxt, q->v.h.dport,
                                      &std::pair<std::uint16_t, utcp::Seq32>::first);
    ASSERT_NE(it, snd_nxt.end());
    EXPECT_EQ(q->v.h.seq, it->second);  // <SEQ=SND.NXT>
  }
  EXPECT_EQ(state(h.a(), *c3), TcpState::established);
  EXPECT_EQ(h.b().debug_usage().tcp_slots, 0u);
  EXPECT_FALSE(h.b().tcp_accept(*l));
  h.b().debug_check();
}

// §3.5: when the ChunkPool runs out, tcp_send refuses and readiness says not
// writable; once chunks are freed (here by reading another connection) the
// refused connection gets ev_writable, even with nothing in flight.
TEST(TcpListen, ChunkPoolExhaustionResumesWriters) {
  StackConfig ca = config(Side::a);
  ca.chunk_limit = 4;
  t::TcpHarness h(ca, config(Side::b));
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 4, {});
  ASSERT_TRUE(l);
  const auto c1 = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  const auto c2 = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
  ASSERT_TRUE(c1 && c2);
  h.run_for(100ms);
  const auto s1 = h.b().tcp_accept(*l);
  ASSERT_TRUE(s1);
  ASSERT_TRUE(h.b().tcp_send(*s1, t::pattern(16 * 1024)));
  h.run_for(100ms);
  EXPECT_EQ(h.a().debug_usage().chunks - h.a().debug_usage().chunks_free, 4u);
  (void)events_of(h.a(), *c2);
  const auto r = h.a().tcp_send(*c2, t::pattern(1000));
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error(), Error::would_block);
  EXPECT_FALSE(h.a().tcp_readiness(*c2).writable);
  EXPECT_EQ(drain(h.a(), *c1).size(), 16u * 1024);
  EXPECT_NE(events_of(h.a(), *c2) & utcp::ev_writable, 0);
  EXPECT_TRUE(h.a().tcp_readiness(*c2).writable);
  EXPECT_TRUE(h.a().tcp_send(*c2, t::pattern(1000)));
  h.a().debug_check();
}

}  // namespace
