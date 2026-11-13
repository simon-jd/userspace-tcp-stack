// m1-tcp-core acceptance test 6: listeners, refused connects, many
// connections, and blocked connections resuming (DESIGN §3.4, §3.5, §4.3).
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
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

}  // namespace
