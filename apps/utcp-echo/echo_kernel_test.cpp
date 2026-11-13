// KernelTransport over loopback (Linux sockets, the backend's EventLoop), with
// utcp-echo's server and client on top. These tests live here because the
// KernelTransport sources (apps/common/kernel_transport.*) are tested from a
// program directory; they need only the loopback interface.
#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <vector>

#include "common/kernel_transport.hpp"
#include "utcp-echo/echo.hpp"

namespace utcp::app {
namespace {

constexpr Ipv4Addr loopback = Ipv4Addr::from_octets(127, 0, 0, 1);

// No stop signals: the tests must not change the process's signal mask.
EventLoopOptions quiet_loop() {
  EventLoopOptions o;
  o.stop_signals.clear();
  return o;
}

// Calls the handler functions given; records events by name.
class Script final : public Handler {
public:
  std::function<void(ConnId, ConnId)> accept = [](ConnId, ConnId) {};
  std::function<void(ConnId)> connected = [](ConnId) {};
  std::function<void(ConnId)> readable = [](ConnId) {};
  std::function<void(ConnId)> writable = [](ConnId) {};
  std::function<void(ConnId)> closed = [](ConnId) {};
  std::function<void(ConnId, Error)> error = [](ConnId, Error) {};
  std::vector<std::string> log;

  void on_accept(ConnId l, ConnId c) override { log.push_back("accept"), accept(l, c); }
  void on_connected(ConnId c) override { log.push_back("connected"), connected(c); }
  void on_readable(ConnId c) override { readable(c); }
  void on_writable(ConnId c) override { log.push_back("writable"), writable(c); }
  void on_closed(ConnId c) override { log.push_back("closed"), closed(c); }
  void on_error(ConnId c, Error e) override {
    log.push_back("error:" + std::string(to_string(e)));
    error(c, e);
  }
};

// Ends a run that hangs.
void guard(KernelTransport& t, Duration limit = std::chrono::seconds(10)) {
  t.add_oneshot(limit, [&t] {
    ADD_FAILURE() << "run did not finish in time";
    t.stop();
  });
}

Endpoint listen_any(KernelTransport& t, ConnId& l, const TcpSocketOptions& o = {}) {
  auto r = t.listen(Endpoint{loopback, 0}, 128, o);
  EXPECT_TRUE(r) << t.last_error_detail();
  l = *r;
  return *t.local_endpoint(l);
}

std::vector<std::byte> bytes(std::string_view s) {
  const auto b = std::as_bytes(std::span(s));
  return {b.begin(), b.end()};
}

TEST(EchoKernelTransport, ConnectAcceptExchangeAndCloseInOrder) {
  KernelTransport t(quiet_loop());
  guard(t);
  ConnId l = no_conn, srv = no_conn, cli = no_conn;
  const Endpoint ep = listen_any(t, l);
  std::string got_srv, got_cli;
  bool cli_eof = false, srv_eof = false;
  int closed = 0;
  Script s;
  s.accept = [&](ConnId listener, ConnId c) {
    EXPECT_EQ(listener, l);
    srv = c;
    EXPECT_EQ(*t.remote_endpoint(c), *t.local_endpoint(cli));
  };
  s.connected = [&](ConnId c) {
    EXPECT_EQ(c, cli);
    EXPECT_EQ(*t.send(c, bytes("ping")), 4u);
    t.shutdown_write(c);
    EXPECT_EQ(t.send(c, bytes("x")).error(), Error::shut_down);
  };
  s.readable = [&](ConnId c) {
    std::vector<std::byte> b(100);
    while (true) {
      auto r = t.recv(c, b);
      if (!r) {
        EXPECT_EQ(r.error(), Error::would_block);
        return;
      }
      if (*r == 0) {
        if (c == srv && !srv_eof) {
          srv_eof = true;
          EXPECT_EQ(*t.send(c, bytes("pong")), 4u);
          t.shutdown_write(c);
        } else if (c == cli) {
          cli_eof = true;
        }
        return;
      }
      (c == srv ? got_srv : got_cli).append(reinterpret_cast<const char*>(b.data()), *r);
    }
  };
  s.closed = [&](ConnId c) {
    EXPECT_TRUE(c == srv || c == cli);
    if (++closed == 2) t.stop();
  };
  auto c = t.connect(ep, {});
  ASSERT_TRUE(c) << t.last_error_detail();
  cli = *c;
  t.run(s);
  EXPECT_EQ(got_srv, "ping");
  EXPECT_EQ(got_cli, "pong");
  EXPECT_TRUE(srv_eof);
  EXPECT_TRUE(cli_eof);
  EXPECT_EQ(closed, 2);  // on_closed once both FINs were exchanged, on both ends
  const ConnSample cs = t.sample(cli);
  EXPECT_NE(cs.cc_name_view(), "");
  EXPECT_GT(cs.snd_mss, 0u);
  // tcpi_bytes_acked: the 4 data bytes plus one or both of SYN and FIN
  // (Linux counts sequence space; the sample may precede the FIN's ACK).
  EXPECT_GE(cs.bytes_acked, 5u);
  EXPECT_LE(cs.bytes_acked, 6u);
  EXPECT_EQ(cs.bytes_received, 5u);  // "pong" and the peer's FIN (tcp_rcv_nxt_update)
  EXPECT_TRUE(cs.state == TcpState::time_wait || cs.state == TcpState::fin_wait_2 ||
              cs.state == TcpState::closed)
      << to_string(cs.state);
  t.close(srv);
  t.close(cli);
  t.close(l);
  EXPECT_EQ(t.open_count(), 0u);
}

TEST(EchoKernelTransport, RefusedConnectIsAnError) {
  KernelTransport t(quiet_loop());
  guard(t);
  // A port that was just bound and released: nothing listens there.
  ConnId l = no_conn;
  const Endpoint ep = listen_any(t, l);
  t.close(l);
  Script s;
  Error got = Error::would_block;
  s.error = [&](ConnId, Error e) {
    got = e;
    t.stop();
  };
  auto c = t.connect(ep, {});
  ASSERT_TRUE(c);
  t.run(s);
  EXPECT_EQ(got, Error::connection_refused);
  EXPECT_EQ(t.send(*c, bytes("x")).error(), Error::connection_refused);
  t.close(*c);
}

TEST(EchoKernelTransport, CloseWithUnreadDataResetsThePeer) {
  KernelTransport t(quiet_loop());
  guard(t);
  ConnId l = no_conn, srv = no_conn;
  const Endpoint ep = listen_any(t, l);
  Script s;
  Error got = Error::would_block;
  s.accept = [&](ConnId, ConnId c) { srv = c; };
  s.connected = [&](ConnId c) { (void)t.send(c, bytes("unread")); };
  s.readable = [&](ConnId c) {
    if (c == srv) {
      t.close(srv);  // data unread: RST (RFC 2525 §2.17, Linux tcp_close)
      srv = no_conn;
    }
  };
  s.error = [&](ConnId, Error e) {
    got = e;
    t.stop();
  };
  auto c = t.connect(ep, {});
  ASSERT_TRUE(c);
  t.run(s);
  EXPECT_EQ(got, Error::connection_reset);
  std::vector<std::byte> b(10);
  EXPECT_EQ(t.recv(*c, b).error(), Error::connection_reset);
  t.close(*c);
  t.close(l);
}

TEST(EchoKernelTransport, ShortSendThenWritable) {
  KernelTransport t(quiet_loop());
  guard(t);
  ConnId l = no_conn, srv = no_conn, cli = no_conn;
  TcpSocketOptions small;
  small.snd_buf = 4096;
  small.rcv_buf = 4096;
  const Endpoint ep = listen_any(t, l, small);
  std::vector<std::byte> big(4 << 20, std::byte{7});
  std::size_t sent = 0, received = 0;
  bool refused = false;
  Script s;
  const auto pump = [&] {
    while (sent < big.size()) {
      auto r = t.send(cli, std::span(big).subspan(sent));
      if (!r) {
        EXPECT_EQ(r.error(), Error::would_block);
        refused = true;
        return;
      }
      sent += *r;
    }
    t.shutdown_write(cli);
  };
  s.accept = [&](ConnId, ConnId c) { srv = c; };
  s.connected = [&](ConnId) { pump(); };
  s.writable = [&](ConnId c) {
    EXPECT_EQ(c, cli);
    pump();
  };
  s.readable = [&](ConnId c) {
    if (c != srv) return;
    std::vector<std::byte> b(65536);
    while (true) {
      auto r = t.recv(c, b);
      if (!r) return;
      if (*r == 0) {
        t.stop();
        return;
      }
      received += *r;
    }
  };
  cli = *t.connect(ep, small);
  t.run(s);
  EXPECT_TRUE(refused);
  EXPECT_EQ(sent, big.size());
  EXPECT_EQ(received, big.size());
  EXPECT_GT(std::ranges::count(s.log, std::string("writable")), 0);
}

TEST(EchoKernelTransport, TimersFireInDeadlineOrderAndPeriodically) {
  KernelTransport t(quiet_loop());
  guard(t);
  std::vector<int> order;
  int ticks = 0;
  t.add_oneshot(std::chrono::milliseconds(30), [&] { order.push_back(30); });
  const TimerToken cancelled = t.add_oneshot(std::chrono::milliseconds(5), [&] { order.push_back(5); });
  t.add_oneshot(std::chrono::milliseconds(10), [&] { order.push_back(10); });
  t.add_oneshot(std::chrono::milliseconds(10), [&] { order.push_back(11); });  // same deadline: arm order
  t.cancel_timer(cancelled);
  TimerToken periodic = 0;
  periodic = t.add_timer(std::chrono::milliseconds(4), [&] {
    if (++ticks == 5) t.cancel_timer(periodic);
  });
  t.add_oneshot(std::chrono::milliseconds(40), [&] { t.stop(); });
  const Time t0 = t.now();
  Script s;
  t.run(s);
  EXPECT_EQ(order, (std::vector<int>{10, 11, 30}));
  EXPECT_EQ(ticks, 5);
  EXPECT_GE(t.now() - t0, std::chrono::milliseconds(40));
  ASSERT_NE(t.loop_stats(), nullptr);
  EXPECT_GE(t.loop_stats()->lateness.count, 4u);
}

TEST(EchoKernelTransport, UdpSendRecvAndTruncation) {
  KernelTransport t(quiet_loop());
  guard(t);
  const ConnId a = *t.udp_open(Endpoint{loopback, 0});
  const ConnId b = *t.udp_open(Endpoint{loopback, 0});
  const Endpoint eb = *t.local_endpoint(b);
  ASSERT_TRUE(t.send_to(a, eb, bytes("hello world")));
  Script s;
  std::vector<UdpRecv> got;
  s.readable = [&](ConnId id) {
    std::vector<std::byte> buf(5);
    while (auto r = t.recv_from(id, buf)) {
      got.push_back(*r);
    }
    t.stop();
  };
  t.run(s);
  ASSERT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0].len, 11u);
  EXPECT_TRUE(got[0].truncated);
  EXPECT_EQ(got[0].from, *t.local_endpoint(a));
  EXPECT_EQ(t.send_to(a, Endpoint{loopback, 0}, bytes("x")).error(), Error::invalid_argument);
  EXPECT_EQ(t.send(a, bytes("x")).error(), Error::bad_handle);  // a UDP id is not a connection
}

TEST(EchoKernelTransport, SocketOptionErrorsAreReported) {
  KernelTransport t(quiet_loop());
  TcpSocketOptions o;
  o.mss_clamp = 1;  // below the minimum TCP_MAXSEG accepts
  auto c = t.connect(Endpoint{loopback, 9}, o);
  ASSERT_FALSE(c);
  EXPECT_EQ(c.error(), Error::invalid_argument);
  EXPECT_NE(t.last_error_detail().find("TCP_MAXSEG"), std::string::npos) << t.last_error_detail();
}

TEST(EchoKernelServerClient, ManyConnectionsOverLoopback) {
  KernelTransport t(quiet_loop());
  guard(t, std::chrono::seconds(60));
  echo::EchoServer server(t, {.local = Endpoint{loopback, 0}});
  ASSERT_TRUE(server.start());
  // The server's listener is the transport's first id.
  const Endpoint ep = *t.local_endpoint(1);
  echo::EchoClient client(t, {.remote = ep, .size = 3000, .count = 20, .connections = 100,
                              .concurrency = 16});
  ASSERT_TRUE(client.start());
  struct Mux final : Handler {
    echo::EchoServer& s;
    echo::EchoClient& c;
    Mux(echo::EchoServer& sv, echo::EchoClient& cl) : s(sv), c(cl) {}
    Handler& pick(ConnId id) { return s.owns(id) ? static_cast<Handler&>(s) : c; }
    void on_accept(ConnId l, ConnId n) override { s.on_accept(l, n); }
    void on_connected(ConnId id) override { pick(id).on_connected(id); }
    void on_readable(ConnId id) override { pick(id).on_readable(id); }
    void on_writable(ConnId id) override { pick(id).on_writable(id); }
    void on_closed(ConnId id) override { pick(id).on_closed(id); }
    void on_error(ConnId id, Error e) override { pick(id).on_error(id, e); }
  } mux(server, client);
  t.run(mux);
  ASSERT_TRUE(client.done());
  EXPECT_TRUE(client.result().ok) << client.result().first_error;
  EXPECT_EQ(client.result().requests_ok, 2000u);
  EXPECT_EQ(client.result().bytes, 6'000'000u);
  EXPECT_EQ(server.stats().errors, 0u);
  server.close_all();
}

TEST(EchoKernelServerClient, UdpEchoOverLoopback) {
  KernelTransport t(quiet_loop());
  guard(t);
  echo::EchoServer server(t, {.local = Endpoint{loopback, 0}, .udp = true});
  ASSERT_TRUE(server.start());
  const Endpoint ep = *t.local_endpoint(1);
  const ConnId peer = *t.udp_open(Endpoint{loopback, 0});
  ASSERT_TRUE(t.send_to(peer, ep, bytes("over udp")));
  Script s;
  std::string got;
  s.readable = [&](ConnId id) {
    if (id != peer) {
      server.on_readable(id);
      return;
    }
    std::vector<std::byte> b(100);
    if (auto r = t.recv_from(peer, b)) {
      got.assign(reinterpret_cast<const char*>(b.data()), r->len);
      t.stop();
    }
  };
  t.run(s);
  EXPECT_EQ(got, "over udp");
  EXPECT_EQ(server.stats().datagrams, 1u);
}

}  // namespace
}  // namespace utcp::app
