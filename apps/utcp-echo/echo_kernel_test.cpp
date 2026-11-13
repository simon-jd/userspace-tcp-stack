// KernelTransport over loopback (Linux sockets, the backend's EventLoop), with
// utcp-echo's server and client on top. These tests live here because the
// KernelTransport sources (apps/common/kernel_transport.*) are tested from a
// program directory; they need only the loopback interface.
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
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

TEST(EchoKernelTransport, TcpInfoMapsEveryField) {
  // Distinct values in every field, so a swapped field or a wrong unit shows.
  tcp_info ti{};
  ti.tcpi_state = 1;  // TCP_ESTABLISHED
  ti.tcpi_ca_state = TCP_CA_Recovery;
  ti.tcpi_snd_wscale = 7;
  ti.tcpi_rcv_wscale = 9;
  ti.tcpi_rto = 1001;
  ti.tcpi_ato = 1002;
  ti.tcpi_rtt = 1003;
  ti.tcpi_rttvar = 1004;
  ti.tcpi_min_rtt = 1005;
  ti.tcpi_snd_cwnd = 1006;
  ti.tcpi_snd_ssthresh = 1007;
  ti.tcpi_snd_mss = 1008;
  ti.tcpi_rcv_mss = 1009;
  ti.tcpi_advmss = 1010;
  ti.tcpi_pmtu = 1011;
  ti.tcpi_bytes_sent = 1012;
  ti.tcpi_bytes_retrans = 1013;
  ti.tcpi_bytes_acked = 1014;
  ti.tcpi_bytes_received = 1015;
  ti.tcpi_segs_out = 1016;
  ti.tcpi_segs_in = 1017;
  ti.tcpi_data_segs_out = 1018;
  ti.tcpi_data_segs_in = 1019;
  ti.tcpi_pacing_rate = 1020;
  ti.tcpi_delivery_rate = 1021;
  ti.tcpi_delivered = 1022;
  ti.tcpi_delivery_rate_app_limited = 1;
  ti.tcpi_busy_time = 1023;
  ti.tcpi_rwnd_limited = 1024;
  ti.tcpi_sndbuf_limited = 1025;
  ti.tcpi_unacked = 1026;
  ti.tcpi_sacked = 1027;
  ti.tcpi_lost = 1028;
  ti.tcpi_retrans = 1029;
  ti.tcpi_total_retrans = 1030;
  ti.tcpi_dsack_dups = 1031;
  ti.tcpi_reordering = 1032;
  ti.tcpi_reord_seen = 1033;
  ti.tcpi_rcv_rtt = 1034;
  ti.tcpi_rcv_space = 1035;
  ti.tcpi_rcv_ssthresh = 1036;
  ti.tcpi_snd_wnd = 1037;
  ti.tcpi_rcv_wnd = 1038;
  ti.tcpi_notsent_bytes = 1039;
  ti.tcpi_last_data_sent = 1040;
  ti.tcpi_last_data_recv = 1041;
  ti.tcpi_last_ack_recv = 1042;
  using std::chrono::microseconds, std::chrono::milliseconds;
  const ConnSample s = sample_from_tcp_info(ti, "cubic");
  EXPECT_EQ(s.cc_name_view(), "cubic");
  EXPECT_EQ(s.state, TcpState::established);
  EXPECT_EQ(s.ca_state, CaState::recovery);
  EXPECT_EQ(s.snd_wscale, 7);
  EXPECT_EQ(s.rcv_wscale, 9);
  EXPECT_EQ(s.rto, microseconds(1001));
  EXPECT_EQ(s.ato, microseconds(1002));
  EXPECT_EQ(s.srtt, microseconds(1003));
  EXPECT_EQ(s.rttvar, microseconds(1004));
  EXPECT_EQ(s.min_rtt, microseconds(1005));
  EXPECT_EQ(s.cwnd, 1006u);
  EXPECT_EQ(s.ssthresh, 1007u);
  EXPECT_EQ(s.snd_mss, 1008u);
  EXPECT_EQ(s.rcv_mss, 1009u);
  EXPECT_EQ(s.adv_mss, 1010u);
  EXPECT_EQ(s.pmtu, 1011u);
  EXPECT_EQ(s.bytes_sent, 1012u);
  EXPECT_EQ(s.bytes_retrans, 1013u);
  EXPECT_EQ(s.bytes_acked, 1014u);
  EXPECT_EQ(s.bytes_received, 1015u);
  EXPECT_EQ(s.segs_out, 1016u);
  EXPECT_EQ(s.segs_in, 1017u);
  EXPECT_EQ(s.data_segs_out, 1018u);
  EXPECT_EQ(s.data_segs_in, 1019u);
  EXPECT_EQ(s.pacing_rate, 1020u);
  EXPECT_EQ(s.delivery_rate, 1021u);
  EXPECT_EQ(s.delivered, 1022u);
  EXPECT_TRUE(s.app_limited);
  EXPECT_EQ(s.busy_time, microseconds(1023));
  EXPECT_EQ(s.rwnd_limited, microseconds(1024));
  EXPECT_EQ(s.sndbuf_limited, microseconds(1025));
  EXPECT_EQ(s.unacked, 1026u);
  EXPECT_EQ(s.sacked, 1027u);
  EXPECT_EQ(s.lost, 1028u);
  EXPECT_EQ(s.retrans, 1029u);
  EXPECT_EQ(s.total_retrans, 1030u);
  EXPECT_EQ(s.dsack_dups, 1031u);
  EXPECT_EQ(s.reordering, 1032u);
  EXPECT_EQ(s.reord_seen, 1033u);
  EXPECT_EQ(s.rcv_rtt, microseconds(1034));
  EXPECT_EQ(s.rcv_space, 1035u);
  EXPECT_EQ(s.rcv_ssthresh, 1036u);
  EXPECT_EQ(s.snd_wnd, 1037u);
  EXPECT_EQ(s.rcv_wnd, 1038u);
  EXPECT_EQ(s.notsent_bytes, 1039u);
  EXPECT_EQ(s.last_data_sent, milliseconds(1040));
  EXPECT_EQ(s.last_data_recv, milliseconds(1041));
  EXPECT_EQ(s.last_ack_recv, milliseconds(1042));
  // Linux's "reno" is NewReno; TcpInfo names it "newreno" (stats.hpp).
  EXPECT_EQ(sample_from_tcp_info(ti, "reno").cc_name_view(), "newreno");
  EXPECT_EQ(sample_from_tcp_info(ti, "bbr").cc_name_view(), "bbr");
}

TEST(EchoKernelTransport, SampleOfALiveConnectionNamesNewReno) {
  KernelTransport t(quiet_loop());
  guard(t);
  ConnId l = no_conn, srv = no_conn;
  TcpSocketOptions o;
  o.cc = CcAlgo::newreno;
  const Endpoint ep = listen_any(t, l, o);
  Script s;
  s.accept = [&](ConnId, ConnId c) {
    srv = c;
    t.stop();
  };
  const ConnId cli = *t.connect(ep, o);
  t.run(s);
  ASSERT_NE(srv, no_conn);
  const ConnSample cs = t.sample(cli);
  EXPECT_EQ(cs.cc_name_view(), "newreno");
  EXPECT_EQ(cs.state, TcpState::established);
  EXPECT_GT(cs.snd_mss, 0u);
  EXPECT_GT(cs.cwnd, 0u);
  EXPECT_GE(cs.rto, std::chrono::milliseconds(200));  // TCP_RTO_MIN
  EXPECT_EQ(t.sample(srv).cc_name_view(), "newreno");  // inherited from the listener
  t.close(cli);
  t.close(srv);
  t.close(l);
}

TEST(EchoKernelTransport, ShutdownWriteDuringConnectSendsFinAfterIt) {
  KernelTransport t(quiet_loop());
  guard(t);
  ConnId l = no_conn, srv = no_conn;
  const Endpoint ep = listen_any(t, l);
  bool srv_eof = false;
  Script s;
  s.accept = [&](ConnId, ConnId c) { srv = c; };
  s.readable = [&](ConnId c) {
    if (c != srv) return;
    std::vector<std::byte> b(16);
    while (auto r = t.recv(c, b)) {
      if (*r == 0) {
        srv_eof = true;
        t.stop();
        return;
      }
    }
  };
  const ConnId cli = *t.connect(ep, {});
  t.shutdown_write(cli);  // the connect is (usually) still in progress
  EXPECT_EQ(t.send(cli, bytes("x")).error(), Error::shut_down);
  t.run(s);
  EXPECT_TRUE(srv_eof);  // the FIN went out once the connect completed
  EXPECT_EQ(std::ranges::count(s.log, std::string("connected")), 1);
  t.close(cli);
  t.close(srv);
  t.close(l);
}

// Connects `n` blocking client sockets to `ep` (they complete in the
// listener's accept queue) and returns their fds.
std::vector<int> queue_connections(Endpoint ep, int n) {
  std::vector<int> fds;
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(ep.port);
  sa.sin_addr.s_addr = htonl(ep.addr.v);
  for (int i = 0; i < n; ++i) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    EXPECT_GE(fd, 0);
    EXPECT_EQ(::connect(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof sa), 0);
    fds.push_back(fd);
  }
  return fds;
}

TEST(EchoKernelTransport, AcceptRetriesAfterRunningOutOfDescriptors) {
  KernelTransport t(quiet_loop());
  guard(t);
  ConnId l = no_conn;
  const Endpoint ep = listen_any(t, l);
  const std::vector<int> clients = queue_connections(ep, 5);
  // Use up the descriptors: lower the soft limit to just above the highest
  // open fd, then fill every free number below it.
  rlimit old{};
  ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &old), 0);
  int max_fd = 0;
  if (DIR* d = ::opendir("/proc/self/fd")) {
    while (const dirent* e = ::readdir(d)) {
      max_fd = std::max(max_fd, std::atoi(e->d_name));
    }
    ::closedir(d);
  }
  rlimit low = old;
  low.rlim_cur = static_cast<rlim_t>(max_fd + 1);
  ASSERT_EQ(::setrlimit(RLIMIT_NOFILE, &low), 0);
  std::vector<int> fillers;
  for (int fd; (fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC)) >= 0;) {
    fillers.push_back(fd);
  }
  int accepted = 0;
  Script s;
  s.accept = [&](ConnId, ConnId) { ++accepted; };
  // The listener's edge arrives now: accept4 fails with EMFILE.
  t.add_oneshot(std::chrono::milliseconds(50), [&] { t.stop(); });
  t.run(s);
  EXPECT_EQ(accepted, 0);
  // Free the descriptors. No new connection arrives, so no new edge: only the
  // retry timer can accept the five queued connections.
  for (const int fd : fillers) ::close(fd);
  ASSERT_EQ(::setrlimit(RLIMIT_NOFILE, &old), 0);
  s.accept = [&](ConnId, ConnId) {
    if (++accepted == 5) t.stop();
  };
  t.run(s);
  EXPECT_EQ(accepted, 5);
  for (const int fd : clients) ::close(fd);
}

TEST(EchoKernelTransport, AcceptResumesAfterAStopWithConnectionsQueued) {
  KernelTransport t(quiet_loop());
  guard(t);
  ConnId l = no_conn;
  const Endpoint ep = listen_any(t, l);
  const std::vector<int> clients = queue_connections(ep, 3);
  int accepted = 0;
  Script s;
  s.accept = [&](ConnId, ConnId) {
    ++accepted;
    t.stop();  // one at a time
  };
  for (int i = 0; i < 3; ++i) {
    t.run(s);  // the guard ends a run that hangs
    ASSERT_EQ(accepted, i + 1);
  }
  for (const int fd : clients) ::close(fd);
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
