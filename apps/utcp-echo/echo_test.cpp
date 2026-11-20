// utcp-echo's logic against the fake Transport (DESIGN §9).
#include "utcp-echo/echo.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <expected>
#include <functional>
#include <iterator>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "common/fake_transport.hpp"

namespace utcp::app::echo {
namespace {

// Routes events to the server or the client by id ownership.
class Mux final : public Handler {
public:
  Mux(Handler& server, Handler& client, std::function<bool(ConnId)> server_owns)
      : s_(server), c_(client), owns_(std::move(server_owns)) {}
  void on_accept(ConnId l, ConnId c) override { s_.on_accept(l, c); }
  void on_connected(ConnId c) override { pick(c).on_connected(c); }
  void on_readable(ConnId c) override { pick(c).on_readable(c); }
  void on_writable(ConnId c) override { pick(c).on_writable(c); }
  void on_closed(ConnId c) override { pick(c).on_closed(c); }
  void on_error(ConnId c, Error e) override { pick(c).on_error(c, e); }

private:
  Handler& pick(ConnId c) { return owns_(c) ? s_ : c_; }
  Handler& s_;
  Handler& c_;
  std::function<bool(ConnId)> owns_;
};

constexpr Endpoint server_ep{Ipv4Addr{}, 7};
constexpr Endpoint client_target{Ipv4Addr{0x0a000001}, 7};

TEST(EchoTcp, ManyConnectionsAllRequestsVerified) {
  FakeTransport t({.rcv_buf = 700});  // smaller than a request: short sends both ways
  EchoServer server(t, {.local = server_ep, .max_pending = 1500});
  ASSERT_TRUE(server.start());
  EchoClient client(t, {.remote = client_target, .size = 1000, .count = 10, .connections = 30,
                        .concurrency = 7});
  ASSERT_TRUE(client.start());
  Mux mux(server, client, [&](ConnId id) { return server.owns(id); });
  t.run(mux);
  ASSERT_TRUE(client.done());
  t.run(mux);  // the server's side of the last closes
  const ClientResult& r = client.result();
  EXPECT_TRUE(r.ok) << r.first_error;
  EXPECT_EQ(r.requests_ok, 300u);
  EXPECT_EQ(r.connections_done, 30u);
  EXPECT_EQ(r.bytes, 300'000u);
  EXPECT_EQ(r.latency.count(), 300u);
  EXPECT_EQ(server.stats().accepted, 30u);
  EXPECT_EQ(server.stats().bytes, 300'000u);
  // The server closed every connection after the client's FIN.
  EXPECT_EQ(server.open_connections(), 0u);
  EXPECT_EQ(server.stats().errors, 0u);
  const std::string s = client.summary().str();
  for (const char* key : {"\"ok\":true", "\"latency_p50_ns\":", "\"latency_p99_ns\":", "\"latency_p999_ns\":",
                          "\"requests_ok\":300"}) {
    EXPECT_NE(s.find(key), std::string::npos) << key;
  }
}

TEST(EchoTcp, RequestBytesDifferPerConnectionAndRequest) {
  int same = 0;
  for (std::size_t off = 0; off < 64; ++off) {
    same += request_byte(1, 0, 0, off) == request_byte(1, 1, 0, off);
    same += request_byte(1, 0, 0, off) == request_byte(1, 0, 1, off);
  }
  EXPECT_LT(same, 8);
}

// Echoes everything back with the first byte of every read changed.
class CorruptingServer final : public Handler {
public:
  explicit CorruptingServer(Transport& t) : t_(t) {}
  void start() { l_ = *t_.listen(server_ep, 16, {}); }
  bool owns(ConnId id) const { return id == l_ || conns_.contains(id); }
  void on_accept(ConnId, ConnId c) override { conns_.insert(c); }
  void on_readable(ConnId id) override {
    std::vector<std::byte> b(4096);
    while (true) {
      auto r = t_.recv(id, b);
      if (!r || *r == 0) return;
      b[0] ^= std::byte{1};
      (void)t_.send(id, std::span(b).first(*r));
    }
  }

private:
  Transport& t_;
  ConnId l_ = no_conn;
  std::set<ConnId> conns_;
};

TEST(EchoTcp, CorruptedEchoIsDetected) {
  FakeTransport t;
  CorruptingServer bad(t);
  bad.start();
  EchoClient client(t, {.remote = client_target, .size = 100, .count = 5, .connections = 3});
  ASSERT_TRUE(client.start());
  Mux mux(bad, client, [&](ConnId id) { return bad.owns(id); });
  t.run(mux);
  ASSERT_TRUE(client.done());
  EXPECT_FALSE(client.result().ok);
  EXPECT_EQ(client.result().mismatches, 3u);
  EXPECT_EQ(client.result().requests_ok, 0u);
}

TEST(EchoTcp, RateLimitSpacesRequestStarts) {
  FakeTransport t;
  EchoServer server(t, {.local = server_ep});
  ASSERT_TRUE(server.start());
  // 40 requests at 100 per second: the first starts at once, the last no
  // earlier than 390 ms of virtual time.
  EchoClient client(t, {.remote = client_target, .size = 10, .count = 10, .connections = 4,
                        .concurrency = 2, .rate = 100});
  const Time t0 = t.now();
  ASSERT_TRUE(client.start());
  Mux mux(server, client, [&](ConnId id) { return server.owns(id); });
  t.run(mux);
  ASSERT_TRUE(client.done());
  EXPECT_TRUE(client.result().ok) << client.result().first_error;
  EXPECT_EQ(client.result().requests_ok, 40u);
  EXPECT_GE(t.now() - t0, std::chrono::milliseconds(390));
  EXPECT_LE(t.now() - t0, std::chrono::milliseconds(420));
}

TEST(EchoTcp, FailedFirstSendDuringLoadActivationAbortsAllConnections) {
  FakeTransport t;
  EchoServer server(t, {.local = server_ep});
  ASSERT_TRUE(server.start());
  EchoClient client(t, {.remote = client_target, .connections = 2, .concurrency = 2,
                        .rate = 100, .open_batch = 2});
  ASSERT_TRUE(client.start());
  client.advance_load();
  Mux mux(server, client, [&](ConnId id) { return server.owns(id); });
  t.add_oneshot(std::chrono::milliseconds(3), [&] { t.stop(); });
  t.run(mux);
  ASSERT_EQ(client.load_phase(), LoadPhase::idle);
  ASSERT_EQ(server.open_connections(), 2u);

  // The first client is id 2, following the listener. Record its failure
  // before the callback is delivered, so the first send sees it synchronously.
  t.inject_error(2, Error::connection_reset);
  client.advance_load();
  EXPECT_TRUE(client.done());
  EXPECT_FALSE(client.result().ok);
  EXPECT_EQ(client.result().requests_ok, 0u);
  EXPECT_EQ(client.result().errors, 2u);
  EXPECT_FALSE(client.owns(2));
  EXPECT_EQ(t.open_count(), 3u);  // listener and the two server-side handles
}

TEST(EchoTcp, RefusedConnectionsAreErrors) {
  FakeTransport t;
  EchoClient client(t, {.remote = client_target, .connections = 3});
  ASSERT_TRUE(client.start());
  t.run(client);
  ASSERT_TRUE(client.done());
  EXPECT_FALSE(client.result().ok);
  EXPECT_EQ(client.result().errors, 3u);
  EXPECT_NE(client.result().first_error.find("connection_refused"), std::string::npos);
}

TEST(EchoTcp, ServerFinishesEchoingAfterTheClientsFin) {
  // A client that sends 10 kB, half-closes at once and reads the echo.
  FakeTransport t({.rcv_buf = 1000});
  EchoServer server(t, {.local = server_ep, .max_pending = 2000});
  ASSERT_TRUE(server.start());
  struct Client final : Handler {
    Transport& t;
    ConnId c = no_conn;
    std::size_t sent = 0, got = 0;
    bool eof = false;
    explicit Client(Transport& tr) : t(tr) {}
    void pump() {
      std::vector<std::byte> b(10'000 - sent, std::byte{'z'});
      while (sent < 10'000) {
        auto r = t.send(c, std::span(b).first(10'000 - sent));
        if (!r) return;
        sent += *r;
      }
      t.shutdown_write(c);
    }
    void on_connected(ConnId) override { pump(); }
    void on_writable(ConnId) override { pump(); }
    void on_readable(ConnId) override {
      std::vector<std::byte> b(512);
      while (true) {
        auto r = t.recv(c, b);
        if (!r) return;
        if (*r == 0) {
          eof = true;
          t.stop();
          return;
        }
        got += *r;
      }
    }
  } client(t);
  client.c = *t.connect(client_target, {});
  Mux mux(server, client, [&](ConnId id) { return server.owns(id); });
  t.run(mux);
  EXPECT_TRUE(client.eof);
  EXPECT_EQ(client.got, 10'000u);
  EXPECT_EQ(server.open_connections(), 0u);
}

TEST(EchoUdp, DatagramsAreSentBack) {
  FakeTransport t;
  EchoServer server(t, {.local = Endpoint{Ipv4Addr{}, 7001}, .udp = true});
  ASSERT_TRUE(server.start());
  const ConnId peer = *t.udp_open(Endpoint{Ipv4Addr{}, 40000});
  const std::string msgs[] = {"hello", "", std::string(1400, 'u')};
  for (const std::string& m : msgs) {
    ASSERT_TRUE(t.send_to(peer, Endpoint{Ipv4Addr{0x0a000001}, 7001}, std::as_bytes(std::span(m))));
  }
  struct Peer final : Handler {
    Transport& t;
    Handler& server;
    ConnId peer;
    std::vector<std::string> got;
    Peer(Transport& tr, Handler& s, ConnId p) : t(tr), server(s), peer(p) {}
    void on_readable(ConnId id) override {
      if (id != peer) {
        server.on_readable(id);
        return;
      }
      std::vector<std::byte> b(2000);
      while (auto r = t.recv_from(peer, b)) {
        got.emplace_back(reinterpret_cast<const char*>(b.data()), r->len);
        EXPECT_EQ(r->from.port, 7001);
      }
    }
  } p(t, server, peer);
  t.run(p);
  ASSERT_EQ(p.got.size(), 3u);
  EXPECT_EQ(p.got[0], msgs[0]);
  EXPECT_EQ(p.got[1], msgs[1]);
  EXPECT_EQ(p.got[2], msgs[2]);
  EXPECT_EQ(server.stats().datagrams, 3u);
}

}  // namespace

// main_ calls finish_closing(finish_closing_max) once, after run() returned
// (interop case E-chunked: without the call the server's FIN that follows
// the program's close is never ACKed). Nothing listens on the fake, so the
// connection is refused and the program fails, but the exit path is the same.
TEST(EchoMain, MainFinishesClosingAfterRun) {
  std::vector<std::pair<Duration, std::uint64_t>> calls;
  const TransportFactory make = [&](const BackendSelection&)
      -> std::expected<std::unique_ptr<Transport>, std::string> {
    FakeTransportOptions o;
    o.on_finish_closing = [&](Duration max, std::uint64_t runs_returned) {
      calls.emplace_back(max, runs_returned);
    };
    return std::make_unique<FakeTransport>(o);
  };
  const char* const argv[] = {"utcp-echo", "--connect", "10.0.0.1:7", "--count", "1"};
  EXPECT_EQ(main_(static_cast<int>(std::size(argv)), argv, make), 1);
  ASSERT_EQ(calls.size(), 1u);
  EXPECT_EQ(calls[0].first, finish_closing_max);
  EXPECT_EQ(calls[0].second, 1u);
}

}  // namespace utcp::app::echo
