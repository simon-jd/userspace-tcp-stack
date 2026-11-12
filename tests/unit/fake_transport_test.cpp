#include "common/fake_transport.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace utcp::app {
namespace {

using namespace std::chrono_literals;

std::span<const std::byte> bytes(std::string_view s) { return std::as_bytes(std::span(s)); }

std::string to_str(std::span<const std::byte> b) {
  return {reinterpret_cast<const char*>(b.data()), b.size()};
}

const Ipv4Addr host = Ipv4Addr::from_octets(10, 0, 0, 1);

// Records every event as "<ms> <event> <names...>" and runs per-event hooks.
class Recorder : public Handler {
public:
  explicit Recorder(FakeTransport& t) : t_(t) {}

  void on_accept(ConnId listener, ConnId conn) override {
    if (!names.contains(conn)) {
      names[conn] = "S" + std::to_string(++accepted_);
    }
    log("accept " + name(listener) + " " + name(conn));
    if (accept_hook) accept_hook(conn);
  }
  void on_connected(ConnId conn) override {
    log("connected " + name(conn));
    if (connected_hook) connected_hook(conn);
  }
  void on_readable(ConnId id) override {
    log("readable " + name(id));
    if (readable_hook) readable_hook(id);
  }
  void on_writable(ConnId id) override {
    log("writable " + name(id));
    if (writable_hook) writable_hook(id);
  }
  void on_closed(ConnId id) override { log("closed " + name(id)); }
  void on_error(ConnId id, Error e) override {
    log("error " + name(id) + " " + std::string(to_string(e)));
  }

  void log(const std::string& s) {
    events.push_back(std::to_string(t_.now().ns / 1'000'000) + " " + s);
  }
  std::string name(ConnId id) const {
    const auto it = names.find(id);
    return it == names.end() ? "#" + std::to_string(id) : it->second;
  }

  std::map<ConnId, std::string> names;
  std::vector<std::string> events;
  std::function<void(ConnId)> accept_hook, connected_hook, readable_hook, writable_hook;

private:
  FakeTransport& t_;
  int accepted_ = 0;
};

// Reads everything available from a connection: the data, then "<eof>" or
// "<error>" if the stream ended.
std::string drain(Transport& t, ConnId id) {
  std::string out;
  std::array<std::byte, 64> buf{};
  for (;;) {
    const auto r = t.recv(id, buf);
    if (!r) {
      if (r.error() != Error::would_block) {
        out += "<" + std::string(to_string(r.error())) + ">";
      }
      return out;
    }
    if (*r == 0) {
      return out + "<eof>";
    }
    out += to_str(std::span(buf).first(*r));
  }
}

// Acceptance test 13: listen, accept, connect, send, recv, close, UDP send
// and receive, and timers, with the event order checked.
TEST(FakeTransport, ScriptedProgramGetsItsEventsInOrder) {
  FakeTransport t;
  Recorder r(t);
  const ConnId l = t.listen({Ipv4Addr{}, 7000}, 16, {}).value();
  const ConnId u1 = t.udp_open({Ipv4Addr{}, 9000}).value();
  const ConnId u2 = t.udp_open({Ipv4Addr{}, 0}).value();  // ephemeral: 49152
  const ConnId c = t.connect({host, 7000}, {}).value();
  r.names = {{l, "L"}, {u1, "U1"}, {u2, "U2"}, {c, "C"}};

  r.connected_hook = [&](ConnId id) { EXPECT_EQ(t.send(id, bytes("hello")).value(), 5u); };
  r.readable_hook = [&](ConnId id) {
    if (id == u1 || id == u2) {
      std::array<std::byte, 16> buf{};
      const UdpRecv d = t.recv_from(id, buf).value();
      r.log("  " + to_str(std::span(buf).first(d.len)) + " from " + to_string(d.from));
      if (id == u1) {
        ASSERT_TRUE(t.send_to(u1, d.from, bytes("pong")));
      }
      return;
    }
    const std::string got = drain(t, id);
    r.log("  " + got);
    if (r.name(id) == "S1" && got == "hello") {
      EXPECT_EQ(t.send(id, bytes("HELLO")).value(), 5u);
    } else if (id == c && got == "HELLO") {
      t.shutdown_write(c);
    } else if (r.name(id) == "S1" && got == "<eof>") {
      t.close(id);  // no unread data: the client sees FIN
    }
  };
  // Every 4 ms, three times.
  int ticks = 0;
  TimerToken tick = 0;
  tick = t.add_timer(4ms, [&] {
    r.log("tick " + std::to_string(++ticks));
    if (ticks == 3) {
      t.cancel_timer(tick);
    }
  });
  t.add_oneshot(10ms, [&] {
    r.log("oneshot");
    ASSERT_TRUE(t.send_to(u2, {host, 9000}, bytes("ping")));
  });

  t.run(r);

  const std::vector<std::string> want = {
      "0 connected C",
      "0 accept L S1",
      "0 readable S1",
      "0   hello",
      "0 readable C",
      "0   HELLO",
      "0 readable S1",
      "0   <eof>",
      "0 readable C",
      "0   <eof>",
      "0 closed C",
      "4 tick 1",
      "8 tick 2",
      "10 oneshot",
      "10 readable U1",
      "10   ping from 10.0.0.1:49152",
      "10 readable U2",
      "10   pong from 10.0.0.1:9000",
      "12 tick 3",
  };
  EXPECT_EQ(r.events, want);
  EXPECT_EQ(t.now(), Time{12'000'000});
  EXPECT_EQ(t.events_queued(), 0u);

  // The client id stays valid until close(); the server end is gone.
  EXPECT_TRUE(t.is_open(c));
  EXPECT_EQ(t.sample(c).state, TcpState::closed);
  EXPECT_EQ(t.sample(c).bytes_sent, 5u);
  EXPECT_EQ(t.sample(c).bytes_received, 5u);
  t.close(c);
  EXPECT_EQ(t.open_count(), 3u);  // L, U1, U2
}

TEST(FakeTransport, ConnectWithoutListenerIsRefused) {
  FakeTransport t;
  Recorder r(t);
  const ConnId c = t.connect({host, 80}, {}).value();
  r.names = {{c, "C"}};
  t.run(r);
  EXPECT_EQ(r.events, std::vector<std::string>{"0 error C connection_refused"});
  std::array<std::byte, 4> buf{};
  EXPECT_EQ(t.recv(c, buf).error(), Error::connection_refused);
  EXPECT_EQ(t.send(c, bytes("x")).error(), Error::connection_refused);
}

TEST(FakeTransport, ListenerMatchesPortAndBoundAddress) {
  FakeTransport t;
  ASSERT_TRUE(t.listen({Ipv4Addr::from_octets(10, 0, 0, 2), 80}, 1, {}));
  EXPECT_EQ(t.listen({Ipv4Addr{}, 80}, 1, {}).error(), Error::addr_in_use);
  Recorder r(t);
  const ConnId to_other = t.connect({host, 80}, {}).value();
  const ConnId to_bound = t.connect({Ipv4Addr::from_octets(10, 0, 0, 2), 80}, {}).value();
  r.names = {{to_other, "A"}, {to_bound, "B"}};
  t.run(r);
  EXPECT_EQ(r.events, (std::vector<std::string>{"0 error A connection_refused", "0 connected B",
                                                "0 accept #1 S1"}));
}

TEST(FakeTransport, FullBufferGivesShortWritesThenWritable) {
  FakeTransport t({.rcv_buf = 1000});
  Recorder r(t);
  const ConnId l = t.listen({Ipv4Addr{}, 1}, 1, {}).value();
  const ConnId c = t.connect({host, 1}, {}).value();
  ConnId s = no_conn;
  r.accept_hook = [&](ConnId id) { s = id; };
  t.run(r);
  ASSERT_NE(s, no_conn);
  static_cast<void>(l);

  const std::vector<std::byte> big(1500, std::byte{7});
  EXPECT_EQ(t.send(c, big).value(), 1000u);
  EXPECT_EQ(t.send(c, big).error(), Error::would_block);
  EXPECT_EQ(t.sample(c).snd_wnd, 0u);

  std::vector<std::byte> buf(400);
  EXPECT_EQ(t.recv(s, buf).value(), 400u);  // 400 free: below half, no event yet
  buf.resize(100);
  EXPECT_EQ(t.recv(s, buf).value(), 100u);  // 500 free: writable
  r.events.clear();
  r.names = {{c, "C"}, {s, "S"}};
  t.run(r);
  EXPECT_EQ(r.events, (std::vector<std::string>{"0 readable S", "0 writable C"}));
  EXPECT_EQ(t.send(c, big).value(), 500u);
  EXPECT_EQ(t.sample(s).rcv_wnd, 0u);
  EXPECT_EQ(t.sample(s).bytes_received, 1500u);
}

TEST(FakeTransport, CloseWithUnreadDataResetsThePeer) {
  FakeTransport t;
  Recorder r(t);
  ASSERT_TRUE(t.listen({Ipv4Addr{}, 1}, 1, {}));
  const ConnId c = t.connect({host, 1}, {}).value();
  ConnId s = no_conn;
  r.accept_hook = [&](ConnId id) { s = id; };
  t.run(r);
  ASSERT_EQ(t.send(c, bytes("unread")).value(), 6u);
  t.close(s);
  r.events.clear();
  r.names = {{c, "C"}};
  t.run(r);
  // The readable event of the closed server end is skipped.
  EXPECT_EQ(r.events, std::vector<std::string>{"0 error C connection_reset"});
  EXPECT_EQ(t.send(c, bytes("x")).error(), Error::connection_reset);
  EXPECT_EQ(drain(t, c), "<connection_reset>");
  EXPECT_FALSE(t.is_open(s));
  EXPECT_EQ(t.send(s, bytes("x")).error(), Error::bad_handle);
}

TEST(FakeTransport, HalfCloseKeepsTheOtherDirectionOpen) {
  FakeTransport t;
  Recorder r(t);
  ASSERT_TRUE(t.listen({Ipv4Addr{}, 1}, 1, {}));
  const ConnId c = t.connect({host, 1}, {}).value();
  ConnId s = no_conn;
  r.accept_hook = [&](ConnId id) { s = id; };
  t.run(r);
  r.names = {{c, "C"}, {s, "S"}};
  r.events.clear();

  t.shutdown_write(c);
  EXPECT_EQ(t.send(c, bytes("x")).error(), Error::shut_down);
  EXPECT_EQ(t.sample(c).state, TcpState::fin_wait_2);
  EXPECT_EQ(t.sample(s).state, TcpState::close_wait);
  EXPECT_EQ(drain(t, s), "<eof>");
  ASSERT_EQ(t.send(s, bytes("late")).value(), 4u);
  t.shutdown_write(s);
  t.run(r);
  // C's FIN exchange completes first: S's shutdown_write delivers its FIN to C
  // before marking S itself.
  EXPECT_EQ(r.events, (std::vector<std::string>{"0 readable S", "0 readable C", "0 closed C",
                                                "0 closed S"}));
  EXPECT_EQ(drain(t, c), "late<eof>");
}

TEST(FakeTransport, ClosingTheListenerResetsUnacceptedConnections) {
  FakeTransport t;
  Recorder r(t);
  const ConnId l = t.listen({Ipv4Addr{}, 1}, 1, {}).value();
  const ConnId c = t.connect({host, 1}, {}).value();
  r.names = {{c, "C"}};
  t.close(l);
  t.run(r);
  EXPECT_EQ(r.events, (std::vector<std::string>{"0 connected C", "0 error C connection_reset"}));
  EXPECT_EQ(t.open_count(), 1u);
}

TEST(FakeTransport, InjectedErrorComesAfterBufferedData) {
  FakeTransport t;
  Recorder r(t);
  ASSERT_TRUE(t.listen({Ipv4Addr{}, 1}, 1, {}));
  const ConnId c = t.connect({host, 1}, {}).value();
  ConnId s = no_conn;
  r.accept_hook = [&](ConnId id) { s = id; };
  t.run(r);
  ASSERT_EQ(t.send(s, bytes("data")).value(), 4u);
  t.inject_error(c, Error::timed_out);
  r.names = {{c, "C"}};
  r.events.clear();
  t.run(r);
  EXPECT_EQ(r.events, (std::vector<std::string>{"0 readable C", "0 error C timed_out"}));
  EXPECT_EQ(drain(t, c), "data<timed_out>");
  EXPECT_EQ(t.send(c, bytes("x")).error(), Error::timed_out);
}

TEST(FakeTransport, UdpLimitsAndDrops) {
  FakeTransport t;
  const ConnId u = t.udp_open({Ipv4Addr{}, 53}).value();
  EXPECT_EQ(t.udp_open({Ipv4Addr{}, 53}).error(), Error::addr_in_use);
  const std::vector<std::byte> max(65507), over(65508);
  EXPECT_TRUE(t.send_to(u, {host, 53}, max));
  EXPECT_EQ(t.send_to(u, {host, 53}, over).error(), Error::message_too_big);
  EXPECT_TRUE(t.send_to(u, {host, 54}, max));  // no socket on 54
  EXPECT_EQ(t.udp_dropped(), 1u);

  std::array<std::byte, 10> small{};
  const UdpRecv d = t.recv_from(u, small).value();
  EXPECT_EQ(d.len, 65507u);
  EXPECT_TRUE(d.truncated);
  EXPECT_EQ(d.from, (Endpoint{host, 53}));
  EXPECT_EQ(t.recv_from(u, small).error(), Error::would_block);
  EXPECT_EQ(t.recv(u, small).error(), Error::bad_handle);  // not a TCP id
}

TEST(FakeTransport, TimersFireByDeadlineThenCreation) {
  FakeTransport t({.start = Time{1'000'000'000}});
  Recorder r(t);
  std::vector<int> order;
  t.add_oneshot(2ms, [&] { order.push_back(1); });
  t.add_oneshot(1ms, [&] { order.push_back(2); });
  t.add_oneshot(2ms, [&] { order.push_back(3); });
  const TimerToken gone = t.add_oneshot(1ms, [&] { order.push_back(4); });
  t.cancel_timer(gone);
  t.add_oneshot(0ms, [&] {
    order.push_back(5);
    t.add_oneshot(1ms, [&] { order.push_back(6); });  // same deadline as 2, created later
  });
  t.run(r);
  EXPECT_EQ(order, (std::vector<int>{5, 2, 6, 1, 3}));
  EXPECT_EQ(t.now(), Time{1'002'000'000});
}

TEST(FakeTransport, StopEndsRunAndRunResumes) {
  FakeTransport t;
  Recorder r(t);
  int ticks = 0;
  t.add_timer(1s, [&] {
    if (++ticks % 2 == 0) {
      t.stop();
    }
  });
  t.run(r);
  EXPECT_EQ(ticks, 2);
  t.run(r);
  EXPECT_EQ(ticks, 4);
  EXPECT_EQ(t.now(), Time{4'000'000'000});
}

TEST(FakeTransport, CallbacksMayCloseTheirOwnId) {
  FakeTransport t;
  Recorder r(t);
  ASSERT_TRUE(t.listen({Ipv4Addr{}, 1}, 1, {}));
  const ConnId c = t.connect({host, 1}, {}).value();
  r.connected_hook = [&](ConnId id) {
    ASSERT_TRUE(t.send(id, bytes("bye")));
    t.close(id);
  };
  std::string got;
  r.readable_hook = [&](ConnId id) { got += drain(t, id); };
  t.run(r);
  EXPECT_FALSE(t.is_open(c));
  EXPECT_EQ(got, "bye<eof>");
}

TEST(FakeTransport, BadHandles) {
  FakeTransport t;
  std::array<std::byte, 4> buf{};
  EXPECT_EQ(t.send(42, bytes("x")).error(), Error::bad_handle);
  EXPECT_EQ(t.recv(42, buf).error(), Error::bad_handle);
  EXPECT_EQ(t.send_to(42, {host, 1}, bytes("x")).error(), Error::bad_handle);
  EXPECT_EQ(t.recv_from(42, buf).error(), Error::bad_handle);
  EXPECT_EQ(t.sample(42), ConnSample{});
  t.close(42);
  t.shutdown_write(42);
  const ConnId l = t.listen({Ipv4Addr{}, 1}, 1, {}).value();
  EXPECT_EQ(t.send(l, bytes("x")).error(), Error::bad_handle);
}

TEST(FakeTransport, HasNoEventLoop) {
  FakeTransport t;
  EXPECT_EQ(t.loop_stats(), nullptr);
}

}  // namespace
}  // namespace utcp::app
