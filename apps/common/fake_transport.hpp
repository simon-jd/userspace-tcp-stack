// An in-memory Transport for tests of application logic (DESIGN §9).
//
// One fake host: every connect() and send_to() reaches the listeners and UDP
// sockets of the same FakeTransport, whatever the destination address (only
// the port is matched, and a bound address other than 0 must equal it). Data
// moves at once into the peer's receive buffer of FakeTransportOptions::
// rcv_buf bytes, so a full buffer gives short sends, would_block and later
// on_writable. Time is virtual: it moves only when run() fires a timer.
//
// Events are queued in the order the calls produce them and delivered in that
// order by run(); readable and writable are coalesced per id until delivered.
// A connect() queues on_connected for the client, then on_accept for the
// listener (the order in which a real handshake completes the two ends); a
// refused connect queues on_error(connection_refused). close() with unread
// data resets the peer (on_error(connection_reset)), otherwise the peer reads
// the end of stream; on_closed follows once both ends have sent FIN. Sending
// to a peer that has closed fails with connection_reset.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "common/transport.hpp"

namespace utcp::app {

struct FakeTransportOptions {
  Ipv4Addr local_addr = Ipv4Addr::from_octets(10, 0, 0, 1);  // source of connections and datagrams
  std::uint32_t rcv_buf = 64 * 1024;          // receive buffer per connection, bytes
  Time start{};                               // initial virtual time
  std::uint16_t first_ephemeral_port = 49152;  // then counting up
};

class FakeTransport final : public Transport {
public:
  explicit FakeTransport(const FakeTransportOptions& options = {});

  std::expected<ConnId, Error> connect(Endpoint remote, const TcpSocketOptions& opts) override;
  std::expected<ConnId, Error> listen(Endpoint local, std::uint32_t backlog,
                                      const TcpSocketOptions& opts) override;
  std::expected<std::size_t, Error> send(ConnId id, std::span<const std::byte> data) override;
  std::expected<std::size_t, Error> recv(ConnId id, std::span<std::byte> out) override;
  void shutdown_write(ConnId id) override;
  void close(ConnId id) override;
  ConnSample sample(ConnId id) override;

  std::expected<ConnId, Error> udp_open(Endpoint local) override;
  std::expected<void, Error> send_to(ConnId id, Endpoint remote,
                                     std::span<const std::byte> data) override;
  std::expected<UdpRecv, Error> recv_from(ConnId id, std::span<std::byte> out) override;

  TimerToken add_timer(Duration period, std::function<void()> cb) override;
  TimerToken add_oneshot(Duration delay, std::function<void()> cb) override;
  void cancel_timer(TimerToken t) override;

  // Delivers queued events, then fires timers in deadline order (ties in
  // creation order), moving the clock to each deadline, until stop() is
  // called or nothing is left (no event queued, no timer). stop() takes
  // effect after the current callback; run() can then be called again (it
  // clears the stop request on entry). Events go first: a timer fires only
  // when no event is queued.
  void run(Handler& h) override;
  void stop() override { stopped_ = true; }
  [[nodiscard]] Time now() const override { return now_; }

  // --- Test hooks.
  // The connection fails with `e`: on_error(id, e) is queued and later send()
  // and recv() (after buffered data) return e.
  void inject_error(ConnId id, Error e);
  [[nodiscard]] bool is_open(ConnId id) const { return socks_.contains(id); }
  [[nodiscard]] std::size_t open_count() const { return socks_.size(); }
  // Datagrams sent to a port without a UDP socket.
  [[nodiscard]] std::uint64_t udp_dropped() const { return udp_dropped_; }
  [[nodiscard]] std::size_t events_queued() const { return events_.size(); }

private:
  enum class Kind : std::uint8_t { listener, tcp, udp };
  struct Datagram {
    Endpoint from{};
    std::vector<std::byte> bytes{};
  };
  struct Sock {
    Kind kind = Kind::tcp;
    Endpoint local{}, remote{};
    TcpSocketOptions opts{};
    ConnId peer = no_conn;          // tcp: the other end, no_conn once it closed
    std::deque<std::byte> rx{};     // tcp: received, unread
    std::deque<Datagram> dgrams{};  // udp
    bool fin_sent = false;          // shutdown_write or close
    bool peer_fin = false;          // the peer sent FIN (or closed)
    bool closed_queued = false;     // on_closed was queued
    bool want_writable = false;     // a send was refused or short
    bool readable_queued = false, writable_queued = false;
    std::optional<Error> error{};
    std::uint64_t bytes_sent = 0, bytes_received = 0;
    std::uint64_t segs_out = 0, segs_in = 0;
  };
  enum class EvType : std::uint8_t { accept, connected, readable, writable, closed, error };
  struct Event {
    EvType type = EvType::readable;
    ConnId id = no_conn;
    ConnId conn = no_conn;  // accept: the new connection
    Error err = Error::would_block;
  };
  struct Timer {
    Time deadline{};
    Duration period{};  // 0: one-shot
    std::function<void()> cb{};
  };

  Sock* find(ConnId id, Kind kind);
  ConnId add(Sock s);
  std::uint16_t ephemeral_port();
  void queue(Event e);
  void queue_readable(ConnId id);
  void queue_writable(ConnId id);
  void maybe_closed(ConnId id);
  // The connection fails with connection_reset (the peer sent RST).
  void reset(ConnId id);
  void dispatch(const Event& e, Handler& h);

  FakeTransportOptions opt_;
  Time now_;
  std::map<ConnId, Sock> socks_;
  std::deque<Event> events_;
  std::map<TimerToken, Timer> timers_;
  ConnId next_id_ = 1;
  TimerToken next_timer_ = 1;
  std::uint16_t next_port_;
  std::uint64_t udp_dropped_ = 0;
  bool stopped_ = false;
};

}  // namespace utcp::app
