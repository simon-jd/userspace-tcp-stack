// utcp-echo (DESIGN §9): a TCP echo server and client, and a UDP echo server
// (for `nc -u`).
//
// Server: every byte received on a connection is sent back; when the peer
// ends its stream and everything was echoed, the connection is closed. At
// most max_pending unsent bytes are buffered per connection; beyond that it
// stops reading until the peer reads. UDP: every datagram is sent back to its
// source.
//
// Client: --connections N connections in total, --concurrency C at a time;
// each sends --count requests of --size bytes one after the other (the next
// request after the whole echo of the previous one arrived), checks every
// echoed byte, and closes. Request bytes depend on the connection and request
// number, so a mixed-up echo is detected. --rate R limits the request starts
// to R per second over all connections (0 = as fast as the echoes come).
// Latency (request start to last echoed byte) goes into a log-linear
// histogram; the summary has p50, p99 and p999.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <map>
#include <string>
#include <vector>

#include "common/cli.hpp"
#include "common/jsonl.hpp"
#include "common/kernel_transport.hpp"
#include "common/latency_hist.hpp"
#include "common/transport.hpp"

namespace utcp::app::echo {

// --- Server.

struct ServerOptions {
  Endpoint local{};
  bool udp = false;
  TcpSocketOptions sock{};
  std::uint32_t backlog = 4096;
  std::size_t max_pending = 1024 * 1024;  // unsent bytes per connection
};

struct ServerStats {
  std::uint64_t accepted = 0, closed = 0, errors = 0;
  std::uint64_t bytes = 0;      // TCP bytes echoed (accepted by send)
  std::uint64_t datagrams = 0;  // UDP datagrams echoed
  std::uint64_t udp_dropped = 0;  // UDP replies refused by the transport
};

class EchoServer final : public Handler {
public:
  EchoServer(Transport& t, const ServerOptions& o);
  [[nodiscard]] std::expected<void, std::string> start();
  // The listener or connection belongs to this server (for a shared transport).
  [[nodiscard]] bool owns(ConnId id) const;
  [[nodiscard]] const ServerStats& stats() const { return stats_; }
  [[nodiscard]] std::size_t open_connections() const { return conns_.size(); }
  void close_all();

  void on_accept(ConnId listener, ConnId conn) override;
  void on_readable(ConnId id) override;
  void on_writable(ConnId id) override;
  void on_closed(ConnId id) override;
  void on_error(ConnId id, Error e) override;

private:
  struct Conn {
    std::vector<std::byte> pending;  // received, not yet sent back
    std::size_t pending_off = 0;
    bool eof = false;
  };
  void service(ConnId id);
  void udp_readable();
  void drop(ConnId id);

  Transport& t_;
  ServerOptions o_;
  ConnId sock_ = no_conn;  // listener or UDP socket
  std::map<ConnId, Conn> conns_;
  std::vector<std::byte> buf_;
  ServerStats stats_;
};

// --- Client.

struct ClientOptions {
  Endpoint remote{};
  std::size_t size = 64;          // bytes per request
  std::uint64_t count = 100;      // requests per connection
  std::uint64_t connections = 1;  // in total
  std::uint64_t concurrency = 1;  // at a time
  std::uint64_t rate = 0;         // request starts per second, 0 = unlimited
  TcpSocketOptions sock{};
  std::uint64_t seed = 1;
  std::uint64_t open_batch = 0;   // nonzero: gated load, this many outstanding handshakes
};

struct ClientResult {
  bool ok = false;
  std::string first_error;
  std::uint64_t connections_done = 0;  // all requests verified
  std::uint64_t requests_ok = 0;
  std::uint64_t mismatches = 0;  // echoed bytes that differ from the request
  std::uint64_t errors = 0;      // failed connections
  std::uint64_t bytes = 0;       // echoed bytes verified
  Duration duration{};
  LatencyHistogram latency;
};

// The byte at offset `off` of request `req` on connection `conn`.
[[nodiscard]] std::byte request_byte(std::uint64_t seed, std::uint64_t conn, std::uint64_t req,
                                     std::size_t off) noexcept;

enum class LoadPhase { baseline, opening, idle, active, drained };

class EchoClient final : public Handler {
public:
  EchoClient(Transport& t, const ClientOptions& o);
  // Opens the first connections. The transport is stopped when all are done
  // unless stop_when_done is false.
  [[nodiscard]] std::expected<void, std::string> start(bool stop_when_done = true);
  [[nodiscard]] bool owns(ConnId id) const { return conns_.contains(id); }
  [[nodiscard]] bool done() const { return done_; }
  [[nodiscard]] const ClientResult& result() const { return result_; }
  [[nodiscard]] JsonLine summary() const;
  void abort(const std::string& why);

  // Gated load keeps every connection open through idle, active and drain.
  // The controller advances baseline, idle and drained after taking snapshots.
  void advance_load();
  [[nodiscard]] LoadPhase load_phase() const { return load_phase_; }
  [[nodiscard]] JsonLine load_report() const;

  void on_connected(ConnId id) override;
  void on_readable(ConnId id) override;
  void on_writable(ConnId id) override;
  void on_closed(ConnId id) override;
  void on_error(ConnId id, Error e) override;

private:
  struct Conn {
    std::uint64_t index = 0;  // connection number
    std::uint64_t req = 0;    // current request
    std::size_t sent = 0, received = 0;
    bool connected = false;
    bool waiting = false;     // waiting for a rate token
    bool in_request = false;
    Time started{};
  };
  void open_more();
  void start_rate();
  void begin_request(ConnId id);
  void send_some(ConnId id);
  void read_some(ConnId id);
  void finish_conn(ConnId id, bool ok, const std::string& why);
  void refill(Time now);
  void check_done();

  Transport& t_;
  ClientOptions o_;
  std::map<ConnId, Conn> conns_;
  std::uint64_t opened_ = 0;
  std::uint64_t established_ = 0;
  std::uint64_t requests_started_ = 0;
  LoadPhase load_phase_ = LoadPhase::baseline;
  TimerToken open_timer_ = 0;
  std::deque<ConnId> waiting_;  // connections waiting for a rate token
  std::uint64_t tokens_milli_ = 0;  // rate tokens, in thousandths
  Time last_refill_{};
  TimerToken rate_timer_ = 0;
  bool rate_timer_on_ = false;
  Time start_{};
  bool stop_when_done_ = true;
  bool done_ = false;
  std::vector<std::byte> buf_;
  ClientResult result_;
};

void add_options(CliParser& p);
// The whole program; `make` creates the transport (tests pass a fake). The
// client calls finish_closing after run().
int main_(int argc, const char* const* argv,
          const TransportFactory& make = make_transport);

}  // namespace utcp::app::echo
