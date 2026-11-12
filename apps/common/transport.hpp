// The transport interface the applications are written against (DESIGN §9).
//
// Implementations: KernelTransport (non-blocking Linux sockets on an
// EventLoop, apps/common/kernel_transport.hpp, m1-apps), UtcpTransport (Stack +
// TUN + EventLoop, make_utcp_transport below, m1-backend) and FakeTransport (in
// memory, for tests, apps/common/fake_transport.hpp).
//
// Model: ids name listeners, connections and UDP sockets, like file
// descriptors: an id stays valid until the application calls close(id), also
// after on_closed or on_error. All calls are non-blocking. Events are
// delivered by run() to a Handler, edge-triggered: on_readable after new data
// or the end of stream arrived, on_writable after a send was refused or short
// and space is free again. Listeners accept by themselves: each new connection
// arrives as on_accept(listener, conn).
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>

#include "utcp/config.hpp"
#include "utcp/error.hpp"
#include "utcp/event_loop.hpp"
#include "utcp/stack.hpp"
#include "utcp/stats.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp::app {

// A listener, connection or UDP socket. 0 is never a valid id.
using ConnId = std::uint32_t;
inline constexpr ConnId no_conn = 0;

// Connection statistics: TcpInfo (§10.1). UtcpTransport takes Stack::tcp_info;
// KernelTransport maps TCP_INFO field by field (the table of §10.1).
using ConnSample = TcpInfo;

using TimerToken = std::uint32_t;

// Receives the events of Transport::run. Every callback may call any
// Transport function, close() and stop() included.
class Handler {
public:
  virtual ~Handler() = default;
  // `listener` accepted the new connection `conn` (already established).
  virtual void on_accept(ConnId /*listener*/, ConnId /*conn*/) {}
  // connect() completed.
  virtual void on_connected(ConnId /*conn*/) {}
  // Data, the end of stream (recv returns 0) or a pending error can be read;
  // for a UDP socket, a datagram is queued.
  virtual void on_readable(ConnId /*id*/) {}
  // A send that was refused (would_block) or short can make progress again.
  virtual void on_writable(ConnId /*id*/) {}
  // Both directions are closed (our FIN and the peer's were exchanged). The id
  // stays valid until close().
  virtual void on_closed(ConnId /*id*/) {}
  // The connection failed: connection_refused, connection_reset, timed_out, ...
  // Data received before the error can still be read. The id stays valid
  // until close().
  virtual void on_error(ConnId /*id*/, Error /*e*/) {}
};

class Transport {
public:
  virtual ~Transport() = default;

  // --- TCP.
  // Starts a connection; the result arrives as on_connected or on_error.
  virtual std::expected<ConnId, Error> connect(Endpoint remote, const TcpSocketOptions& opts) = 0;
  // Address 0 binds every local address. Accepted connections inherit `opts`.
  virtual std::expected<ConnId, Error> listen(Endpoint local, std::uint32_t backlog,
                                              const TcpSocketOptions& opts) = 0;
  // Bytes accepted (may be short); would_block when no send space is free.
  virtual std::expected<std::size_t, Error> send(ConnId id, std::span<const std::byte> data) = 0;
  // In-order bytes; 0 = end of stream; would_block when nothing is readable.
  virtual std::expected<std::size_t, Error> recv(ConnId id, std::span<std::byte> out) = 0;
  // Sends FIN after the queued data (half-close).
  virtual void shutdown_write(ConnId id) = 0;
  // Releases the id (listener, connection or UDP socket). A connection is
  // closed as Stack::tcp_close does (FIN, or RST if unread data remains).
  virtual void close(ConnId id) = 0;
  // Statistics of a connection (zero for other ids).
  virtual ConnSample sample(ConnId id) = 0;

  // --- UDP (unconnected sockets, §3.6). Port 0 = ephemeral.
  virtual std::expected<ConnId, Error> udp_open(Endpoint local) = 0;
  virtual std::expected<void, Error> send_to(ConnId id, Endpoint remote,
                                             std::span<const std::byte> data) = 0;
  // would_block when no datagram is queued.
  virtual std::expected<UdpRecv, Error> recv_from(ConnId id, std::span<std::byte> out) = 0;

  // --- Timers. Callbacks run inside run(), like the Handler's.
  // Every `period`, the first time at now() + period.
  virtual TimerToken add_timer(Duration period, std::function<void()> cb) = 0;
  // Once, at now() + delay.
  virtual TimerToken add_oneshot(Duration delay, std::function<void()> cb) = 0;
  virtual void cancel_timer(TimerToken t) = 0;

  // --- Running.
  // Delivers events and runs timers until stop().
  virtual void run(Handler& h) = 0;
  virtual void stop() = 0;
  // The transport's clock (CLOCK_MONOTONIC for the real ones).
  [[nodiscard]] virtual Time now() const = 0;
  // The statistics of the EventLoop the transport runs on, wake-up lateness
  // included (§8.3; utcp-bulk's summary line); nullptr without one (the fake).
  [[nodiscard]] virtual const LoopStats* loop_stats() const { return nullptr; }
};

// UtcpTransport configuration (m1-backend). The programs (m1-apps) fill it
// from their command lines: --pcap FILE into pcap_file, --spin-us N into
// spin_us, --profile into stack.tcp, and so on.
struct UtcpTransportOptions {
  StackConfig stack;            // local_addr, mtu (must equal the TUN MTU), profile, seed, ...
  std::string tun = "utcp0";    // TUN interface, IFF_TUN | IFF_NO_PI (§8.1)
  std::string pcap_file;        // non-empty: write what crosses the TUN (CLOCK_REALTIME, §10.2)
  std::uint32_t spin_us = 0;    // --spin-us: busy-poll the last N us before a deadline (§8.3)
  bool seed_from_getrandom = true;  // fill stack.seed from getrandom(2) (§3.8)
};

// The utcp backend. Returns a message if the TUN device or anything else
// cannot be set up.
std::expected<std::unique_ptr<Transport>, std::string> make_utcp_transport(
    const UtcpTransportOptions& opts);

}  // namespace utcp::app
