// The stack: host interface, socket API and events (DESIGN §3.4-3.7).
//
// Sans-I/O: inputs are IPv4 datagrams (receive), the current time (receive,
// advance) and the seed (StackConfig::seed); outputs are datagrams
// (pop_transmit), socket events (poll_event) and the next deadline
// (next_deadline). The same inputs give byte-identical outputs.
//
// Host contract (§3.4):
// 1. Before blocking, drain pop_transmit() and poll_event(), then re-read
//    next_deadline().
// 2. When now >= next_deadline(), call advance(now). Waking late is allowed.
// 3. Socket calls use now(), the time of the last receive/advance; an
//    iteration starts with advance(clock()).
// 4. A `now` earlier than now() is clamped and counted in
//    stats().time_regressions (an assertion with
//    StackConfig::assert_time_monotonic).
//
// Ownership: receive() borrows its input (payload is copied before it
// returns). pop_transmit() hands out pool buffers; dropping the TxPacket
// returns the buffer. Every TxPacket must be dropped before the Stack.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>

#include "utcp/config.hpp"
#include "utcp/error.hpp"
#include "utcp/packet.hpp"
#include "utcp/stats.hpp"
#include "utcp/time.hpp"
#include "utcp/trace.hpp"
#include "utcp/types.hpp"

namespace utcp {

enum class Shutdown : std::uint8_t { read, write, both };

// Per-socket options; unset fields take the TcpConfig default.
struct TcpSocketOptions {
  std::optional<bool> nodelay;
  std::optional<std::uint32_t> snd_buf, rcv_buf;  // payload bytes; disables autotuning for that side
  std::optional<CcAlgo> cc;                       // NewReno, CUBIC or BBR at socket creation
  std::optional<std::uint16_t> mss_clamp;         // like TCP_MAXSEG

  bool operator==(const TcpSocketOptions&) const = default;
};

// Socket event bits (edge-triggered, coalesced per socket).
enum Ev : std::uint16_t {
  ev_readable = 1,
  ev_writable = 2,     // free send space rose to at least half the queued bytes
  ev_acceptable = 4,
  ev_connected = 8,
  ev_read_closed = 16,  // peer FIN
  ev_closed = 32,       // fully closed (once, on reaching CLOSED)
  ev_error = 64,
};

// Sockets with pending events are delivered in the order in which they first
// became pending (FIFO, at most one entry per socket).
struct SocketEvent {
  Handle h;
  std::uint16_t events = 0;  // Ev bits

  bool operator==(const SocketEvent&) const = default;
};

// Level-triggered state.
struct Readiness {
  bool readable = false;
  bool writable = false;
  bool acceptable = false;
  bool read_closed = false;
  bool write_closed = false;
  bool has_error = false;

  bool operator==(const Readiness&) const = default;
};

struct UdpRecv {
  std::size_t len = 0;   // datagram length (bytes copied: min(len, buffer size))
  Endpoint from;
  bool truncated = false;

  bool operator==(const UdpRecv&) const = default;
};

struct EchoReply {
  std::uint16_t id = 0, seq = 0;
  Ipv4Addr from;
  std::size_t len = 0;  // payload bytes
  Time t;               // receive time

  bool operator==(const EchoReply&) const = default;
};

// Resource usage, for leak checks (QuiescenceChecker) and tests.
struct StackUsage {
  std::uint32_t tcp_slots = 0;           // live TCP sockets and connections, listeners included
  std::uint32_t udp_slots = 0;           // open UDP sockets
  std::uint32_t time_wait_entries = 0;
  std::uint32_t pool_buffers = 0;        // PacketPool size
  std::uint32_t pool_buffers_free = 0;
  std::uint32_t chunks = 0;              // chunks the ChunkPool has allocated so far
  std::uint32_t chunks_free = 0;
  std::uint32_t tx_queued = 0;           // packets waiting for pop_transmit
  std::uint32_t events_queued = 0;       // sockets waiting for poll_event
  std::uint32_t echo_replies_queued = 0;
  std::uint32_t blocked_conns = 0;       // connections waiting for transmit queue or pool space
  std::uint32_t conn_timers_armed = 0;   // per-connection and TIME_WAIT timers
  std::uint32_t stack_timers_armed = 0;  // stack-wide timers (pmtu_expiry)

  bool operator==(const StackUsage&) const = default;
};

class StackImpl;

class Stack {
public:
  // cfg.seed is the only source of randomness.
  explicit Stack(const StackConfig& cfg);
  ~Stack();
  Stack(const Stack&) = delete;
  Stack& operator=(const Stack&) = delete;

  // --- Host interface (§3.4). `now` must be non-decreasing across calls.
  void receive(Time now, std::span<const std::byte> ipv4, RxMeta meta = {});
  // Resumes connections blocked on transmit space, then fires timers and
  // pacing gates due at or before `now`.
  void advance(Time now);
  // Oldest queued datagram (FIFO); nullopt when nothing is queued.
  std::optional<TxPacket> pop_transmit();
  // Earliest timer or pacing gate; now() when blocked connections can resume;
  // Time::never() if there is nothing to do.
  [[nodiscard]] Time next_deadline() const;
  // Time of the last receive or advance.
  [[nodiscard]] Time now() const;
  // Next socket with pending events (§3.5).
  std::optional<SocketEvent> poll_event();

  // --- TCP (§3.5).
  // Binds `local` (address 0 or the stack address); addr_in_use if another
  // listener has the port. `backlog` bounds established-but-not-accepted
  // children; SYNs beyond it (SYN-RECEIVED children included) are dropped.
  std::expected<Handle, Error> tcp_listen(Endpoint local, std::uint32_t backlog,
                                          const TcpSocketOptions& opts = {});
  // Oldest established child; would_block if none.
  std::expected<Handle, Error> tcp_accept(Handle listener);
  // Sends SYN; the result arrives as ev_connected or ev_error. local_port 0
  // picks an RFC 6056 ephemeral port (addr_not_available if none is free).
  std::expected<Handle, Error> tcp_connect(Endpoint remote, const TcpSocketOptions& opts = {},
                                           std::uint16_t local_port = 0);
  // Bytes accepted (may be short); would_block if no send space.
  std::expected<std::size_t, Error> tcp_send(Handle h, std::span<const std::byte> data);
  // In-order bytes; 0 = end of stream; then the connection error, if any.
  std::expected<std::size_t, Error> tcp_recv(Handle h, std::span<std::byte> out);
  std::expected<void, Error> tcp_shutdown(Handle h, Shutdown how);
  // The handle is invalid on return.
  std::expected<void, Error> tcp_close(Handle h);
  // Sends RST if synchronized; the handle is invalid on return.
  std::expected<void, Error> tcp_abort(Handle h);
  [[nodiscard]] Readiness tcp_readiness(Handle h) const;
  [[nodiscard]] std::expected<TcpInfo, Error> tcp_info(Handle h) const;
  std::expected<void, Error> tcp_set_options(Handle h, const TcpSocketOptions& opts);
  // Pending connection error, cleared by the call (like SO_ERROR).
  std::optional<Error> take_error(Handle h);

  // --- UDP (§3.6). Unconnected sockets only.
  // Events: a UDP handle raises only ev_readable, through poll_event like a
  // TCP socket, when a datagram is queued on it (coalesced: one pending
  // ev_readable for any number of datagrams until poll_event returns it). It
  // raises no ev_writable: there is no send buffer.
  std::expected<Handle, Error> udp_open(Endpoint local);  // port 0 = ephemeral
  // Builds and queues the datagram at once, or fails: message_too_big above
  // pmtu(dst) - 28 bytes; no_buffers when the transmit queue or the packet
  // pool is full (nothing is queued; space returns when the host drains
  // pop_transmit, host contract item 1, so the caller retries in its next
  // iteration). UDP never joins the blocked-connection FIFO.
  std::expected<void, Error> udp_send_to(Handle h, Endpoint remote,
                                         std::span<const std::byte> data);
  // would_block if no datagram is queued.
  std::expected<UdpRecv, Error> udp_recv_from(Handle h, std::span<std::byte> out);
  std::expected<void, Error> udp_close(Handle h);

  // --- ICMP (§3.7).
  std::expected<void, Error> icmp_echo(Ipv4Addr dst, std::uint16_t id, std::uint16_t seq,
                                       std::span<const std::byte> payload);
  // Oldest echo reply received (queue of 64).
  std::optional<EchoReply> poll_echo_reply();

  // --- Observability and checks.
  // Events of the kinds selected by StackConfig::trace_mask; nullptr disables.
  void set_trace_sink(TraceSink* sink);
  [[nodiscard]] const StackStats& stats() const;
  [[nodiscard]] const StackConfig& config() const;
  // Verifies internal invariants; aborts on failure.
  void debug_check() const;
  [[nodiscard]] StackUsage debug_usage() const;

private:
  std::unique_ptr<StackImpl> impl_;  // one allocation at construction
};

}  // namespace utcp
