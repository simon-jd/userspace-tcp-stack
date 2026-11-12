// The TCP engine as the IP layer sees it (DESIGN §4.1, §4.3). Interface
// declared by m1-found; implemented by m1-tcp-core (tcp_engine.cpp and the
// tcp_*.cpp files), which deletes the link stub tcp_engine_stub.cpp.
//
// The IP layer validates IPv4 and the TCP header (§4.4) and calls on_segment;
// it dispatches ICMP errors quoting TCP, the connection timers and transmit
// space to the engine. The engine reaches the rest of the stack only through
// StackCore (core/stack_impl.hpp). The tcp_* entry points are those of Stack
// (§3.5), with the same contracts; they run at core.now().
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include "core/timer/timer_heap.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "utcp/error.hpp"
#include "utcp/packet.hpp"
#include "utcp/seq.hpp"
#include "utcp/stack.hpp"
#include "utcp/stats.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

class StackCore;

// An ICMP error quoting one of our TCP segments (§3.7, §4.7, §4.13), as the
// IP layer parsed it.
struct TcpIcmpError {
  std::uint8_t type = 0, code = 0;  // wire::icmp_* values
  FourTuple tuple;                  // local = the quoted source (us), remote = the quoted destination
  Seq32 seq;                        // the quoted sequence number (RFC 5927 §4.1 check)
  // Type 3 code 4: the path MTU to use, already derived by the IP layer (the
  // next-hop MTU, or the RFC 1191 §7 plateau below the quoted total length
  // when the field is 0) and clamped to [min_pmtu, current); 0 otherwise.
  std::uint16_t new_pmtu = 0;
};

// Counts for Stack::debug_usage (§3.4).
struct TcpUsage {
  std::uint32_t slots = 0;              // live sockets and connections, listeners included
  std::uint32_t time_wait_entries = 0;
  std::uint32_t timers_armed = 0;       // connection and TIME_WAIT timers
  std::uint32_t chunks_held = 0;        // in send and receive buffers
};

class TcpEngine {
public:
  explicit TcpEngine(StackCore& core);
  ~TcpEngine();
  TcpEngine(const TcpEngine&) = delete;
  TcpEngine& operator=(const TcpEngine&) = delete;

  // --- From the IP layer.
  // A validated segment for the stack address (§4.4). `ip` is the datagram's
  // header (source, TTL, ...), `seg` the parsed segment; payload views point
  // into the borrowed input and are copied before return.
  void on_segment(Time now, const wire::Ipv4Header& ip, const wire::TcpView& seg, RxMeta meta);
  // An ICMP error quoting a TCP segment we sent.
  void on_icmp_error(Time now, const TcpIcmpError& err);
  // A connection or TIME_WAIT timer fired (kinds xmit, delack, pace,
  // fin_wait2, keepalive, time_wait; `owner` as given to TimerHeap::create).
  void on_timer(Time now, std::uint32_t owner, TimerKind kind);
  // Transmit queue and pool space freed: resume the connection in `slot` that
  // joined the blocked FIFO through StackCore::block_tx (§3.4).
  void on_tx_space(Time now, std::uint32_t slot);

  // --- For the port allocator (§4.6).
  // The 4-tuple is in the connection or TIME_WAIT table.
  [[nodiscard]] bool tuple_in_use(const FourTuple& tuple) const;
  // A TCP listener holds the port.
  [[nodiscard]] bool port_has_listener(std::uint16_t port) const;

  // --- Socket API (§3.5), forwarded by Stack.
  std::expected<Handle, Error> tcp_listen(Endpoint local, std::uint32_t backlog,
                                          const TcpSocketOptions& opts);
  std::expected<Handle, Error> tcp_accept(Handle listener);
  std::expected<Handle, Error> tcp_connect(Endpoint remote, const TcpSocketOptions& opts,
                                           std::uint16_t local_port);
  std::expected<std::size_t, Error> tcp_send(Handle h, std::span<const std::byte> data);
  std::expected<std::size_t, Error> tcp_recv(Handle h, std::span<std::byte> out);
  std::expected<void, Error> tcp_shutdown(Handle h, Shutdown how);
  std::expected<void, Error> tcp_close(Handle h);
  std::expected<void, Error> tcp_abort(Handle h);
  [[nodiscard]] Readiness tcp_readiness(Handle h) const;
  [[nodiscard]] std::expected<TcpInfo, Error> tcp_info(Handle h) const;
  std::expected<void, Error> tcp_set_options(Handle h, const TcpSocketOptions& opts);
  std::optional<Error> take_error(Handle h);

  // --- Checks.
  [[nodiscard]] TcpUsage usage() const;
  // Every TCB's invariants (Tcb::check_invariants) and the tables; aborts on
  // failure (Stack::debug_check).
  void check_invariants() const;

private:
  StackCore& core_;
  // Engine state is m1-tcp-core's.
};

}  // namespace utcp
