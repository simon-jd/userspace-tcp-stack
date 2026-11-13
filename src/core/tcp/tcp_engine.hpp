// The TCP engine as the IP layer sees it (DESIGN §4.1, §4.3). Interface
// declared by m1-found; implemented by m1-tcp-core in tcp_engine.cpp (slots,
// tables, connection life cycle, events, traces), tcp_input.cpp (§4.4),
// tcp_output.cpp (§4.9 and segment construction), tcp_timers.cpp (§6),
// tcp_api.cpp (§3.5) and tcp_icmp.cpp (§4.7, §4.13).
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
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "core/tcp/conn_table.hpp"
#include "core/tcp/tcb.hpp"
#include "core/tcp/time_wait.hpp"
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
  // when the field is 0) and clamped to [min_pmtu, cached PMTU]; 0 otherwise.
  // It may equal or exceed the connection's own PMTU: the engine acts only if
  // new_pmtu < Tcb::pmtu (Linux tcp_v4_mtu_reduced) and never raises it (RFC
  // 1191 §6.1).
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
  struct Slot {
    std::uint32_t gen = 0;
    std::unique_ptr<Tcb> tcb;
  };
  // One received segment after the IP layer's validation (§4.4).
  struct InSeg {
    Time now;
    const wire::TcpView* v = nullptr;
    RxMeta meta;
    Seq32 seq, ack;
    std::uint16_t flags = 0;
    std::uint32_t plen = 0;  // payload bytes
    std::uint32_t len = 0;   // SEG.LEN: payload + SYN + FIN
    [[nodiscard]] bool has(std::uint16_t f) const noexcept { return (flags & f) != 0; }
  };
  // How send_segment() builds one segment.
  struct SegOut {
    Seq32 seq;
    std::uint16_t flags = 0;
    std::uint64_t data_off = 0;  // stream offset of the payload
    std::uint32_t data_len = 0;
    TxKind kind = TxKind::ack;
    bool retrans = false;  // a retransmission (counted in TcpRetransSegs, not TcpOutSegs)
  };

  // --- tcp_engine.cpp: slots, life cycle, events, traces.
  [[nodiscard]] Tcb* find(Handle h);
  [[nodiscard]] const Tcb* find(Handle h) const;
  [[nodiscard]] Tcb& at(std::uint32_t slot) { return *slots_[slot].tcb; }
  [[nodiscard]] Tcb* alloc_tcb(const SockOpts& opts, std::uint32_t rcv_buf_hint = 0);
  void free_tcb(Tcb& t);
  [[nodiscard]] SockOpts resolve(const TcpSocketOptions& o) const;
  void set_state(Tcb& t, TcpState s, CloseCause cause = CloseCause::none);
  // The connection reached CLOSED: traced with `cause`, ev_closed (and
  // ev_error with `err`), timers stopped, tables left; freed at once if no
  // application holds it, else kept until tcp_close.
  void close_conn(Tcb& t, CloseCause cause, std::optional<Error> err = std::nullopt);
  void enter_time_wait(Tcb& t);
  void raise(Tcb& t, std::uint16_t ev);
  void listener_add(std::uint16_t port, std::uint32_t slot);
  void listener_remove(std::uint16_t port);
  [[nodiscard]] std::optional<std::uint32_t> listener_for(std::uint16_t port) const;
  void detach_from_listener(Tcb& t);
  [[nodiscard]] TraceEvent trace_base(const Tcb& t, TraceKind k) const;
  void trace_tx(const Tcb& t, TxKind kind, Seq32 seq, Seq32 ack, std::uint32_t len,
                std::uint32_t wnd, std::uint16_t flags);
  void trace_timer(const Tcb& t, TraceTimer timer, TimerOp op);
  void trace_drop(const Tcb* t, const InSeg& s);
  [[nodiscard]] std::uint32_t ts_now(const Tcb& t, Time now) const;
  void update_mss(Tcb& t);
  void chrono_start(Tcb& t, ChronoType type, Time now);
  void chrono_stop(Tcb& t, ChronoType type, Time now);
  [[nodiscard]] RecoveryCtx rctx(Tcb& t, Time now);
  void refresh_cc(Tcb& t, Time now);

  // --- tcp_input.cpp (§4.4). Functions returning bool return false when
  // the connection left the input path (freed, closed or in TIME-WAIT): the
  // caller must not touch the TCB again.
  void closed_input(const FourTuple& tuple, const InSeg& s);
  void listen_input(Tcb& l, const FourTuple& tuple, const InSeg& s,
                    std::optional<Seq32> iss = std::nullopt);
  void syn_sent_input(Tcb& t, const InSeg& s);
  void sync_input(Tcb& t, const InSeg& s);
  void time_wait_input(std::uint32_t index, const InSeg& s);
  void take_peer_syn(Tcb& t, const InSeg& s);
  void negotiate(Tcb& t, const wire::TcpOptions& peer);
  void handshake_done(Tcb& t, const InSeg& s);
  [[nodiscard]] bool paws_reject(const Tcb& t, const InSeg& s) const;
  // RFC 5961 §7 / Linux tcp_oow_rate_limited: false (and `skipped` counted)
  // within oow_ack_interval of the last such ACK; segments with data or FIN
  // and no SYN are never limited.
  [[nodiscard]] bool oow_allowed(std::optional<Time>& last, const InSeg& s,
                                 std::uint64_t& skipped);
  void challenge_ack(Tcb& t, const InSeg& s);
  void dup_ack(Tcb& t, const InSeg& s, std::uint64_t& skipped);
  [[nodiscard]] bool process_ack_input(Tcb& t, const InSeg& s);
  [[nodiscard]] bool data_input(Tcb& t, const InSeg& s);
  [[nodiscard]] bool fin_check(Tcb& t, Time now);
  void window_writable(Tcb& t, Time now);
  [[nodiscard]] bool alive(std::uint32_t slot, std::uint32_t gen) const;

  // --- tcp_output.cpp (§4.9).
  // Runs the output path: lost segments, new data, FIN, then the ACK owed;
  // then the timers.
  void transmit(Tcb& t, Time now);
  // Sends the ACK AckPolicy wants now, if nothing else carried it.
  void flush_ack(Tcb& t, Time now);
  bool send_segment(Tcb& t, Time now, const SegOut& o);
  bool send_ack(Tcb& t, Time now, TxKind kind = TxKind::ack);
  // Our SYN, or SYN-ACK once IRS is known. `counts`: a transmission of the
  // SYN schedule (syn_tries); the SYN-ACK of a simultaneous open is not.
  void send_syn(Tcb& t, Time now, bool counts = true);
  void send_rst(Tcb& t, Time now);
  // RFC 9293 §3.10.7.1 reply to a segment no connection takes.
  void send_reset_reply(const FourTuple& tuple, const InSeg& s);
  void send_tw_ack(TimeWaitEntry& e, Time now);
  bool retransmit_seg(Tcb& t, Time now, const TxSeg& seg, TxKind kind);
  bool send_new_data(Tcb& t, Time now, std::uint32_t len, bool fin);
  [[nodiscard]] std::uint32_t mss_now(const Tcb& t) const;
  [[nodiscard]] std::size_t sack_blocks(const Tcb& t, std::span<Range> out) const;
  [[nodiscard]] std::uint32_t initial_window(const Tcb& t) const;
  void sndbuf_expand(Tcb& t);

  // --- tcp_timers.cpp (§6).
  void sync_timers(Tcb& t, Time now);
  void on_xmit(Tcb& t, Time now);
  void on_syn_timeout(Tcb& t, Time now);
  void on_rto(Tcb& t, Time now);
  void on_persist(Tcb& t, Time now);
  void abort_timed_out(Tcb& t, Time now);
  void on_time_wait_expiry(std::uint32_t index);
  void trace_tw_state(const TimeWaitEntry& e, CloseCause cause);

  StackCore& core_;
  const TcpConfig& cfg_;
  std::vector<Slot> slots_;
  std::vector<std::uint32_t> free_slots_;  // min-heap: the lowest free index is reused first
  ConnTable conns_;
  TimeWaitTable tw_;
  std::vector<std::pair<std::uint16_t, std::uint32_t>> listeners_;  // (port, slot), sorted
  std::uint32_t next_conn_id_ = 1;
  std::uint32_t live_ = 0;  // slots holding a TCB
};

}  // namespace utcp
