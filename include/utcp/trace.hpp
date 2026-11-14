// Event trace (DESIGN §10.2).
//
// The stack reports events to a TraceSink set with Stack::set_trace_sink;
// StackConfig::trace_mask selects the kinds (bit i = TraceKind i). With no
// sink the cost is one branch. New TraceKind or TxKind values and new
// TraceEvent fields need the coordinator's approval.
#pragma once

#include <cstdint>
#include <string_view>

#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

enum class TraceKind : std::uint8_t {
  state,     // TCP state change
  tx,        // segment transmitted (TraceEvent::tx says which kind)
  rx,        // segment received
  ack,       // ACK processed by the ACK pipeline
  rtt,       // RTT sample
  rto,       // RTO expiry
  cwnd,      // cwnd or ssthresh change
  recovery,  // CaState change
  timer,     // timer armed or fired
  icmp,      // ICMP error applied to a connection
  drop,      // segment dropped
};
inline constexpr int trace_kind_count = 11;

enum class TxKind : std::uint8_t {
  syn,
  synack,
  data,
  fin,
  ack,
  rst,
  fast_rexmit,    // retransmission on entering recovery (exempt from the cwnd gate)
  rexmit,         // other retransmission of a segment marked lost
  rto_rexmit,     // head retransmission on RTO (exempt from the cwnd gate)
  pmtu_rexmit,    // retransmission after a PMTU decrease
  zwp,            // zero-window probe
  tlp,            // tail loss probe (M2a, exempt from the cwnd gate)
  challenge_ack,  // RFC 5961
};
inline constexpr int tx_kind_count = 13;

// Why a connection reached CLOSED: TraceKind::state events whose state is
// closed carry one (§4.4, §4.7, §4.8, §4.12; the end states of the
// simulator's TerminationChecker, §7.3).
enum class CloseCause : std::uint8_t {
  none,               // not a transition to CLOSED
  last_ack,           // LAST-ACK: our FIN was ACKed
  time_wait_expired,  // the TIME-WAIT entry's timer expired
  time_wait_reused,   // a SYN took the tuple over from TIME-WAIT (RFC 6191)
  time_wait_rst,      // RST in TIME-WAIT with rst_in_time_wait = accept
  rst_received,       // acceptable RST in a synchronized state (connection_reset; none in CLOSING, LAST-ACK)
  refused,            // connection_refused: RST or ICMP port/protocol unreachable in SYN-SENT,
                      // RST in SYN-RECEIVED of an active open
  child_reset,        // passive SYN-RECEIVED child freed by an RST (the listener stays)
  aborted,            // we sent RST: tcp_abort, tcp_close with unread data, data after close
  timed_out,          // retry exhaustion: SYN retries, data or probe retries (RST sent if synchronized)
  synack_timed_out,   // passive SYN-RECEIVED child freed after synack_retries
  fin_wait2_timeout,  // orphan freed after orphan_fin_wait2_timeout
  listener_closed,    // a listener closed, or a non-accepted child reset by that close
};
inline constexpr int close_cause_count = 13;

// The timer of a TraceKind::timer event (§6; xmit split by LossRecovery's
// XmitTimer kind).
enum class TraceTimer : std::uint8_t {
  none,
  rto,
  persist,
  reo,
  pto,
  delack,
  pace,
  fin_wait2,
  keepalive,
  time_wait,
  pmtu_expiry,
};
inline constexpr int trace_timer_count = 11;

enum class TimerOp : std::uint8_t { none, armed, cancelled, fired };
inline constexpr int timer_op_count = 4;

// One event. Plain data, no strings. Fields that do not apply to a kind are
// zero. Sequence fields are raw 32-bit sequence numbers, *_off fields are
// 64-bit stream offsets. Every connection event (TIME-WAIT entries included)
// carries conn_id and the tuple, so the simulator's checkers can match a
// connection with its peer's on the other node and with the Handle of the
// workload (TcpInfo::conn_id).
struct TraceEvent {
  Time t;
  std::uint32_t conn_id = 0;  // Tcb::conn_id (TimeWaitEntry::conn_id), monotonic per stack
  FourTuple tuple;            // the connection's 4-tuple; local is this stack
  TraceKind kind = TraceKind::state;
  TxKind tx = TxKind::data;
  TcpState state = TcpState::closed;
  CaState ca = CaState::open;
  CloseCause cause = CloseCause::none;  // state events to closed
  TraceTimer timer = TraceTimer::none;  // timer events
  TimerOp timer_op = TimerOp::none;     // timer events
  std::uint16_t flags = 0;  // tx, rx, drop: the segment's TCP flags (wire::TcpHeader::flags layout)
  std::uint16_t mss = 0;    // mss_cache: payload bytes of a full segment
  std::uint32_t seq = 0, ack = 0, len = 0, wnd = 0;
  std::uint32_t cwnd = 0, ssthresh = 0, in_flight = 0, snd_wnd = 0;
  std::uint32_t sacked_out = 0, lost_out = 0, retrans_out = 0;  // packets (SendQueue counters)
  std::int64_t srtt_ns = 0, rttvar_ns = 0, rto_ns = 0;
  std::uint64_t delivered = 0, pacing_rate = 0, delivery_rate = 0;
  std::uint64_t snd_una_off = 0, snd_nxt_off = 0;
  // tx events of data and retransmissions (M2-DESIGN §4.4, PacingChecker):
  // the rate of the pacing gate in force at this send in bytes/s, 0 when
  // the gate does not apply; and whether this send opened a new paced burst
  // (the gate was checked against pacing_next before it).
  std::uint64_t gate_rate = 0;
  bool burst_start = false;

  bool operator==(const TraceEvent&) const = default;
};

class TraceSink {
public:
  virtual ~TraceSink() = default;
  virtual void on_event(const TraceEvent& e) = 0;
};

[[nodiscard]] constexpr std::uint32_t trace_bit(TraceKind k) noexcept {
  return std::uint32_t{1} << static_cast<unsigned>(k);
}
inline constexpr std::uint32_t trace_mask_all = (std::uint32_t{1} << trace_kind_count) - 1;

[[nodiscard]] constexpr std::string_view to_string(TraceKind k) noexcept {
  switch (k) {
    case TraceKind::state: return "state";
    case TraceKind::tx: return "tx";
    case TraceKind::rx: return "rx";
    case TraceKind::ack: return "ack";
    case TraceKind::rtt: return "rtt";
    case TraceKind::rto: return "rto";
    case TraceKind::cwnd: return "cwnd";
    case TraceKind::recovery: return "recovery";
    case TraceKind::timer: return "timer";
    case TraceKind::icmp: return "icmp";
    case TraceKind::drop: return "drop";
  }
  return "?";
}

[[nodiscard]] constexpr std::string_view to_string(TxKind k) noexcept {
  switch (k) {
    case TxKind::syn: return "syn";
    case TxKind::synack: return "synack";
    case TxKind::data: return "data";
    case TxKind::fin: return "fin";
    case TxKind::ack: return "ack";
    case TxKind::rst: return "rst";
    case TxKind::fast_rexmit: return "fast_rexmit";
    case TxKind::rexmit: return "rexmit";
    case TxKind::rto_rexmit: return "rto_rexmit";
    case TxKind::pmtu_rexmit: return "pmtu_rexmit";
    case TxKind::zwp: return "zwp";
    case TxKind::tlp: return "tlp";
    case TxKind::challenge_ack: return "challenge_ack";
  }
  return "?";
}

[[nodiscard]] constexpr std::string_view to_string(CloseCause c) noexcept {
  switch (c) {
    case CloseCause::none: return "none";
    case CloseCause::last_ack: return "last_ack";
    case CloseCause::time_wait_expired: return "time_wait_expired";
    case CloseCause::time_wait_reused: return "time_wait_reused";
    case CloseCause::time_wait_rst: return "time_wait_rst";
    case CloseCause::rst_received: return "rst_received";
    case CloseCause::refused: return "refused";
    case CloseCause::child_reset: return "child_reset";
    case CloseCause::aborted: return "aborted";
    case CloseCause::timed_out: return "timed_out";
    case CloseCause::synack_timed_out: return "synack_timed_out";
    case CloseCause::fin_wait2_timeout: return "fin_wait2_timeout";
    case CloseCause::listener_closed: return "listener_closed";
  }
  return "?";
}

[[nodiscard]] constexpr std::string_view to_string(TraceTimer t) noexcept {
  switch (t) {
    case TraceTimer::none: return "none";
    case TraceTimer::rto: return "rto";
    case TraceTimer::persist: return "persist";
    case TraceTimer::reo: return "reo";
    case TraceTimer::pto: return "pto";
    case TraceTimer::delack: return "delack";
    case TraceTimer::pace: return "pace";
    case TraceTimer::fin_wait2: return "fin_wait2";
    case TraceTimer::keepalive: return "keepalive";
    case TraceTimer::time_wait: return "time_wait";
    case TraceTimer::pmtu_expiry: return "pmtu_expiry";
  }
  return "?";
}

[[nodiscard]] constexpr std::string_view to_string(TimerOp op) noexcept {
  switch (op) {
    case TimerOp::none: return "none";
    case TimerOp::armed: return "armed";
    case TimerOp::cancelled: return "cancelled";
    case TimerOp::fired: return "fired";
  }
  return "?";
}

// f(std::string_view name, const auto& value) for every TraceEvent field, in
// declaration order.
template <class F>
void for_each_field(const TraceEvent& e, F&& f) {
  f(std::string_view{"t"}, e.t);
  f(std::string_view{"conn_id"}, e.conn_id);
  f(std::string_view{"tuple"}, e.tuple);
  f(std::string_view{"kind"}, e.kind);
  f(std::string_view{"tx"}, e.tx);
  f(std::string_view{"state"}, e.state);
  f(std::string_view{"ca"}, e.ca);
  f(std::string_view{"cause"}, e.cause);
  f(std::string_view{"timer"}, e.timer);
  f(std::string_view{"timer_op"}, e.timer_op);
  f(std::string_view{"flags"}, e.flags);
  f(std::string_view{"mss"}, e.mss);
  f(std::string_view{"seq"}, e.seq);
  f(std::string_view{"ack"}, e.ack);
  f(std::string_view{"len"}, e.len);
  f(std::string_view{"wnd"}, e.wnd);
  f(std::string_view{"cwnd"}, e.cwnd);
  f(std::string_view{"ssthresh"}, e.ssthresh);
  f(std::string_view{"in_flight"}, e.in_flight);
  f(std::string_view{"snd_wnd"}, e.snd_wnd);
  f(std::string_view{"sacked_out"}, e.sacked_out);
  f(std::string_view{"lost_out"}, e.lost_out);
  f(std::string_view{"retrans_out"}, e.retrans_out);
  f(std::string_view{"srtt_ns"}, e.srtt_ns);
  f(std::string_view{"rttvar_ns"}, e.rttvar_ns);
  f(std::string_view{"rto_ns"}, e.rto_ns);
  f(std::string_view{"delivered"}, e.delivered);
  f(std::string_view{"pacing_rate"}, e.pacing_rate);
  f(std::string_view{"delivery_rate"}, e.delivery_rate);
  f(std::string_view{"snd_una_off"}, e.snd_una_off);
  f(std::string_view{"snd_nxt_off"}, e.snd_nxt_off);
  f(std::string_view{"gate_rate"}, e.gate_rate);
  f(std::string_view{"burst_start"}, e.burst_start);
}

}  // namespace utcp
