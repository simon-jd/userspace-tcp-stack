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

// One event. Plain data, no strings. Fields that do not apply to a kind are
// zero. Sequence fields are raw 32-bit sequence numbers, *_off fields are
// 64-bit stream offsets.
struct TraceEvent {
  Time t;
  std::uint32_t conn_id = 0;  // Tcb::conn_id, monotonic per stack
  TraceKind kind = TraceKind::state;
  TxKind tx = TxKind::data;
  TcpState state = TcpState::closed;
  CaState ca = CaState::open;
  std::uint32_t seq = 0, ack = 0, len = 0, wnd = 0;
  std::uint32_t cwnd = 0, ssthresh = 0, in_flight = 0, snd_wnd = 0;
  std::int64_t srtt_ns = 0, rttvar_ns = 0, rto_ns = 0;
  std::uint64_t delivered = 0, pacing_rate = 0, delivery_rate = 0;
  std::uint64_t snd_una_off = 0, snd_nxt_off = 0;

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

// f(std::string_view name, const auto& value) for every TraceEvent field, in
// declaration order.
template <class F>
void for_each_field(const TraceEvent& e, F&& f) {
  f(std::string_view{"t"}, e.t);
  f(std::string_view{"conn_id"}, e.conn_id);
  f(std::string_view{"kind"}, e.kind);
  f(std::string_view{"tx"}, e.tx);
  f(std::string_view{"state"}, e.state);
  f(std::string_view{"ca"}, e.ca);
  f(std::string_view{"seq"}, e.seq);
  f(std::string_view{"ack"}, e.ack);
  f(std::string_view{"len"}, e.len);
  f(std::string_view{"wnd"}, e.wnd);
  f(std::string_view{"cwnd"}, e.cwnd);
  f(std::string_view{"ssthresh"}, e.ssthresh);
  f(std::string_view{"in_flight"}, e.in_flight);
  f(std::string_view{"snd_wnd"}, e.snd_wnd);
  f(std::string_view{"srtt_ns"}, e.srtt_ns);
  f(std::string_view{"rttvar_ns"}, e.rttvar_ns);
  f(std::string_view{"rto_ns"}, e.rto_ns);
  f(std::string_view{"delivered"}, e.delivered);
  f(std::string_view{"pacing_rate"}, e.pacing_rate);
  f(std::string_view{"delivery_rate"}, e.delivery_rate);
  f(std::string_view{"snd_una_off"}, e.snd_una_off);
  f(std::string_view{"snd_nxt_off"}, e.snd_nxt_off);
}

}  // namespace utcp
