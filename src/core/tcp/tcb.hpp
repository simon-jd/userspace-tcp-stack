// The transmission control block (DESIGN §4.2) and the listener state.
// Owned by the TCP engine (tcp_engine.hpp); every TCB lives in one slot of
// the engine's slot vector.
//
// Sequence space and stream offsets (§3.2): SendQueue and RecvBuffer address
// payload bytes by 64-bit stream offset, offset 0 being the byte at ISS + 1
// (send) or IRS + 1 (receive). SND.UNA, SND.NXT and RCV.NXT are therefore not
// stored as Seq32 fields but derived from the queues (snd_una(), snd_nxt(),
// rcv_nxt() below), so the two views cannot disagree; SYN and FIN add their
// one unit of sequence space through syn_acked, SendQueue::fin_sent/fin_acked
// and fin_rcvd. rcv_adv is RcvWindow::rcv_adv() (an offset).
#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <optional>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/ack_policy.hpp"
#include "core/tcp/cc.hpp"
#include "core/tcp/cc_newreno.hpp"
#include "core/tcp/rate.hpp"
#include "core/tcp/rcv_window.hpp"
#include "core/tcp/recovery.hpp"
#include "core/tcp/recv_buffer.hpp"
#include "core/tcp/rtt.hpp"
#include "core/tcp/sack_gen.hpp"
#include "core/tcp/send_queue.hpp"
#include "core/tcp/tx_policy.hpp"
#include "core/timer/timer_heap.hpp"
#include "utcp/config.hpp"
#include "utcp/error.hpp"
#include "utcp/seq.hpp"
#include "utcp/stack.hpp"
#include "utcp/stats.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

// Limited-time accounting (§10.1, Linux enum tcp_chrono): exactly one of
// busy, rwnd_limited and sndbuf_limited runs while unsent or unacked data
// exists. Order matters: a higher value takes over a lower one
// (tcp_chrono_start).
enum class ChronoType : std::uint8_t { none, busy, rwnd_limited, sndbuf_limited };

struct Chrono {
  ChronoType type = ChronoType::none;
  Time start;
  std::array<Duration, 4> total{};  // by ChronoType
};

// TcpSocketOptions resolved against the TcpConfig defaults.
struct SockOpts {
  bool nodelay = false;
  std::optional<std::uint32_t> snd_buf, rcv_buf;  // set by the application: no autotuning
  CcAlgo cc = CcAlgo::newreno;
  std::optional<std::uint16_t> mss_clamp;
};

struct ListenState {
  std::uint32_t backlog = 0;
  std::deque<std::uint32_t> accept_q;  // slots of established, not accepted children, oldest first
  std::uint32_t syn_children = 0;      // children in SYN-RECEIVED
};

struct Tcb {
  Tcb(const TcpConfig& cfg, ChunkPool& chunks, std::uint32_t snd_buf, std::uint32_t rcv_buf,
      bool rcv_autotune)
      : rtt(cfg),
        sndq(chunks, snd_buf),
        txp(cfg),
        rcvq(rcv_buf, chunks),
        ackp(cfg),
        rwin(cfg, rcv_buf, rcv_autotune) {}

  FourTuple tuple;
  Handle self;                         // slot and current generation
  std::optional<std::uint32_t> listener;  // passive child: the listener's slot until accepted
  std::uint32_t conn_id = 0;           // monotonic per stack, for traces
  TcpState state = TcpState::closed;
  bool passive = false;                // created by a listener
  bool app_holds = false;              // the application holds `self` (connect, accept)
  bool orphan = false;                 // closed by the application, still running
  bool app_read_shut = false, app_write_shut = false;
  bool in_conn_table = false;
  std::optional<ListenState> listen;   // listeners only
  SockOpts opts;

  // Send sequence space (RFC 9293 §3.3.1). snd_una/snd_nxt are derived.
  Seq32 iss;
  bool syn_acked = false;              // our SYN (or SYN-ACK) is acknowledged
  Seq32 snd_wl1, snd_wl2;
  std::uint32_t snd_wnd = 0, max_snd_wnd = 0;  // scaled, bytes
  // Receive sequence space.
  Seq32 irs;
  bool have_irs = false;
  bool fin_rcvd = false;               // the peer's FIN is processed: RCV.NXT is past it
  std::uint32_t rcv_wnd = 0;           // last advertised window, bytes
  std::uint16_t syn_wnd = 0;           // window field of our SYN or SYN-ACK (unscaled)
  Seq32 last_ack_sent;                 // RFC 7323 §4.3 Last.ACK.sent

  // Options (§4.5).
  bool ws_ok = false, ts_ok = false, sack_ok = false;
  std::uint8_t snd_wscale = 0, rcv_wscale = 0;
  std::uint8_t offered_wscale = 0;     // the shift our SYN or SYN-ACK offers
  std::uint16_t peer_mss = 536, adv_mss = 536, mss_cache = 536, pmtu = 576;
  std::uint32_t ts_recent = 0, ts_offset = 0;
  Time ts_recent_stamp;
  bool ts_recent_valid = false;
  std::optional<std::uint32_t> last_tsecr;  // receiver RTT: the last TSecr seen with data

  // RTT, retransmission, retries (§4.8).
  RttEstimator rtt;
  std::uint8_t backoff = 0, rto_count = 0, probes_out = 0, syn_tries = 0;
  std::optional<Time> retrans_stamp;   // first retransmission since the last full recovery
  Time syn_first_tx, syn_last_tx;
  XmitTimer xmit_kind = XmitTimer::none;  // what the xmit timer is armed for
  // SND.NXT (offset) at the last PMTU drop that marked segments lost: lost
  // segments below it are resent as TxKind::pmtu_rexmit (§4.13) until
  // SND.UNA passes it or an RTO fires.
  std::optional<std::uint64_t> pmtu_rexmit_end;

  // Send side.
  SendQueue sndq;
  TxPolicy txp;
  bool fin_queued = false;
  bool send_blocked = false;           // tcp_send was refused or short: ev_writable owed
  Time pacing_next;
  Time lsndtime;                       // last data transmission (cwnd restart)
  std::uint64_t cwnd_usage_seq = 0;    // tcp_cwnd_validate window end (offset)
  // Receive side.
  RecvBuffer rcvq;
  SackGenerator sackgen;
  AckPolicy ackp;
  RcvWindow rwin;
  // Congestion control and recovery (§5).
  CcConn cc_conn;
  CcStorage cc;
  LossRecovery recovery;
  RateState rate;

  // Timers (§6), created with the slot as owner.
  TimerId t_xmit = no_timer, t_delack = no_timer, t_pace = no_timer, t_fin_wait2 = no_timer;
  std::optional<Time> last_oow_ack;    // RFC 5961 §7 limiter (§4.7)
  std::optional<Error> error, soft_error;
  bool error_reported = false;         // take_error returned `error`
  bool closed_event_sent = false;
  TcpCounters ctr;
  Chrono chrono;
  Time last_data_recv, last_ack_recv;
  std::uint16_t ip_id = 0;

  // Sequence numbers derived from the queues (§3.2).
  [[nodiscard]] Seq32 snd_base() const noexcept { return iss + 1; }
  [[nodiscard]] Seq32 rcv_base() const noexcept { return irs + 1; }
  [[nodiscard]] Seq32 snd_una() const noexcept {
    return syn_acked ? seq_at(snd_base(), sndq.una_with_fin()) : iss;
  }
  [[nodiscard]] Seq32 snd_nxt() const noexcept { return seq_at(snd_base(), sndq.nxt_with_fin()); }
  [[nodiscard]] std::uint64_t rcv_nxt_off() const noexcept { return rcvq.contiguous_end(); }
  [[nodiscard]] Seq32 rcv_nxt() const noexcept {
    return seq_at(rcv_base(), rcvq.contiguous_end()) + (fin_rcvd ? 1u : 0u);
  }
  // RCV.WND as acceptance sees it: rcv_adv (the highest edge advertised,
  // RFC 7323 §2.4 rule 1) minus RCV.NXT.
  [[nodiscard]] std::uint32_t rcv_window() const noexcept {
    const std::uint64_t nxt = rcvq.contiguous_end() + (fin_rcvd ? 1u : 0u);
    const std::uint64_t adv = rwin.rcv_adv();
    return adv > nxt ? static_cast<std::uint32_t>(adv - nxt) : 0u;
  }
  [[nodiscard]] bool synchronized() const noexcept {
    switch (state) {
      case TcpState::established:
      case TcpState::fin_wait_1:
      case TcpState::fin_wait_2:
      case TcpState::close_wait:
      case TcpState::closing:
      case TcpState::last_ack:
      case TcpState::time_wait:
        return true;
      default:
        return false;
    }
  }
  [[nodiscard]] CongestionControl& algo() noexcept { return cc_of(cc); }

  // snd_una <= snd_nxt, SendQueue counters against a recount, the receive
  // side consistent; aborts on failure.
  void check_invariants() const;
};

}  // namespace utcp
