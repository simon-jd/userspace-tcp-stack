// Loss recovery (DESIGN §5.1, §5.3). Interface declared by m1-found;
// implemented by m1-tx (recovery.cpp).
//
// M1: RFC 6582 NewReno over the Linux in-flight formula, RTO handling as Linux
// tcp_enter_loss/tcp_timeout_mark_lost with the reneging check, and the
// choice of the connection's one `xmit` timer. M2a replaces the internals
// (RFC 6675 scoreboard, RACK-TLP, PRR) without changing TxSeg, SendQueue or
// the engine.
#pragma once

#include <cstdint>
#include <optional>
#include <utility>

#include "core/tcp/cc.hpp"
#include "core/tcp/rtt.hpp"
#include "core/tcp/send_queue.hpp"
#include "utcp/config.hpp"
#include "utcp/stats.hpp"
#include "utcp/time.hpp"
#include "utcp/trace.hpp"
#include "utcp/types.hpp"

namespace utcp {

// What recovery works on, built by the engine for each call.
struct RecoveryCtx {
  SendQueue& q;
  CcConn& cc;
  CongestionControl& algo;
  const RttEstimator& rtt;
  const TcpConfig& cfg;
  Time now;
  std::uint32_t snd_wnd;  // bytes, scaled
  StackStats& stats;      // TcpExtTCPSACKReneging, TcpExtTCPSackRecovery, ...
  bool sack_ok;           // SACK negotiated (else reno dupack accounting)
  std::uint8_t backoff;   // RTO backoff exponent (rto_backed_off)
  std::uint8_t rto_count; // RTO expiries since SND.UNA last advanced, this one excluded
};

// The connection's one transmission timer (RFC 8985 §8, Linux icsk_pending).
enum class XmitTimer : std::uint8_t { none, rto, persist, reo, pto };

class LossRecovery {  // M1: NewReno; M2a: RFC 6675 scoreboard + RACK-TLP + PRR
public:
  LossRecovery() = default;

  // From the SendQueue DeliveredFn callbacks (RACK advance and reordering
  // detection in M2a).
  void on_delivered(RecoveryCtx& c, const TxSeg& seg, bool via_sack);
  // Linux tcp_fastretrans_alert: marks lost, moves the CaState; on entering
  // Recovery sets recover = SND.NXT, ssthresh from the CC, cwnd = ssthresh,
  // marks the SND.UNA segment lost and flags it for fast_rexmit; a partial
  // ACK marks the new SND.UNA segment lost (RFC 6582 §3.2 step 5); a full ACK
  // returns to Open. PRR (M2a) writes cwnd here.
  void on_ack(RecoveryCtx& c, const AckInput& in, AckOutcome& out);
  // Every data (re)transmission: prr_out, HighRxt, TLP state (M2a); clears
  // the fast_rexmit flag.
  void on_transmit(RecoveryCtx& c, const TxSeg& seg, TxKind kind);
  // End of the engine's transmit(): schedules the PTO (M2a).
  void on_burst_end(RecoveryCtx& c);
  // RTO expiry (§5.3): reneging check (a SACKed head clears every SACK mark,
  // counts TcpExtTCPSACKReneging, and makes rate samples invalid until
  // recovery ends), every non-SACKed segment marked lost, ssthresh per RFC
  // 5681 §3.1, cwnd = in-flight + 1 (1 unless reneging), Loss with recover =
  // SND.NXT. The engine then increments backoff and rto_count and runs
  // transmit(); the rto_rexmit re-arms the RTO at the new backoff (Linux
  // tcp_retransmit_timer).
  void on_rto(RecoveryCtx& c);
  // PMTU decrease (§4.13, Linux tcp_simple_retransmit), with cc.mss already
  // the new mss_cache: marks TxSegs longer than it lost, splits them
  // (SendQueue::split_to_mss), and if anything is lost enters Loss without a
  // cwnd cut, recover = SND.NXT, ssthresh = tcp_current_ssthresh (max(ssthresh,
  // 3/4 cwnd) outside a cwnd reduction).
  void on_pmtu_drop(RecoveryCtx& c);
  // Kind and deadline of the xmit timer once the connection is synchronized.
  // M1: rto with data or FIN outstanding (RFC 6298 §5), persist at zero
  // window with data queued and nothing in flight (§4.9), else none. While
  // our SYN or SYN-ACK is unacknowledged (it is not a TxSeg, §3.2) the engine
  // arms the xmit timer as rto itself, with the SYN schedule of §4.8
  // (syn_linear_timeouts, rto_after_syn_rexmit), and does not call this.
  // Deadlines are fixed when armed (Linux icsk_timeout), at now +
  // rto_backed_off(backoff): rto by the first data transmission with the
  // timer not running as rto, by a retransmission of the SND.UNA segment, and
  // by an ACK that advances SND.UNA (RFC 6298 §5.1, §5.3; Linux
  // tcp_rearm_rto), or at now + max(srtt/2, 10 ms) by an ACK that stops at a
  // SACKed segment; persist when nothing is in flight and SND.WND <
  // min(unsent, mss) (zero window or the SWS override), re-armed by ACKs
  // (tcp_ack_probe) and by on_burst_end once it has expired. none otherwise,
  // deadline Time::never(). A queued FIN that was never sent is not visible
  // here (the engine covers that case).
  [[nodiscard]] std::pair<XmitTimer, Time> xmit_timer(const RecoveryCtx& c) const;
  // reo and pto expiries (M2a). For rto and persist the engine runs the
  // expiry itself (on_rto; the probe); calling this for them only stops the
  // timer until the next arming event.
  void on_xmit_timer(RecoveryCtx& c, XmitTimer kind);

  [[nodiscard]] CaState state() const;
  // The head segment must be resent as TxKind::fast_rexmit (exempt from the
  // cwnd gate, RFC 6675 §5 (4.3)).
  [[nodiscard]] bool fast_rexmit_pending() const;
  // recover (RFC 6582) as an offset, while in Recovery or Loss.
  [[nodiscard]] std::optional<std::uint64_t> recover() const;
  // Rate samples are invalid (reneging seen at RTO, until recovery ends).
  [[nodiscard]] bool sack_reneg() const;

private:
  void refresh(RecoveryCtx& c) const;  // the CcConn views recovery owns
  void set_state(RecoveryCtx& c, CaState s);
  void fastretrans_alert(RecoveryCtx& c, bool dupack, bool advanced, AckOutcome& out);
  void enter_recovery(RecoveryCtx& c);
  void try_to_open(RecoveryCtx& c);
  void mark_head_lost(RecoveryCtx& c);
  void reno_dupack(RecoveryCtx& c, AckOutcome& out);
  void timer_after_ack(RecoveryCtx& c);
  [[nodiscard]] bool persist_wanted(const RecoveryCtx& c) const;
  void arm(XmitTimer kind, Time deadline);

  CaState state_ = CaState::open;
  std::uint64_t recover_ = 0;  // Linux high_seq, as SendQueue::nxt_with_fin
  bool fast_rexmit_pending_ = false;
  bool sack_reneg_ = false;  // Linux is_sack_reneg
  XmitTimer timer_ = XmitTimer::none;
  Time deadline_ = Time::never();
};

}  // namespace utcp
