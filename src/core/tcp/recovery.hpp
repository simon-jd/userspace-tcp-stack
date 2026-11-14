// Loss recovery (DESIGN §5.1, §5.3). Interface declared by m1-found and
// extended by m2-found with the hooks of M2-DESIGN §1.11; implemented by
// m1-tx, then m2a-recovery (recovery.cpp). A contract from M2 on.
//
// M1: RFC 6582 NewReno over the Linux in-flight formula, RTO handling as Linux
// tcp_enter_loss/tcp_timeout_mark_lost with the reneging check, and the
// choice of the connection's one `xmit` timer. M2a replaces the internals
// (RFC 6675 scoreboard, RACK-TLP, PRR) without changing TxSeg or SendQueue;
// the engine calls the M2 hooks below, whose m2-found stubs keep M1
// behaviour.
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

// What recovery works on, built by the engine for each call (TcpEngine::rctx)
// and by process_ack for the calls of one ACK.
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

  // M2 inputs (M2-DESIGN §1.6 "Inputs", §1.7 "Pacing delay").
  // The ACK being processed (TSecr, now_ts for tcp_skb_spurious_retrans);
  // set by process_ack, nullptr in calls outside an ACK.
  const AckInput* in = nullptr;
  std::uint32_t ts_offset = 0;      // the connection's TS clock offset (ts_of)
  std::uint32_t max_snd_wnd = 0;    // bytes, scaled: the largest window the peer offered
  std::uint64_t total_retrans = 0;  // TcpCounters::total_retrans
  std::uint64_t dsack_dups = 0;     // TcpCounters::dsack_dups, this ACK's D-SACK included
  // The ACK's rate snapshot for tcp_rack_update_reo_wnd, set by process_ack
  // once the ACK's segments are delivered: whether a delivered segment
  // carried a snapshot (rs->prior_mstamp != 0), its `delivered` value
  // (rs->prior_delivered), and RateState::delivered after this ACK
  // (tp->delivered).
  bool has_prior = false;
  std::uint64_t prior_delivered = 0;
  std::uint64_t delivered = 0;
  // tcp_pacing_delay: pacing_next - now while the pacing gate applies and
  // pacing_next is ahead, else 0. Recovery truncates it to whole ms where
  // Linux adds it to a timer (§1.7).
  Duration pacing_delay{0};

  // The TS clock value (TSval) of time `t`: 1 ms ticks plus the offset, as the
  // engine's ts_now (DESIGN §3.1).
  [[nodiscard]] std::uint32_t ts_of(Time t) const noexcept {
    return static_cast<std::uint32_t>(static_cast<std::uint64_t>(t.ns) / 1'000'000u) + ts_offset;
  }
};

// The connection's one transmission timer (RFC 8985 §8, Linux icsk_pending).
enum class XmitTimer : std::uint8_t { none, rto, persist, reo, pto };

// What a PTO expiry sends (tcp_send_loss_probe, M2-DESIGN §1.7): nothing, one
// segment of new data (past cwnd by one, pacing-gated), or the last segment
// of the retransmission queue again (not gated). The engine sends it as
// TxKind::tlp.
enum class TlpAction : std::uint8_t { none, new_data, retransmit_last };

// Test seam (M2-TASKS m2-found): LossRecovery is concrete and held by value in
// the TCB, so tests override its hook answers through a RecoveryScript set
// with LossRecovery::set_script (null in production; tests/support/
// recovery_script.hpp has a scriptable one). Each M2 hook and the timer hooks
// ask the script first: a script method returning nullopt or false lets the
// real hook run; any other answer replaces it.
class RecoveryScript {
public:
  virtual ~RecoveryScript() = default;
  virtual std::optional<bool> exempt_from_cwnd(const RecoveryCtx&, const TxSeg&) {
    return std::nullopt;
  }
  virtual std::optional<bool> may_raise_cwnd(const RecoveryCtx&, const AckOutcome&) {
    return std::nullopt;
  }
  // true: handled, the real cwnd_reduction does not run.
  virtual bool cwnd_reduction(RecoveryCtx&, std::uint32_t /*newly_acked_sacked*/,
                              std::uint32_t /*newly_lost*/, std::uint32_t /*flags*/) {
    return false;
  }
  // Outer nullopt: not handled; else the answer (an offset, or none).
  virtual std::optional<std::optional<std::uint64_t>> next_seg_extra(RecoveryCtx&) {
    return std::nullopt;
  }
  virtual std::optional<TlpAction> on_pto(RecoveryCtx&) { return std::nullopt; }
  virtual bool on_tlp_sent(RecoveryCtx&, TlpAction, bool /*sent*/) { return false; }
  virtual bool on_burst_end(RecoveryCtx&, bool /*new_data_sent*/) { return false; }
  virtual std::optional<std::pair<XmitTimer, Time>> xmit_timer(const RecoveryCtx&) {
    return std::nullopt;
  }
  virtual bool on_xmit_timer(RecoveryCtx&, XmitTimer) { return false; }

protected:
  RecoveryScript() = default;
  RecoveryScript(const RecoveryScript&) = default;
  RecoveryScript& operator=(const RecoveryScript&) = default;
};

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
  // End of the engine's transmit(): schedules the PTO (M2a) when
  // `new_data_sent` (new data went out in this call, Linux tcp_write_xmit's
  // sent_pkts > 0 and push_one != 2); M1 and the stub ignore the flag.
  void on_burst_end(RecoveryCtx& c, bool new_data_sent = false);
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
  // 3/4 cwnd) outside a cwnd reduction); a pending fast retransmit is
  // dropped, as the head is then resent under cwnd (§4.9).
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

  // ---- M2 hooks (M2-DESIGN §1.11); the m2-found stubs keep M1 behaviour.

  // tcp_cwnd_reduction (PRR, §1.8): process_ack's CC step calls it in CWR and
  // Recovery when the CC has no cong_control, with newly_acked_sacked =
  // AckOutcome::delivered, newly_lost = RateSample::losses and the AckFlag
  // bits; the REO timer with (1, newly_lost, 0). Writes cc.cwnd. Does nothing
  // with recovery_reduction = rfc6675. Stub: nothing (M1 sets cwnd = ssthresh
  // on entry).
  void cwnd_reduction(RecoveryCtx& c, std::uint32_t newly_acked_sacked, std::uint32_t newly_lost,
                      std::uint32_t flags);
  // tcp_may_raise_cwnd (§1.9): whether cong_avoid runs outside CWR and
  // Recovery. Linux: forward progress (SND.UNA advanced or new SACK) when
  // reordering > dupthresh, else data cumulatively acked. Stub: acked_pkts > 0.
  [[nodiscard]] bool may_raise_cwnd(const RecoveryCtx& c, const AckOutcome& out) const;
  // RFC 6675 NextSeg rules 3 and 4 (§1.4): after the engine's new-data loop
  // stopped with no data or no window left and cwnd - pipe >= 1, the offset of
  // one more segment to send as TxKind::rexmit through the cwnd gate, or
  // nothing. Stub: nothing.
  [[nodiscard]] std::optional<std::uint64_t> next_seg_extra(RecoveryCtx& c);
  // PTO expiry (§1.7): what to send as the probe. Stub: none (M1 never arms a
  // PTO).
  TlpAction on_pto(RecoveryCtx& c);
  // After on_pto: `action` as returned, `sent` whether the engine sent it.
  // Arms the RTO: a full RTO from now after a sent probe, the head's
  // remaining time otherwise. Stub: nothing.
  void on_tlp_sent(RecoveryCtx& c, TlpAction action, bool sent);
  // The lost segment `seg` may be resent past the cwnd gate (RFC 6675 §5
  // (4.3): the fast retransmit with recovery_reduction = rfc6675); the engine
  // sends it as TxKind::fast_rexmit. Stub: M1's rule, `seg` is the head and
  // fast_rexmit_pending().
  [[nodiscard]] bool exempt_from_cwnd(const RecoveryCtx& c, const TxSeg& seg) const;
  // The reordering degree in packets (tcpi_reordering, §1.9): starts at
  // cfg.dupthresh. Stub: cfg.dupthresh.
  [[nodiscard]] std::uint32_t reordering(const TcpConfig& cfg) const;
  // Reordering events detected (tcpi_reord_seen). Stub: 0.
  [[nodiscard]] std::uint32_t reord_seen() const;
  // tlp_high_seq: SND.NXT (offset) when the outstanding probe was sent, or
  // nothing (process_ack's ack_dsack_tlp test). Stub: nothing.
  [[nodiscard]] std::optional<std::uint64_t> tlp_high_seq() const;
  // The test seam (RecoveryScript above); nullptr to remove.
  void set_script(RecoveryScript* script) noexcept { script_ = script; }

  [[nodiscard]] CaState state() const;
  // The head segment must be resent as TxKind::fast_rexmit (exempt from the
  // cwnd gate, RFC 6675 §5 (4.3)). The engine asks exempt_from_cwnd.
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
  RecoveryScript* script_ = nullptr;  // test seam; null in production
};

}  // namespace utcp
