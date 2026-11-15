#include "core/tcp/recovery.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>

#include "utcp/check.hpp"

namespace utcp {
namespace {

constexpr Duration reneg_min_delay = std::chrono::milliseconds{10};  // tcp_check_sack_reneging

// Linux tcp_any_retrans_done.
bool any_retrans_done(const SendQueue& q) {
  if (q.counters().retrans_out > 0) {
    return true;
  }
  const auto segs = q.segs();
  return !segs.empty() && segs.front().ever_retrans;
}

}  // namespace

void LossRecovery::refresh(RecoveryCtx& c) const {
  const Counters& k = c.q.counters();
  c.cc.ca_state = state_;
  c.cc.in_flight = packets_in_flight(k);
  c.cc.packets_out = k.packets_out;
  c.cc.snd_una = c.q.una();
  c.cc.snd_nxt = c.q.nxt();
  c.cc.lost = c.q.lost_total();
  c.cc.now = c.now;
  c.cc.srtt = c.rtt.srtt();
  c.cc.min_rtt = c.rtt.min_rtt();
}

void LossRecovery::set_state(RecoveryCtx& c, CaState s) {
  // Linux tcp_set_ca_state: the CC hook sees the new state first.
  c.algo.set_state(c.cc, s);
  state_ = s;
  c.cc.ca_state = s;
}

void LossRecovery::arm(XmitTimer kind, Time deadline) {
  timer_ = kind;
  deadline_ = kind == XmitTimer::none ? Time::never() : deadline;
}

bool LossRecovery::persist_wanted(const RecoveryCtx& c) const {
  if (c.q.counters().packets_out != 0) {
    return false;
  }
  const std::uint64_t unsent = c.q.end() - c.q.nxt();
  if (unsent == 0) {
    return false;
  }
  const std::uint64_t mss = c.cc.mss == 0 ? unsent : c.cc.mss;
  return c.snd_wnd < std::min(unsent, mss);
}

void LossRecovery::timer_after_ack(RecoveryCtx& c) {
  if (c.q.counters().packets_out > 0) {
    arm(XmitTimer::rto, c.now + c.rtt.rto_backed_off(c.backoff));  // RFC 6298 §5.3
  } else if (persist_wanted(c)) {
    arm(XmitTimer::persist, c.now + c.rtt.rto_backed_off(c.backoff));  // tcp_ack_probe
  } else {
    arm(XmitTimer::none, Time::never());  // §5.2
  }
}

void LossRecovery::mark_head_lost(RecoveryCtx& c) {
  // Linux tcp_newreno_mark_lost: nothing to do if the head is already lost.
  const auto segs = c.q.segs();
  if (segs.empty() || segs.front().lost || segs.front().sacked) {
    return;
  }
  c.q.mark_lost(segs.front().off);
}

void LossRecovery::reno_dupack(RecoveryCtx& c, AckOutcome& out) {
  // Linux tcp_add_reno_sack: the increase of sacked_out is delivered.
  const std::uint32_t before = c.q.counters().sacked_out;
  c.q.reno_dupack();
  out.delivered += c.q.counters().sacked_out - before;
}

void LossRecovery::try_to_open(RecoveryCtx& c) {
  // Linux tcp_try_to_open / tcp_try_keep_open (no ECN in M1).
  const Counters& k = c.q.counters();
  const CaState s =
      (k.sacked_out + k.lost_out > 0 || any_retrans_done(c.q)) ? CaState::disorder : CaState::open;
  if (state_ != s) {
    set_state(c, s);
    recover_ = c.q.nxt_with_fin();
  }
}

void LossRecovery::enter_recovery(RecoveryCtx& c) {
  // Linux tcp_enter_recovery + tcp_init_cwnd_reduction; M1 has no PRR, so
  // cwnd = ssthresh at once (§5.3).
  if (c.sack_ok) {
    ++c.stats.TcpExtTCPSackRecovery;
  } else {
    ++c.stats.TcpExtTCPRenoRecovery;
  }
  refresh(c);
  c.cc.prior_ssthresh = current_ssthresh(c.cc);
  recover_ = c.q.nxt_with_fin();
  c.cc.cwnd_cnt = 0;
  c.cc.prior_cwnd = c.cc.cwnd;
  c.cc.ssthresh = c.algo.ssthresh(c.cc);
  c.cc.cwnd = c.cc.ssthresh;
  set_state(c, CaState::recovery);
  mark_head_lost(c);
  const auto segs = c.q.segs();
  fast_rexmit_pending_ = !segs.empty() && segs.front().lost && !segs.front().retrans_inflight;
}

void LossRecovery::fastretrans_alert(RecoveryCtx& c, bool dupack, bool advanced,
                                     AckOutcome& out) {
  const bool reno = !c.q.sack_ok();
  const std::uint64_t una = c.q.una_with_fin();

  // D. State exit once SND.UNA reaches recover (Linux high_seq).
  if ((state_ == CaState::recovery || state_ == CaState::loss) && una >= recover_) {
    if (state_ == CaState::recovery && reno) {
      c.q.clear_all_sacked();  // tcp_reset_reno_sack
    }
    if (reno && una == recover_) {
      // tcp_try_undo_recovery: without SACK, hold the state until something
      // above recover is acknowledged (RFC 6582 §3.2 step 1, no false fast
      // retransmits).
      return;
    }
    const bool was_recovery = state_ == CaState::recovery;
    set_state(c, CaState::open);
    sack_reneg_ = false;
    if (was_recovery && c.cc.ssthresh < cwnd_infinite) {
      c.cc.cwnd = c.cc.ssthresh;  // tcp_end_cwnd_reduction (RFC 6582 §3.2 step 3)
    }
    if (was_recovery) {
      c.algo.cwnd_event(c.cc, CaEvent::complete_cwr);
    }
  }

  // E. Process the state.
  const Counters& k = c.q.counters();
  switch (state_) {
    case CaState::recovery:
      if (!advanced) {
        if (reno && dupack) {
          reno_dupack(c, out);
        }
      } else {
        // Partial ACK: the new SND.UNA segment is lost (RFC 6582 §3.2
        // step 5, Linux tcp_newreno_mark_lost).
        mark_head_lost(c);
      }
      return;
    case CaState::loss:
      if (reno) {  // tcp_process_loss
        if (c.q.nxt_with_fin() > recover_ && dupack) {
          reno_dupack(c, out);
        } else if (advanced) {
          c.q.clear_all_sacked();
        }
      }
      return;
    case CaState::open:
    case CaState::disorder:
    case CaState::cwr:
      break;
  }
  if (reno) {
    if (advanced) {
      c.q.clear_all_sacked();
    }
    if (dupack) {
      reno_dupack(c, out);
    }
  }
  // A fixed dupthresh in both profiles: adaptive reordering
  // (cfg.adaptive_reordering, Linux tcp_check_sack_reordering and
  // tcp_check_reno_reordering) is not modelled in M1.
  const std::uint32_t dupthresh = std::max(c.cfg.dupthresh, 1u);
  if (k.sacked_out >= dupthresh) {
    mark_head_lost(c);  // tcp_newreno_mark_lost, state < Recovery
  }
  // tcp_time_to_recover: loss proven, or sacked_out + 1 > dupthresh.
  if (k.lost_out > 0 || k.sacked_out + 1 > dupthresh) {
    enter_recovery(c);
  } else {
    try_to_open(c);
  }
}

void LossRecovery::on_delivered(RecoveryCtx&, const TxSeg&, bool) {
  // M2a: RACK advance and reordering detection.
}

void LossRecovery::on_ack(RecoveryCtx& c, const AckInput& in, AckOutcome& out) {
  UTCP_DCHECK(c.sack_ok == c.q.sack_ok());
  refresh(c);
  const bool advanced = (out.flags & ack_una_advanced) != 0;
  if (advanced) {
    fast_rexmit_pending_ = false;  // the head it named is acknowledged
  }
  // Linux tcp_ack_is_dubious (FLAG_CA_ALERT: newly SACKed data or a
  // D-SACK), and num_dupack (not for a D-SACK).
  const bool dubious = in.dupack || out.newly_sacked > 0 || (out.flags & ack_dsack) != 0 ||
                       state_ != CaState::open;
  const bool dupack = in.dupack && !advanced && (out.flags & ack_dsack) == 0;
  bool rearm = advanced || c.q.counters().packets_out == 0;
  if (dubious) {
    if ((out.flags & ack_sack_reneging) != 0 && advanced) {
      // tcp_check_sack_reneging: give the receiver a short while to send
      // the ACK that covers the SACKed data, then RTO.
      arm(XmitTimer::rto, c.now + std::max(c.rtt.srtt() / 2, reneg_min_delay));
      rearm = false;
    } else {
      fastretrans_alert(c, dupack, advanced, out);
    }
  }
  if (rearm) {
    timer_after_ack(c);
  }
  refresh(c);
  out.in_flight = c.cc.in_flight;
}

void LossRecovery::on_transmit(RecoveryCtx& c, const TxSeg& seg, TxKind kind) {
  const bool head = seg.off == c.q.una();
  if (seg.tx_count == 1) {
    ++c.stats.TcpExtTCPOrigDataSent;
  } else {
    switch (kind) {
      case TxKind::fast_rexmit:
      case TxKind::rexmit:
      case TxKind::pmtu_rexmit:
        // Linux tcp_xmit_retransmit_queue.
        if (state_ == CaState::loss) {
          ++c.stats.TcpExtTCPSlowStartRetrans;
        } else {
          ++c.stats.TcpExtTCPFastRetrans;
        }
        break;
      default: break;
    }
    if (head) {
      fast_rexmit_pending_ = false;
    }
  }
  // RFC 6298 §5.1; Linux re-arms on a retransmission of the head
  // (tcp_xmit_retransmit_queue, tcp_retransmit_timer).
  if (timer_ != XmitTimer::rto || (head && seg.tx_count > 1)) {
    arm(XmitTimer::rto, c.now + c.rtt.rto_backed_off(c.backoff));
  }
}

void LossRecovery::on_burst_end(RecoveryCtx& c, bool new_data_sent) {
  if (script_ != nullptr && script_->on_burst_end(c, new_data_sent)) {
    return;
  }
  if (c.q.counters().packets_out > 0) {
    if (timer_ != XmitTimer::rto) {
      arm(XmitTimer::rto, c.now + c.rtt.rto_backed_off(c.backoff));
    }
  } else if (persist_wanted(c)) {
    // tcp_check_probe_timer; after an expiry, the next probe interval with
    // the backoff the engine raised (tcp_send_probe0).
    if (timer_ != XmitTimer::persist || deadline_ <= c.now) {
      arm(XmitTimer::persist, c.now + c.rtt.rto_backed_off(c.backoff));
    }
  } else {
    arm(XmitTimer::none, Time::never());
  }
}

void LossRecovery::on_rto(RecoveryCtx& c) {
  UTCP_DCHECK(c.sack_ok == c.q.sack_ok());
  // Linux tcp_timeout_mark_lost: a SACKed head means the receiver reneged
  // (RFC 2018 §8).
  const auto segs = c.q.segs();
  if (!segs.empty() && segs.front().sacked) {
    ++c.stats.TcpExtTCPSACKReneging;
    c.q.clear_all_sacked();
    sack_reneg_ = true;
  } else if (!c.q.sack_ok()) {
    c.q.clear_all_sacked();  // tcp_reset_reno_sack
  }
  for (std::size_t i = 0; i < c.q.segs().size(); ++i) {
    const TxSeg& s = c.q.segs()[i];
    if (!s.sacked) {
      c.q.mark_lost(s.off);
    }
  }
  refresh(c);
  // tcp_enter_loss: reduce ssthresh once per loss episode (RFC 5681 §3.1).
  if (state_ == CaState::open || state_ == CaState::disorder ||
      c.q.una_with_fin() >= recover_ || (state_ == CaState::loss && c.rto_count == 0)) {
    c.cc.prior_ssthresh = current_ssthresh(c.cc);
    c.cc.prior_cwnd = c.cc.cwnd;
    c.cc.ssthresh = c.algo.ssthresh(c.cc);
    c.algo.cwnd_event(c.cc, CaEvent::loss);
  }
  c.cc.cwnd = c.cc.in_flight + 1;
  c.cc.cwnd_cnt = 0;
  set_state(c, CaState::loss);
  recover_ = c.q.nxt_with_fin();
  fast_rexmit_pending_ = false;
  arm(XmitTimer::none, Time::never());  // re-armed by the rto_rexmit
  ++c.stats.TcpExtTCPTimeouts;
}

void LossRecovery::on_pmtu_drop(RecoveryCtx& c) {
  UTCP_CHECK(c.cc.mss > 0 && c.cc.mss <= 0xffffu);
  for (std::size_t i = 0; i < c.q.segs().size(); ++i) {
    const TxSeg& s = c.q.segs()[i];
    if (s.len > c.cc.mss) {
      c.q.mark_lost(s.off);
    }
  }
  c.q.split_to_mss(static_cast<std::uint16_t>(c.cc.mss));
  refresh(c);
  if (c.q.counters().lost_out == 0) {
    return;
  }
  // Linux tcp_simple_retransmit: no cwnd change, the units shrank.
  if (state_ != CaState::loss) {
    recover_ = c.q.nxt_with_fin();
    c.cc.ssthresh = current_ssthresh(c.cc);
    c.cc.prior_ssthresh = 0;
    set_state(c, CaState::loss);
    // A fast retransmit owed by Recovery becomes an ordinary lost segment,
    // resent under cwnd as pmtu_rexmit (§4.9, §4.13).
    fast_rexmit_pending_ = false;
  }
  refresh(c);
}

std::pair<XmitTimer, Time> LossRecovery::xmit_timer(const RecoveryCtx& c) const {
  if (script_ != nullptr) {
    if (auto t = script_->xmit_timer(c)) {
      return *t;
    }
  }
  return {timer_, deadline_};
}

void LossRecovery::on_xmit_timer(RecoveryCtx& c, XmitTimer kind) {
  if (script_ != nullptr && script_->on_xmit_timer(c, kind)) {
    return;
  }
  if (kind == timer_) {
    arm(XmitTimer::none, Time::never());
  }
}

// ---- M2 hooks: m2-found stubs with M1 behaviour (m2a-recovery replaces
// them, M2-DESIGN §1.4-1.9).

void LossRecovery::cwnd_reduction(RecoveryCtx& c, std::uint32_t newly_acked_sacked,
                                  std::uint32_t newly_lost, std::uint32_t flags) {
  if (script_ != nullptr && script_->cwnd_reduction(c, newly_acked_sacked, newly_lost, flags)) {
    return;
  }
  // M1: cwnd = ssthresh was set on entering Recovery; nothing per ACK.
}

bool LossRecovery::may_raise_cwnd(const RecoveryCtx& c, const AckOutcome& out) const {
  if (script_ != nullptr) {
    if (const auto r = script_->may_raise_cwnd(c, out)) {
      return *r;
    }
  }
  return out.acked_pkts > 0;  // tcp_may_raise_cwnd, FLAG_DATA_ACKED
}

std::optional<std::uint64_t> LossRecovery::next_seg_extra(RecoveryCtx& c) {
  if (script_ != nullptr) {
    if (auto r = script_->next_seg_extra(c)) {
      return *r;
    }
  }
  return std::nullopt;
}

TlpAction LossRecovery::on_pto(RecoveryCtx& c) {
  if (script_ != nullptr) {
    if (const auto r = script_->on_pto(c)) {
      return *r;
    }
  }
  return TlpAction::none;
}

void LossRecovery::on_tlp_sent(RecoveryCtx& c, TlpAction action, bool sent) {
  if (script_ != nullptr && script_->on_tlp_sent(c, action, sent)) {
    return;
  }
  // tcp_send_loss_probe ends in tcp_rearm_rto (Linux 7.0 tcp_output.c:3227-3230,
  // tcp_input.c:3524-3549). A sent probe cleared the pending timer first, so
  // the RTO is a full one from now; otherwise the PTO is still pending and the
  // RTO gets the time left to the head's RTO (tcp_rto_delta_us), at least one
  // jiffy and rounded up to whole jiffies (usecs_to_jiffies, HZ 1000). Both
  // add the pacing delay (pace_delay = true), truncated to whole ms. M1 never
  // arms a PTO, so the stub is reached only through the test seam; m2a keeps
  // or replaces it with the rest of the TLP state (M2-DESIGN §1.7).
  (void)action;
  const auto segs = c.q.segs();
  if (c.q.counters().packets_out == 0 || segs.empty()) {
    timer_after_ack(c);
    return;
  }
  const Duration rto = c.rtt.rto_backed_off(c.backoff);
  constexpr Duration jiffy = std::chrono::milliseconds{1};
  Duration d = rto;
  if (!sent) {
    const Duration left = std::max(segs.front().last_tx + rto - c.now, Duration{1});
    d = (left + jiffy - Duration{1}) / jiffy * jiffy;
  }
  d += c.pacing_delay / jiffy * jiffy;
  arm(XmitTimer::rto, c.now + d);
}

bool LossRecovery::exempt_from_cwnd(const RecoveryCtx& c, const TxSeg& seg) const {
  if (script_ != nullptr) {
    if (const auto r = script_->exempt_from_cwnd(c, seg)) {
      return *r;
    }
  }
  return fast_rexmit_pending_ && seg.off == c.q.una();
}

std::uint32_t LossRecovery::reordering(const TcpConfig& cfg) const { return cfg.dupthresh; }

std::uint32_t LossRecovery::reord_seen() const { return 0; }

std::optional<std::uint64_t> LossRecovery::tlp_high_seq() const { return std::nullopt; }

CaState LossRecovery::state() const { return state_; }

bool LossRecovery::fast_rexmit_pending() const { return fast_rexmit_pending_; }

std::optional<std::uint64_t> LossRecovery::recover() const {
  if (state_ == CaState::recovery || state_ == CaState::loss) {
    return recover_;
  }
  return std::nullopt;
}

bool LossRecovery::sack_reneg() const { return sack_reneg_; }

}  // namespace utcp
