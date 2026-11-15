#include "core/tcp/recovery.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>

#include "utcp/check.hpp"

namespace utcp {
namespace {

constexpr Duration reneg_min_delay = std::chrono::milliseconds{10};  // tcp_check_sack_reneging
constexpr Duration jiffy = std::chrono::milliseconds{1};              // HZ 1000

// tcp_pacing_delay as tcp_reset_xmit_timer adds it (pace_delay = true):
// whole jiffies, truncated (M2-DESIGN §1.7).
Duration pacing_delay_jiffies(const RecoveryCtx& c) {
  return c.pacing_delay > Duration{0} ? c.pacing_delay / jiffy * jiffy : Duration{0};
}

// tcp_rto_delta_us as tcp_rearm_rto uses it: the time left to the head's RTO
// (from its last transmission), at least 1 us, in whole jiffies rounded up
// (usecs_to_jiffies).
Duration head_rto_left(const RecoveryCtx& c, Duration rto) {
  const auto segs = c.q.segs();
  const Duration left = std::max(segs.front().last_tx + rto - c.now, Duration{1});
  return (left + jiffy - Duration{1}) / jiffy * jiffy;
}

bool is_retransmission(TxKind kind) {
  switch (kind) {
    case TxKind::fast_rexmit:
    case TxKind::rexmit:
    case TxKind::pmtu_rexmit:
      return true;
    default:
      return false;
  }
}

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

void LossRecovery::rearm_rto(RecoveryCtx& c) {
  if (c.q.counters().packets_out > 0) {
    // RFC 6298 §5.3; Linux tcp_rearm_rto: while a REO or PTO timer is
    // pending, only the time left to the head's RTO (a REO or PTO does not
    // extend the RTO).
    const Duration rto = c.rtt.rto_backed_off(c.backoff);
    const Duration d =
        timer_ == XmitTimer::reo || timer_ == XmitTimer::pto ? head_rto_left(c, rto) : rto;
    arm(XmitTimer::rto, c.now + d + pacing_delay_jiffies(c));
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
  // Linux tcp_try_to_open / tcp_try_keep_open (no ECN, so never CWR here).
  if (state_ == CaState::cwr) {
    return;
  }
  const Counters& k = c.q.counters();
  const CaState s =
      (k.sacked_out + k.lost_out > 0 || any_retrans_done(c.q)) ? CaState::disorder : CaState::open;
  if (state_ != s) {
    set_state(c, s);
    recover_ = c.q.nxt_with_fin();
  }
}

void LossRecovery::init_cwnd_reduction(RecoveryCtx& c) {
  // Linux tcp_init_cwnd_reduction (tcp_input.c:2970).
  recover_ = c.q.nxt_with_fin();
  c.cc.cwnd_cnt = 0;
  c.cc.prior_cwnd = c.cc.cwnd;
  prr_init(prr_, c.cc.cwnd);
  c.cc.ssthresh = c.algo.ssthresh(c.cc);
}

void LossRecovery::end_cwnd_reduction(RecoveryCtx& c) {
  // Linux tcp_end_cwnd_reduction (tcp_input.c:3012): cwnd = ssthresh when a
  // CWR or Recovery ends (in Recovery Linux tests undo_marker, always set
  // without undo, §1.10); nothing when the CC owns cwnd.
  if (c.algo.has_cong_control()) {
    return;
  }
  if (c.cc.ssthresh < cwnd_infinite) {
    c.cc.cwnd = c.cc.ssthresh;  // RFC 6582 §3.2 step 3, RFC 6675 §5 (A), RFC 9937
  }
  c.algo.cwnd_event(c.cc, CaEvent::complete_cwr);
}

void LossRecovery::enter_recovery(RecoveryCtx& c) {
  // Linux tcp_enter_recovery (tcp_input.c:3177).
  if (c.sack_ok) {
    ++c.stats.TcpExtTCPSackRecovery;
  } else {
    ++c.stats.TcpExtTCPRenoRecovery;
  }
  refresh(c);
  c.cc.prior_ssthresh = 0;
  if (state_ != CaState::cwr && state_ != CaState::recovery) {  // !tcp_in_cwnd_reduction
    c.cc.prior_ssthresh = current_ssthresh(c.cc);
    init_cwnd_reduction(c);
  }
  set_state(c, CaState::recovery);
  const bool rfc6675 = c.cfg.recovery_reduction == RecoveryReduction::rfc6675;
  if (rfc6675) {
    // RFC 6675 §5 (4.2): cwnd = ssthresh at once. With PRR the CC step of
    // this ACK (or the REO timer) sets cwnd (§1.8).
    c.cc.cwnd = c.cc.ssthresh;
  }
  // RFC 6675 (4.3) and RFC 6582: the first segment is retransmitted. RACK
  // marks what it marks; Linux does not mark the head on entry.
  if (!uses_rack(c)) {
    mark_head_lost(c);
  }
  const auto segs = c.q.segs();
  if (uses_6675(c) && !segs.empty()) {
    sb_.on_enter_recovery(segs.front().end());
  }
  // The fast retransmit skips the cwnd gate only under RFC 6675's cwnd rule
  // (§5 (4.3)); PRR's forced sndcnt admits it (§1.8).
  fast_rexmit_pending_ =
      rfc6675 && !segs.empty() && segs.front().lost && !segs.front().retrans_inflight;
}

bool LossRecovery::time_to_recover(const RecoveryCtx& c) const {
  const Counters& k = c.q.counters();
  if (!c.sack_ok) {
    // tcp_newreno_mark_lost marked the head at sacked_out >= reordering.
    return k.lost_out > 0 || k.sacked_out >= std::max(reordering(c.cfg), 1u);
  }
  if (uses_6675(c)) {
    // RFC 6675 §5 steps (1)-(2): DupAcks >= DupThresh, or IsLost(HighACK + 1)
    // (the IsLost marks are a prefix of the queue, so any mark means the
    // head is lost).
    return k.lost_out > 0 || sb_.dupacks() >= std::max(c.cfg.dupthresh, 1u);
  }
  return k.lost_out > 0;  // tcp_time_to_recover (tcp_input.c:2716)
}

void LossRecovery::newreno_mark_lost(RecoveryCtx& c, bool advanced) {
  // Linux tcp_newreno_mark_lost (tcp_recovery.c:142): before Recovery at
  // sacked_out >= reordering; in Recovery on a partial ACK (RFC 6582 §3.2
  // step 5).
  const std::uint32_t reord = std::max(reordering(c.cfg), 1u);
  if ((state_ < CaState::recovery && c.q.counters().sacked_out >= reord) ||
      (state_ == CaState::recovery && advanced)) {
    mark_head_lost(c);
  }
}

Duration LossRecovery::rack_reo_wnd_now(const RecoveryCtx& c) const {
  return rack_reo_wnd(rack_, reord_seen_, state_ == CaState::recovery || state_ == CaState::loss,
                      c.q.counters().sacked_out, reordering(c.cfg), c.rtt.min_rtt(),
                      c.rtt.srtt());
}

bool LossRecovery::rack_mark_lost(RecoveryCtx& c) {
  // Linux tcp_rack_mark_lost (tcp_recovery.c:95).
  if (!rack_.advanced) {
    return false;
  }
  rack_.advanced = false;
  const Duration timeout = rack_detect_loss(rack_, fifo_, c.q, c.now, rack_reo_wnd_now(c));
  if (timeout <= Duration{0}) {
    return false;
  }
  arm(XmitTimer::reo, rack_reo_deadline(c.now, timeout, c.rtt.rto_backed_off(c.backoff)));
  return true;
}

bool LossRecovery::identify_packet_loss(RecoveryCtx& c, bool advanced) {
  // Linux tcp_identify_packet_loss (tcp_input.c:3297); the rfc profile's SACK
  // marking is RFC 6675 IsLost (§1.2).
  if (c.q.segs().empty()) {
    return false;
  }
  if (!c.sack_ok) {
    newreno_mark_lost(c, advanced);
    return false;
  }
  if (uses_6675(c)) {
    (void)sb_.mark_lost(c.q, std::max(c.cfg.dupthresh, 1u), std::max(c.cc.mss, 1u));
    return false;
  }
  const std::uint32_t prior_retrans = c.q.counters().retrans_out;
  if (rack_mark_lost(c)) {
    reo_armed_ = true;  // *ack_flag &= ~FLAG_SET_XMIT_TIMER
  }
  return c.q.counters().retrans_out < prior_retrans;  // FLAG_LOST_RETRANS
}

void LossRecovery::fastretrans_alert(RecoveryCtx& c, bool dupack, bool advanced,
                                     AckOutcome& out) {
  // Linux tcp_fastretrans_alert (tcp_input.c:3328).
  const bool reno = !c.q.sack_ok();
  const std::uint64_t una = c.q.una_with_fin();

  // D. State exit once SND.UNA reaches recover (Linux high_seq).
  if (state_ == CaState::cwr && una > recover_) {
    // CWR is held until something above high_seq is acknowledged.
    end_cwnd_reduction(c);
    set_state(c, CaState::open);
  } else if ((state_ == CaState::recovery || state_ == CaState::loss) && una >= recover_) {
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
    sb_.reset_recovery();
    if (was_recovery) {
      end_cwnd_reduction(c);
    }
  }

  // E. Process the state.
  switch (state_) {
    case CaState::recovery:
      if (!advanced && reno && dupack) {
        reno_dupack(c, out);
      }
      // With SACK a partial ACK marks nothing by itself (IsLost or RACK only,
      // §1.2); without SACK it marks the new head (newreno_mark_lost).
      (void)identify_packet_loss(c, advanced);
      return;
    case CaState::loss:
      if (reno) {  // tcp_process_loss
        if (c.q.nxt_with_fin() > recover_ && dupack) {
          reno_dupack(c, out);
        } else if (advanced) {
          c.q.clear_all_sacked();
        }
      }
      // A retransmission found lost again leaves Loss for Recovery (Linux
      // FLAG_LOST_RETRANS falls through to the Open case).
      if (!identify_packet_loss(c, advanced)) {
        return;
      }
      break;
    case CaState::open:
    case CaState::disorder:
    case CaState::cwr:
      if (reno) {
        if (advanced) {
          c.q.clear_all_sacked();
        }
        if (dupack) {
          reno_dupack(c, out);
        }
      }
      (void)identify_packet_loss(c, advanced);
      break;
  }
  if (time_to_recover(c)) {
    enter_recovery(c);
  } else {
    try_to_open(c);
  }
}

void LossRecovery::on_delivered(RecoveryCtx& c, const TxSeg& seg, bool via_sack) {
  // RACK advance (§1.6): tcp_sacktag_one for a newly SACKed TxSeg,
  // tcp_clean_rtx_queue for a cumulatively acknowledged one that was not
  // SACKed (only those reach here), the latter skipped when the ACK's TSecr
  // predates its last transmission (tcp_skb_spurious_retrans).
  if (!uses_rack(c)) {
    return;
  }
  if (!via_sack && seg.ever_retrans && c.in != nullptr && c.in->tsecr && *c.in->tsecr != 0 &&
      static_cast<std::int32_t>(*c.in->tsecr - c.ts_of(seg.last_tx)) < 0) {
    return;
  }
  rack_advance(rack_, seg, c.now, c.rtt.min_rtt());
}

void LossRecovery::on_ack(RecoveryCtx& c, const AckInput& in, AckOutcome& out) {
  UTCP_DCHECK(c.sack_ok == c.q.sack_ok());
  refresh(c);
  const bool advanced = (out.flags & ack_una_advanced) != 0;
  if (advanced) {
    fast_rexmit_pending_ = false;  // the head it named is acknowledged
  }
  if (uses_6675(c)) {
    sb_.on_ack(advanced, out.newly_sacked,
               state_ != CaState::recovery && state_ != CaState::loss);
  }
  // Linux tcp_ack_is_dubious (FLAG_CA_ALERT: newly SACKed data or a
  // D-SACK), and num_dupack (not for a D-SACK).
  const bool dubious = in.dupack || out.newly_sacked > 0 || (out.flags & ack_dsack) != 0 ||
                       state_ != CaState::open;
  const bool dupack = in.dupack && !advanced && (out.flags & ack_dsack) == 0;
  // FLAG_SET_XMIT_TIMER (tcp_clean_rtx_queue) as M1: data acknowledged, or
  // nothing left outstanding.
  bool rearm = advanced || c.q.counters().packets_out == 0;
  reo_armed_ = false;
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
  // tcp_set_xmit_timer, not when RACK armed the REO timer in this ACK
  // (tcp_identify_packet_loss clears FLAG_SET_XMIT_TIMER).
  if (rearm && !reo_armed_) {
    rearm_rto(c);
  }
  refresh(c);
  out.in_flight = c.cc.in_flight;
}

void LossRecovery::on_transmit(RecoveryCtx& c, const TxSeg& seg, TxKind kind) {
  const bool head = seg.off == c.q.una();
  const bool retrans = seg.tx_count > 1;
  if (!retrans) {
    ++c.stats.TcpExtTCPOrigDataSent;
  } else {
    if (is_retransmission(kind)) {
      // Linux tcp_xmit_retransmit_queue.
      if (state_ == CaState::loss) {
        ++c.stats.TcpExtTCPSlowStartRetrans;
      } else {
        ++c.stats.TcpExtTCPFastRetrans;
      }
    }
    if (head) {
      fast_rexmit_pending_ = false;
    }
  }
  // prr_out: every data segment sent in CWR or Recovery (tcp_write_xmit,
  // tcp_xmit_retransmit_queue; §1.8).
  if (state_ == CaState::cwr || state_ == CaState::recovery) {
    ++prr_.out;
  }
  // RFC 6675 HighRxt and RescueRxt (§5 (C.3), (C.4)).
  if (uses_6675(c) && state_ == CaState::recovery && retrans && is_retransmission(kind)) {
    sb_.on_retransmit(seg, recover_);
  }
  // The send-time FIFO (§1.5): every data transmission.
  if (uses_rack(c)) {
    fifo_.on_transmit(c.q, seg);
  }
  // Timers (M2-DESIGN §1.7 "Arming on transmission").
  const Duration rto = c.rtt.rto_backed_off(c.backoff);
  if (kind == TxKind::rto_rexmit) {
    // tcp_retransmit_timer: the RTO at the new backoff, no pacing delay.
    arm(XmitTimer::rto, c.now + rto);
  } else if (!retrans) {
    // tcp_event_new_data_sent: only if nothing was out before it or a PTO is
    // pending, via tcp_rearm_rto.
    if (c.q.counters().packets_out == 1 || timer_ == XmitTimer::pto) {
      rearm_rto(c);
    }
  } else if (head && kind != TxKind::tlp && timer_ != XmitTimer::reo) {
    // tcp_xmit_retransmit_queue: a retransmission of the head re-arms a full
    // RTO unless the REO timer is pending (RFC 6298 §5.1).
    arm(XmitTimer::rto, c.now + rto + pacing_delay_jiffies(c));
  }
  if (timer_ == XmitTimer::none || timer_ == XmitTimer::persist) {
    // Data in flight always has a timer (the RTO's own resend was blocked,
    // or a persist probe sent data).
    arm(XmitTimer::rto, c.now + rto);
  }
}

void LossRecovery::on_burst_end(RecoveryCtx& c, bool new_data_sent) {
  if (script_ != nullptr && script_->on_burst_end(c, new_data_sent)) {
    return;
  }
  if (c.q.counters().packets_out > 0) {
    // A REO or PTO timer pending stays (§1.7); the PTO schedule after new
    // data is m2a part 2.
    if (timer_ == XmitTimer::none || timer_ == XmitTimer::persist) {
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
  // Linux tcp_timeout_mark_lost (tcp_input.c:2523): a SACKed head means the
  // receiver reneged (RFC 2018 §8).
  const auto segs = c.q.segs();
  const bool reneg = !segs.empty() && segs.front().sacked;
  if (reneg) {
    ++c.stats.TcpExtTCPSACKReneging;
    c.q.clear_all_sacked();
    sack_reneg_ = true;
  } else if (!c.q.sack_ok()) {
    c.q.clear_all_sacked();  // tcp_reset_reno_sack
  }
  for (std::size_t i = 0; i < c.q.segs().size(); ++i) {
    const TxSeg& s = c.q.segs()[i];
    if (s.sacked) {
      continue;
    }
    // With rack_tlp (§1.6 "RTO"): the head always, another TxSeg only if it
    // was sent at least RACK.rtt ago (tcp_rack_skb_timeout(skb, 0) <= 0).
    // RFC 8985 §6.3 adds reo_wnd; Linux passes 0.
    if (c.cfg.rack_tlp && !reneg && i != 0 && rack_.rtt - (c.now - s.last_tx) > Duration{0}) {
      continue;
    }
    c.q.mark_lost(s.off);
    if (s.retrans_inflight) {
      // A retransmission of a segment that was not marked lost (RFC 6675
      // NextSeg rules 3-4) is lost with the rest: the second mark counts it
      // so (tcp_mark_skb_lost on a LOST|SACKED_RETRANS skb), and the lost
      // loop resends the segment. Linux never has such a segment.
      c.q.mark_lost(s.off);
    }
  }
  refresh(c);
  // tcp_enter_loss: reduce ssthresh once per loss episode (RFC 5681 §3.1).
  if (state_ == CaState::open || state_ == CaState::disorder || c.q.una_with_fin() >= recover_ || (state_ == CaState::loss && c.rto_count == 0)) {
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
  sb_.reset_recovery();  // RFC 6675 §5.1: no recovery until SND.UNA reaches recover
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
  if (uses_rack(c)) {
    fifo_.rebuild(c.q);  // §1.5
  }
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
    sb_.reset_recovery();
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
  if (kind == XmitTimer::reo && timer_ == XmitTimer::reo && uses_rack(c)) {
    // Linux tcp_rack_reo_timeout (tcp_recovery.c:117): mark what has waited
    // long enough; if that changed the flight, enter Recovery (the REO entry
    // reduces cwnd by PRR with one delivered packet) and the engine
    // retransmits.
    ++c.stats.rack_reo_timeouts;
    refresh(c);
    const std::uint64_t lost_before = c.q.lost_total();
    const std::uint32_t prior_in_flight = packets_in_flight(c.q.counters());
    (void)rack_detect_loss(rack_, fifo_, c.q, c.now, rack_reo_wnd_now(c));
    if (packets_in_flight(c.q.counters()) != prior_in_flight && state_ != CaState::recovery) {
      enter_recovery(c);
      if (!c.algo.has_cong_control()) {
        cwnd_reduction(c, 1, static_cast<std::uint32_t>(c.q.lost_total() - lost_before), 0);
      }
    }
    // The pending timer is still REO, so tcp_rearm_rto gives the head's
    // remaining time; a head retransmission by the engine then re-arms a
    // full RTO, as Linux's tcp_rearm_rto after it would.
    rearm_rto(c);
    refresh(c);
    return;
  }
  if (kind == timer_) {
    arm(XmitTimer::none, Time::never());
  }
}

// ---- M2 hooks (M2-DESIGN §1.4-1.9).

void LossRecovery::cwnd_reduction(RecoveryCtx& c, std::uint32_t newly_acked_sacked,
                                  std::uint32_t newly_lost, std::uint32_t flags) {
  if (script_ != nullptr && script_->cwnd_reduction(c, newly_acked_sacked, newly_lost, flags)) {
    return;
  }
  // RFC 6675 §5 keeps cwnd = ssthresh from entry to exit.
  if (c.cfg.recovery_reduction == RecoveryReduction::rfc6675) {
    return;
  }
  // tcp_cwnd_reduction (PRR, §1.8), with in_flight after this ACK's marking.
  const std::optional<std::uint32_t> cwnd =
      prr_cwnd(prr_, c.cc.ssthresh, packets_in_flight(c.q.counters()), newly_acked_sacked,
               newly_lost, (flags & ack_una_advanced) != 0);
  if (cwnd) {
    c.cc.cwnd = *cwnd;
  }
}

bool LossRecovery::may_raise_cwnd(const RecoveryCtx& c, const AckOutcome& out) const {
  if (script_ != nullptr) {
    if (const auto r = script_->may_raise_cwnd(c, out)) {
      return *r;
    }
  }
  return out.acked_pkts > 0;  // tcp_may_raise_cwnd, FLAG_DATA_ACKED (§1.9: m2a part 2)
}

std::optional<std::uint64_t> LossRecovery::next_seg_extra(RecoveryCtx& c) {
  if (script_ != nullptr) {
    if (auto r = script_->next_seg_extra(c)) {
      return *r;
    }
  }
  // RFC 6675 NextSeg rules 3 and 4, in Recovery only (§1.4).
  if (!uses_6675(c) || state_ != CaState::recovery) {
    return std::nullopt;
  }
  return sb_.next_seg(c.q, c.q.una_with_fin(), c.q.una() + c.snd_wnd);
}

TlpAction LossRecovery::on_pto(RecoveryCtx& c) {
  if (script_ != nullptr) {
    if (const auto r = script_->on_pto(c)) {
      return *r;
    }
  }
  return TlpAction::none;  // m2a part 2 (§1.7)
}

void LossRecovery::on_tlp_sent(RecoveryCtx& c, TlpAction action, bool sent) {
  if (script_ != nullptr && script_->on_tlp_sent(c, action, sent)) {
    return;
  }
  // tcp_send_loss_probe ends in tcp_rearm_rto (Linux 7.0 tcp_output.c:3227-3230,
  // tcp_input.c:3524-3549). A sent probe cleared the pending timer first, so
  // the RTO is a full one from now; otherwise the PTO is still pending and the
  // RTO gets the time left to the head's RTO (tcp_rto_delta_us). Both add the
  // pacing delay. The rest of the TLP state is m2a part 2 (M2-DESIGN §1.7).
  (void)action;
  if (c.q.counters().packets_out == 0 || c.q.segs().empty()) {
    rearm_rto(c);
    return;
  }
  const Duration rto = c.rtt.rto_backed_off(c.backoff);
  const Duration d = sent ? rto : head_rto_left(c, rto);
  arm(XmitTimer::rto, c.now + d + pacing_delay_jiffies(c));
}

bool LossRecovery::exempt_from_cwnd(const RecoveryCtx& c, const TxSeg& seg) const {
  if (script_ != nullptr) {
    if (const auto r = script_->exempt_from_cwnd(c, seg)) {
      return *r;
    }
  }
  // RFC 6675 §5 (4.3): the fast retransmit under RFC 6675's cwnd rule only
  // (fast_rexmit_pending_ is set only then).
  return fast_rexmit_pending_ && seg.off == c.q.una();
}

std::uint32_t LossRecovery::reordering(const TcpConfig& cfg) const { return cfg.dupthresh; }

std::uint32_t LossRecovery::reord_seen() const { return reord_seen_; }

std::optional<std::uint64_t> LossRecovery::tlp_high_seq() const { return std::nullopt; }

CaState LossRecovery::state() const {
  if (script_ != nullptr) {
    if (const std::optional<CaState> s = script_->ca_state()) {
      return *s;
    }
  }
  return state_;
}

bool LossRecovery::fast_rexmit_pending() const { return fast_rexmit_pending_; }

std::optional<std::uint64_t> LossRecovery::recover() const {
  if (state_ == CaState::recovery || state_ == CaState::loss) {
    return recover_;
  }
  return std::nullopt;
}

bool LossRecovery::sack_reneg() const { return sack_reneg_; }

}  // namespace utcp
