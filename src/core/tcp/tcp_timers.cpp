// Connection and TIME-WAIT timers (DESIGN §6), the SYN schedule and retry
// limits (§4.8).
#include <algorithm>

#include "core/stack_impl.hpp"
#include "core/tcp/tcp_engine.hpp"
#include "utcp/check.hpp"
#include "utcp/retry_model.hpp"

namespace utcp {

namespace {

TraceTimer trace_kind(XmitTimer k) {
  switch (k) {
    case XmitTimer::rto: return TraceTimer::rto;
    case XmitTimer::persist: return TraceTimer::persist;
    case XmitTimer::reo: return TraceTimer::reo;
    case XmitTimer::pto: return TraceTimer::pto;
    case XmitTimer::none: break;
  }
  return TraceTimer::none;
}

}  // namespace

void TcpEngine::on_timer(Time now, std::uint32_t owner, TimerKind kind) {
  if (kind == TimerKind::time_wait) {
    on_time_wait_expiry(owner);
    return;
  }
  if (owner >= slots_.size() || !slots_[owner].tcb) {
    return;
  }
  Tcb& t = at(owner);
  switch (kind) {
    case TimerKind::xmit:
      on_xmit(t, now);
      return;
    case TimerKind::delack:
      trace_timer(t, TraceTimer::delack, TimerOp::fired);
      t.ackp.on_delack_timer(now);
      ++core_.stats().TcpExtDelayedACKs;
      flush_ack(t, now);
      sync_timers(t, now);
      return;
    case TimerKind::pace:
      trace_timer(t, TraceTimer::pace, TimerOp::fired);
      transmit(t, now);
      return;
    case TimerKind::fin_wait2:
      trace_timer(t, TraceTimer::fin_wait2, TimerOp::fired);
      close_conn(t, CloseCause::fin_wait2_timeout);
      return;
    default:
      return;
  }
}

void TcpEngine::on_time_wait_expiry(std::uint32_t index) {
  trace_tw_state(tw_.entry(index), CloseCause::time_wait_expired);
  ++core_.stats().TcpExtTW;
  tw_.erase(index, core_.timers());
}

void TcpEngine::trace_tw_state(const TimeWaitEntry& e, CloseCause cause) {
  if (!core_.tracing(TraceKind::state)) {
    return;
  }
  TraceEvent ev;
  ev.t = core_.now();
  ev.conn_id = e.conn_id;
  ev.tuple = e.tuple;
  ev.kind = TraceKind::state;
  ev.state = TcpState::closed;
  ev.cause = cause;
  core_.trace(ev);
}

// The timers after an event: the xmit timer as LossRecovery wants it once
// synchronized (the SYN schedule arms it itself before), the delayed ACK as
// AckPolicy wants it.
void TcpEngine::sync_timers(Tcb& t, Time now) {
  if (t.state == TcpState::closed || t.state == TcpState::time_wait || t.listen) {
    return;
  }
  TimerHeap& th = core_.timers();
  if (t.syn_acked) {
    const RecoveryCtx c = rctx(t, now);
    const auto [kind, when] = t.recovery.xmit_timer(c);
    if (kind == XmitTimer::none) {
      if (th.armed(t.t_xmit)) {
        th.cancel(t.t_xmit);
        trace_timer(t, trace_kind(t.xmit_kind), TimerOp::cancelled);
      }
    } else if (!th.armed(t.t_xmit) || th.deadline(t.t_xmit) != when || kind != t.xmit_kind) {
      th.arm(t.t_xmit, when);
      t.xmit_kind = kind;
      trace_timer(t, trace_kind(kind), TimerOp::armed);
    }
    t.xmit_kind = kind;
  }
  if (t.have_irs && t.synchronized()) {
    if (t.ackp.need() == AckNeed::delayed) {
      const Time d = t.ackp.delack_deadline();
      if (!th.armed(t.t_delack) || th.deadline(t.t_delack) != d) {
        th.arm(t.t_delack, d);
        trace_timer(t, TraceTimer::delack, TimerOp::armed);
      }
    } else if (th.armed(t.t_delack)) {
      th.cancel(t.t_delack);
      trace_timer(t, TraceTimer::delack, TimerOp::cancelled);
    }
  }
}

void TcpEngine::on_xmit(Tcb& t, Time now) {
  if (!t.syn_acked) {
    trace_timer(t, TraceTimer::rto, TimerOp::fired);
    on_syn_timeout(t, now);
    return;
  }
  const XmitTimer kind = t.xmit_kind;
  trace_timer(t, trace_kind(kind), TimerOp::fired);
  switch (kind) {
    case XmitTimer::rto:
      on_rto(t, now);
      return;
    case XmitTimer::persist:
      on_persist(t, now);
      return;
    case XmitTimer::reo:
    case XmitTimer::pto: {
      RecoveryCtx c = rctx(t, now);
      t.recovery.on_xmit_timer(c, kind);
      transmit(t, now);
      return;
    }
    case XmitTimer::none:
      sync_timers(t, now);
      return;
  }
}

// §4.8: SYN and SYN-ACK retransmission. After retransmission k the timeout
// is rto_initial << (k - L) (k <= L: rto_initial), L = syn_linear_timeouts in
// SYN-SENT, else 0 (Linux tcp_retransmit_timer); the open fails at the
// timeout after retransmission syn_retries + L (synack_retries for a passive
// child; Linux tcp_write_timeout).
void TcpEngine::on_syn_timeout(Tcb& t, Time now) {
  const std::uint32_t linear = t.state == TcpState::syn_sent ? cfg_.syn_linear_timeouts : 0u;
  const std::uint32_t limit = (t.passive ? cfg_.synack_retries : cfg_.syn_retries) + linear;
  if (core_.tracing(TraceKind::rto)) {
    core_.trace(trace_base(t, TraceKind::rto));
  }
  if (t.rto_count >= limit) {
    if (t.passive) {
      close_conn(t, CloseCause::synack_timed_out);
    } else {
      ++core_.stats().TcpExtTCPAbortOnTimeout;
      close_conn(t, CloseCause::timed_out, t.soft_error.value_or(Error::timed_out));
    }
    return;
  }
  ++t.rto_count;
  t.backoff = static_cast<std::uint8_t>(t.rto_count > linear ? t.rto_count - linear : 0u);
  if (!t.passive) {
    ++core_.stats().TcpExtTCPTimeouts;
  }
  send_syn(t, now);
  core_.timers().arm(t.t_xmit, now + t.rtt.rto_backed_off(t.backoff));
  t.xmit_kind = XmitTimer::rto;
  trace_timer(t, TraceTimer::rto, TimerOp::armed);
}

// RFC 6298 §5.4-5.6 with Linux tcp_retransmit_timer: abort check, loss
// marking, backoff, then the head is resent outside the cwnd gate.
void TcpEngine::on_rto(Tcb& t, Time now) {
  if (core_.tracing(TraceKind::rto)) {
    core_.trace(trace_base(t, TraceKind::rto));
  }
  if (t.sndq.segs().empty()) {
    sync_timers(t, now);
    return;
  }
  if (t.snd_wnd == 0 && !t.orphan) {
    // The peer shrank its window to zero under our data (Linux
    // tcp_retransmit_timer, tcp_rtx_probe0_timed_out): the retransmissions
    // act as zero-window probes, so the retry bound does not apply while
    // the peer answers; abort only after 2 * rto_max without an ACK and
    // without progress.
    const Time since = t.retrans_stamp ? *t.retrans_stamp : t.sndq.segs().front().last_tx;
    if (now - t.last_ack_recv > 2 * cfg_.rto_max && now - since > 2 * cfg_.rto_max) {
      abort_timed_out(t, now);
      return;
    }
  } else if (t.rto_count > 0 && t.retrans_stamp &&
             now - *t.retrans_stamp >=
                 retry_abort_time(retry_limit(t), cfg_.rto_min, cfg_.rto_max)) {
    // §4.8 (Linux retransmits_timed_out): retries counted in time from the
    // first retransmission.
    abort_timed_out(t, now);
    return;
  }
  RecoveryCtx c = rctx(t, now);
  t.recovery.on_rto(c);
  t.pmtu_rexmit_end.reset();
  if (t.backoff < 31) {
    ++t.backoff;
  }
  if (t.rto_count < 0xff) {
    ++t.rto_count;
  }
  const TxSeg head = t.sndq.segs().front();
  if (!core_.can_transmit() || !retransmit_seg(t, now, head, TxKind::rto_rexmit)) {
    core_.block_tx(t.self.slot);
  }
  transmit(t, now);
}

// Zero-window probing (§4.9; Linux tcp_probe_timer, tcp_write_wakeup).
void TcpEngine::on_persist(Tcb& t, Time now) {
  const Counters& k = t.sndq.counters();
  if (k.packets_out != 0 || t.sndq.nxt() == t.sndq.end()) {
    // Linux tcp_send_probe0: the probe timer is not needed any more; the
    // probing backoff ends with it.
    t.probes_out = 0;
    t.backoff = 0;
    sync_timers(t, now);
    return;
  }
  // Linux tcp_probe_timer: an orphan whose backed-off RTO reached rto_max
  // gives up once backoff reaches its retry limit.
  const std::uint8_t limit = retry_limit(t);
  if (t.probes_out >= limit ||
      (t.orphan && cfg_.orphan_retries && t.rtt.rto_backed_off(t.backoff) >= cfg_.rto_max &&
       t.backoff >= limit)) {
    abort_timed_out(t, now);
    return;
  }
  const std::uint64_t una = t.sndq.una(), nxt = t.sndq.nxt(), end = t.sndq.end();
  const std::uint64_t wnd_end = una + t.snd_wnd;
  const std::uint64_t usable = wnd_end > nxt ? wnd_end - nxt : 0;
  if (core_.can_transmit()) {
    if (usable > 0) {
      // The sender SWS override (RFC 9293 §3.8.6.2.1): what the window takes.
      const auto len = static_cast<std::uint32_t>(
          std::min({usable, end - nxt, std::uint64_t{mss_now(t)}}));
      (void)send_new_data(t, now, len, t.fin_queued && len == end - nxt);
    } else {
      SegOut o;
      o.seq = t.snd_una() - 1;  // Linux tcp_xmit_probe_skb
      o.flags = wire::tcp_ack;
      o.kind = TxKind::zwp;
      (void)send_segment(t, now, o);
      ++core_.stats().TcpExtTCPWinProbe;
    }
  } else {
    core_.block_tx(t.self.slot);
  }
  if (t.probes_out < 0xff) {
    ++t.probes_out;
  }
  if (t.backoff < cfg_.data_retries) {
    ++t.backoff;
  }
  RecoveryCtx c = rctx(t, now);
  t.recovery.on_xmit_timer(c, XmitTimer::persist);
  RecoveryCtx c2 = rctx(t, now);
  t.recovery.on_burst_end(c2);
  sync_timers(t, now);
}

// §4.8: data_retries, or for an orphan (closed by the application) the
// orphan_retries rule of Linux tcp_orphan_retries: the configured count; 0
// if a soft error is pending and the backed-off RTO reached rto_max; then 0
// becomes 8 while the RTO is below rto_max ("alive").
std::uint8_t TcpEngine::retry_limit(const Tcb& t) const {
  if (!t.orphan || !cfg_.orphan_retries) {
    return cfg_.data_retries;
  }
  const bool alive = t.rtt.rto_backed_off(t.backoff) < cfg_.rto_max;
  std::uint8_t r = *cfg_.orphan_retries;
  if (t.soft_error && !alive) {
    r = 0;
  }
  if (r == 0 && alive) {
    r = 8;
  }
  return r;
}

// Retries exhausted (§4.8): RST if synchronized, then CLOSED with the soft
// error or timed_out (Linux tcp_write_err).
void TcpEngine::abort_timed_out(Tcb& t, Time now) {
  ++core_.stats().TcpExtTCPAbortOnTimeout;
  if (t.synchronized()) {
    send_rst(t, now);
  }
  close_conn(t, CloseCause::timed_out, t.soft_error.value_or(Error::timed_out));
}

}  // namespace utcp
