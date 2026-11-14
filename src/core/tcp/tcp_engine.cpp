// TCP engine: slots, connection life cycle, listeners, events, traces and
// checks (DESIGN §4.1-4.3, §4.12, §10).
#include "core/tcp/tcp_engine.hpp"

#include <algorithm>
#include <functional>

#include "core/stack_impl.hpp"
#include "utcp/check.hpp"

namespace utcp {

TcpEngine::TcpEngine(StackCore& core)
    : core_(core), cfg_(core.config().tcp), conns_(core.hash_key()), tw_(core.hash_key()) {}

TcpEngine::~TcpEngine() = default;

// --- Slots.

Tcb* TcpEngine::find(Handle h) {
  if (h.proto != Proto::tcp || h.slot >= slots_.size()) {
    return nullptr;
  }
  Slot& s = slots_[h.slot];
  if (!s.tcb || s.gen != h.gen || !s.tcb->app_holds) {
    return nullptr;
  }
  return s.tcb.get();
}

const Tcb* TcpEngine::find(Handle h) const {
  return const_cast<TcpEngine*>(this)->find(h);  // NOLINT: same lookup, no mutation
}

SockOpts TcpEngine::resolve(const TcpSocketOptions& o) const {
  SockOpts r;
  r.nodelay = o.nodelay.value_or(cfg_.nodelay);
  r.snd_buf = o.snd_buf;
  r.rcv_buf = o.rcv_buf;
  r.cc = o.cc.value_or(cfg_.cc);
  r.mss_clamp = o.mss_clamp ? o.mss_clamp : cfg_.mss_clamp;
  return r;
}

Tcb* TcpEngine::alloc_tcb(const SockOpts& opts, std::uint32_t /*rcv_buf_hint*/) {
  if (!core_.reserve_slot()) {
    return nullptr;
  }
  std::uint32_t slot = 0;
  if (!free_slots_.empty()) {
    // §4.3: the lowest free index, so slots depend only on input history.
    std::pop_heap(free_slots_.begin(), free_slots_.end(), std::greater<>{});
    slot = free_slots_.back();
    free_slots_.pop_back();
  } else {
    slot = static_cast<std::uint32_t>(slots_.size());
    slots_.emplace_back();
  }
  const std::uint32_t snd_buf = opts.snd_buf.value_or(cfg_.snd_buf_init);
  const std::uint32_t rcv_buf = std::max(opts.rcv_buf.value_or(cfg_.rcv_buf_init), 1u);
  const bool rcv_autotune = !opts.rcv_buf && cfg_.rcv_buf_init < cfg_.rcv_buf_max;
  Slot& s = slots_[slot];
  s.tcb = std::make_unique<Tcb>(cfg_, core_.chunks(), snd_buf, rcv_buf, rcv_autotune);
  Tcb& t = *s.tcb;
  t.self = Handle{slot, s.gen, Proto::tcp};
  t.conn_id = next_conn_id_++;
  t.opts = opts;
  cc_select(t.cc, opts.cc);
  // §4.5, rcv_wscale row of §3.9: the configured shift, but never one the
  // buffer cannot serve (RcvWindow needs rcv_buf >= min_rcv_buf(shift)).
  t.offered_wscale =
      cfg_.window_scaling ? std::min(effective_rcv_wscale(cfg_), max_rcv_wscale(rcv_buf)) : 0;
  t.adv_mss = static_cast<std::uint16_t>(core_.config().mtu - 40);
  if (opts.mss_clamp && *opts.mss_clamp < t.adv_mss) {
    t.adv_mss = std::max<std::uint16_t>(*opts.mss_clamp, 1);  // TCP_MAXSEG clamps the advertised MSS
  }
  TimerHeap& th = core_.timers();
  t.t_xmit = th.create(slot, TimerKind::xmit);
  t.t_delack = th.create(slot, TimerKind::delack);
  t.t_pace = th.create(slot, TimerKind::pace);
  t.t_fin_wait2 = th.create(slot, TimerKind::fin_wait2);
  ++live_;
  return &t;
}

void TcpEngine::free_tcb(Tcb& t) {
  const std::uint32_t slot = t.self.slot;
  if (t.in_conn_table) {
    conns_.erase(t.tuple);
    t.in_conn_table = false;
  }
  detach_from_listener(t);
  if (t.listen) {
    listener_remove(t.tuple.local.port);
  }
  TimerHeap& th = core_.timers();
  for (const TimerId id : {t.t_xmit, t.t_delack, t.t_pace, t.t_fin_wait2}) {
    th.destroy(id);
  }
  // §3.4: a freed connection leaves the blocked FIFO, and its datagrams
  // still queued no longer count for the slot's next user.
  core_.unblock_tx(slot);
  core_.release_tx_owner(slot);
  core_.drop_events(t.self);
  Slot& s = slots_[slot];
  s.tcb.reset();
  ++s.gen;
  free_slots_.push_back(slot);
  std::push_heap(free_slots_.begin(), free_slots_.end(), std::greater<>{});
  core_.release_slot();
  --live_;
  wake_chunk_waiters();  // its buffers went back to the pool
}

// --- Listeners (§4.3): a sorted vector of (port, slot).

void TcpEngine::listener_add(std::uint16_t port, std::uint32_t slot) {
  const auto it = std::ranges::lower_bound(listeners_, port, {},
                                           &std::pair<std::uint16_t, std::uint32_t>::first);
  listeners_.insert(it, {port, slot});
}

void TcpEngine::listener_remove(std::uint16_t port) {
  const auto it = std::ranges::lower_bound(listeners_, port, {},
                                           &std::pair<std::uint16_t, std::uint32_t>::first);
  if (it != listeners_.end() && it->first == port) {
    listeners_.erase(it);
  }
}

std::optional<std::uint32_t> TcpEngine::listener_for(std::uint16_t port) const {
  const auto it = std::ranges::lower_bound(listeners_, port, {},
                                           &std::pair<std::uint16_t, std::uint32_t>::first);
  if (it != listeners_.end() && it->first == port) {
    return it->second;
  }
  return std::nullopt;
}

void TcpEngine::detach_from_listener(Tcb& t) {
  if (!t.listener) {
    return;
  }
  const std::uint32_t ls = *t.listener;
  t.listener.reset();
  if (ls >= slots_.size() || !slots_[ls].tcb || !slots_[ls].tcb->listen) {
    return;
  }
  ListenState& l = *slots_[ls].tcb->listen;
  const auto it = std::ranges::find(l.accept_q, t.self.slot);
  if (it != l.accept_q.end()) {
    l.accept_q.erase(it);
  } else {
    UTCP_CHECK(l.syn_children > 0);
    --l.syn_children;
  }
}

bool TcpEngine::tuple_in_use(const FourTuple& tuple) const {
  return conns_.find(tuple).has_value() || tw_.find(tuple).has_value();
}

bool TcpEngine::port_has_listener(std::uint16_t port) const {
  return listener_for(port).has_value();
}

// --- Life cycle.

void TcpEngine::set_state(Tcb& t, TcpState s, CloseCause cause) {
  if (t.state == s) {
    return;
  }
  const TcpState old = t.state;
  t.state = s;
  if (s == TcpState::closed) {
    // Linux tcp_set_state / tcp_done MIB accounting.
    if (old == TcpState::established || old == TcpState::close_wait) {
      ++core_.stats().TcpEstabResets;
    }
    if (old == TcpState::syn_sent || old == TcpState::syn_received) {
      ++core_.stats().TcpAttemptFails;
    }
  }
  if (core_.tracing(TraceKind::state)) {
    TraceEvent e = trace_base(t, TraceKind::state);
    e.cause = s == TcpState::closed ? cause : CloseCause::none;
    core_.trace(e);
  }
}

void TcpEngine::close_conn(Tcb& t, CloseCause cause, std::optional<Error> err) {
  if (err && !t.error) {
    t.error = err;
  }
  if (t.state != TcpState::closed) {
    set_state(t, TcpState::closed, cause);
  }
  if (t.in_conn_table) {
    conns_.erase(t.tuple);
    t.in_conn_table = false;
  }
  TimerHeap& th = core_.timers();
  for (const TimerId id : {t.t_xmit, t.t_delack, t.t_pace, t.t_fin_wait2}) {
    th.cancel(id);
  }
  t.xmit_kind = XmitTimer::none;
  core_.unblock_tx(t.self.slot);
  chrono_stop(t, t.chrono.type, core_.now());
  t.chrono.type = ChronoType::none;
  if (!t.app_holds) {
    free_tcb(t);
    return;
  }
  // The application still holds the handle: the TCB stays (unread data stays
  // readable, §3.5) until tcp_close. Nothing more can be sent, so the send
  // side is released now, as Linux tcp_reset / tcp_done_with_error purge the
  // write queue: the ChunkPool is shared, and a dead connection whose
  // application is slow to close must not hold up to snd_buf_max of it.
  t.sndq.purge();
  wake_chunk_waiters();
  std::uint16_t ev = 0;
  if (!t.closed_event_sent) {
    ev |= ev_closed;
    t.closed_event_sent = true;
  }
  if (t.error) {
    ev |= ev_error;
  }
  raise(t, ev);
}

void TcpEngine::enter_time_wait(Tcb& t) {
  // §4.3: the TCB is replaced by a compact entry.
  set_state(t, TcpState::time_wait);
  TimeWaitEntry e;
  e.tuple = t.tuple;
  e.ts_recent_stamp = t.ts_recent_stamp;
  if (t.last_oow_ack) {
    e.last_oow_ack = *t.last_oow_ack;
    e.has_oow_ack = true;
  }
  e.snd_nxt = t.snd_nxt();
  e.rcv_nxt = t.rcv_nxt();
  e.rcv_wnd = t.rcv_wnd;
  e.ts_recent = t.ts_recent;
  e.ts_offset = t.ts_offset;
  e.conn_id = t.conn_id;
  e.rcv_wscale = t.rcv_wscale;
  e.ts_ok = t.ts_ok;
  if (t.in_conn_table) {
    conns_.erase(t.tuple);
    t.in_conn_table = false;
  }
  tw_.insert(e, core_.timers(), core_.now() + cfg_.time_wait);
  TimerHeap& th = core_.timers();
  for (const TimerId id : {t.t_xmit, t.t_delack, t.t_pace, t.t_fin_wait2}) {
    th.cancel(id);
  }
  t.xmit_kind = XmitTimer::none;
  core_.unblock_tx(t.self.slot);
  chrono_stop(t, t.chrono.type, core_.now());
  t.chrono.type = ChronoType::none;
  if (!t.app_holds) {
    free_tcb(t);
    return;
  }
  // The application's socket is done (as Linux tcp_done after tcp_time_wait);
  // it keeps unread data until tcp_close.
  if (!t.closed_event_sent) {
    t.closed_event_sent = true;
    raise(t, ev_closed);
  }
}

void TcpEngine::raise(Tcb& t, std::uint16_t ev) {
  if (ev != 0 && t.app_holds) {
    core_.raise_event(t.self, ev);
  }
}

// --- Helpers.

std::uint32_t TcpEngine::ts_now(const Tcb& t, Time now) const {
  // §3.1: the TCP timestamp clock is 1 ms ticks plus a per-connection offset.
  const auto ms = static_cast<std::uint64_t>(now.ns / 1'000'000);
  return static_cast<std::uint32_t>(ms) + t.ts_offset;
}

void TcpEngine::update_mss(Tcb& t) {
  // §4.13 (Linux tcp_mtu_to_mss): min(peer MSS, PMTU - 40, TCP_MAXSEG),
  // floored at TCP_MIN_SND_MSS (48) and min_snd_mss before the 12 bytes of
  // the timestamp option are taken off, so the floor leaves 36 payload bytes
  // with timestamps.
  std::uint32_t m = std::min<std::uint32_t>(t.peer_mss, t.pmtu > 40 ? t.pmtu - 40u : 0u);
  if (t.opts.mss_clamp) {
    m = std::min<std::uint32_t>(m, *t.opts.mss_clamp);
  }
  m = std::max({m, std::uint32_t{48}, std::uint32_t{cfg_.min_snd_mss}});
  if (t.ts_ok) {
    m -= 12;
  }
  t.mss_cache = static_cast<std::uint16_t>(std::min<std::uint32_t>(m, 0xffff));
  t.cc_conn.mss = t.mss_cache;
}

RecoveryCtx TcpEngine::rctx(Tcb& t, Time now) {
  return RecoveryCtx{t.sndq,    t.cc_conn,          t.algo(), t.rtt,   cfg_,       now,
                     t.snd_wnd, core_.stats(),      t.sack_ok, t.backoff, t.rto_count};
}

void TcpEngine::refresh_cc(Tcb& t, Time now) {
  CcConn& c = t.cc_conn;
  c.mss = t.mss_cache;
  c.gso_max_size = cfg_.gso_max_size;
  c.rng = &core_.rng();
  c.lsndtime = t.lsndtime;
  c.wstamp = t.pacing_next;
  c.now = now;
  const Counters& k = t.sndq.counters();
  c.in_flight = packets_in_flight(k);
  c.packets_out = k.packets_out;
  c.ca_state = t.recovery.state();
  c.snd_una = t.sndq.una();
  c.snd_nxt = t.sndq.nxt();
  c.srtt = t.rtt.srtt();
  c.min_rtt = t.rtt.min_rtt();
}

// §10.1, Linux tcp_chrono_start/tcp_chrono_stop.
void TcpEngine::chrono_start(Tcb& t, ChronoType type, Time now) {
  if (type <= t.chrono.type) {
    return;
  }
  if (t.chrono.type != ChronoType::none) {
    t.chrono.total[static_cast<std::size_t>(t.chrono.type)] += now - t.chrono.start;
  }
  t.chrono.type = type;
  t.chrono.start = now;
}

void TcpEngine::chrono_stop(Tcb& t, ChronoType type, Time now) {
  const bool queues_empty = t.sndq.end() == t.sndq.una() && t.sndq.segs().empty();
  ChronoType next = t.chrono.type;
  if (queues_empty) {
    next = ChronoType::none;
  } else if (type == t.chrono.type) {
    next = ChronoType::busy;
  }
  if (next == t.chrono.type) {
    return;
  }
  if (t.chrono.type != ChronoType::none) {
    t.chrono.total[static_cast<std::size_t>(t.chrono.type)] += now - t.chrono.start;
  }
  t.chrono.type = next;
  t.chrono.start = now;
}

// --- Traces (§10.2).

TraceEvent TcpEngine::trace_base(const Tcb& t, TraceKind k) const {
  TraceEvent e;
  e.t = core_.now();
  e.conn_id = t.conn_id;
  e.tuple = t.tuple;
  e.kind = k;
  e.state = t.state;
  e.ca = t.recovery.state();
  e.mss = t.mss_cache;
  e.cwnd = t.cc_conn.cwnd;
  e.ssthresh = t.cc_conn.ssthresh;
  const Counters& c = t.sndq.counters();
  e.in_flight = packets_in_flight(c);
  e.snd_wnd = t.snd_wnd;
  e.sacked_out = c.sacked_out;
  e.lost_out = c.lost_out;
  e.retrans_out = c.retrans_out;
  e.srtt_ns = t.rtt.srtt().count();
  e.rttvar_ns = t.rtt.rttvar().count();
  e.rto_ns = t.rtt.rto_backed_off(t.backoff).count();
  e.delivered = t.rate.delivered;
  e.pacing_rate = t.cc_conn.pacing_rate;
  e.snd_una_off = t.sndq.una();
  e.snd_nxt_off = t.sndq.nxt();
  return e;
}

void TcpEngine::trace_tx(const Tcb& t, TxKind kind, Seq32 seq, Seq32 ack, std::uint32_t len,
                         std::uint32_t wnd, std::uint16_t flags) {
  if (!core_.tracing(TraceKind::tx)) {
    return;
  }
  TraceEvent e = trace_base(t, TraceKind::tx);
  e.tx = kind;
  e.seq = seq.raw();
  e.ack = ack.raw();
  e.len = len;
  e.wnd = wnd;
  e.flags = flags;
  core_.trace(e);
}

void TcpEngine::trace_timer(const Tcb& t, TraceTimer timer, TimerOp op) {
  if (!core_.tracing(TraceKind::timer)) {
    return;
  }
  TraceEvent e = trace_base(t, TraceKind::timer);
  e.timer = timer;
  e.timer_op = op;
  core_.trace(e);
}

void TcpEngine::trace_drop(const Tcb* t, const InSeg& s) {
  if (t == nullptr || !core_.tracing(TraceKind::drop)) {
    return;
  }
  TraceEvent e = trace_base(*t, TraceKind::drop);
  e.seq = s.seq.raw();
  e.ack = s.ack.raw();
  e.len = s.plen;
  e.wnd = s.v->h.window;
  e.flags = s.flags;
  core_.trace(e);
}

void TcpEngine::on_tx_space(Time now, std::uint32_t slot) {
  if (slot >= slots_.size() || !slots_[slot].tcb) {
    return;
  }
  Tcb& t = at(slot);
  if (t.state == TcpState::closed || t.state == TcpState::time_wait || t.listen) {
    return;
  }
  transmit(t, now);
}

// §3.5 ev_writable for a tcp_send the ChunkPool refused (Linux
// sk_stream_wait_memory / sk_stream_write_space): the connection may have
// nothing in flight, so no ACK would wake it.
void TcpEngine::wait_for_chunks(Tcb& t) {
  if (std::ranges::find(chunk_waiters_, t.self) == chunk_waiters_.end()) {
    chunk_waiters_.push_back(t.self);
  }
}

void TcpEngine::wake_chunk_waiters() {
  if (chunk_waiters_.empty()) {
    return;
  }
  const ChunkPool& pool = core_.chunks();
  if (pool.in_use() >= pool.limit()) {
    return;
  }
  std::vector<Handle> waiters;
  waiters.swap(chunk_waiters_);
  for (const Handle h : waiters) {
    Tcb* t = find(h);
    if (t == nullptr || !t->send_blocked || t->app_write_shut || t->fin_queued ||
        t->state == TcpState::closed || t->state == TcpState::time_wait ||
        t->sndq.free_space() == 0) {
      continue;
    }
    t->send_blocked = false;
    raise(*t, ev_writable);
  }
}

// --- Checks.

void Tcb::check_invariants() const {
  sndq.check_invariants();
  rcvq.check_invariants();
  if (syn_acked) {
    UTCP_CHECK(!after(snd_una(), snd_nxt()));
  }
  UTCP_CHECK(rwin.rcv_adv() >= rcvq.contiguous_end() || !have_irs);
  UTCP_CHECK(!fin_rcvd || rcvq.fin_reached());
}

TcpUsage TcpEngine::usage() const {
  TcpUsage u;
  u.slots = live_;
  u.time_wait_entries = static_cast<std::uint32_t>(tw_.size());
  const TimerHeap& th = core_.timers();
  u.timers_armed = u.time_wait_entries;  // every entry's timer runs until it expires
  for (const Slot& s : slots_) {
    if (!s.tcb) {
      continue;
    }
    const Tcb& t = *s.tcb;
    for (const TimerId id : {t.t_xmit, t.t_delack, t.t_pace, t.t_fin_wait2}) {
      u.timers_armed += th.armed(id) ? 1u : 0u;
    }
    u.chunks_held += t.rcvq.chunks_held() + t.sndq.chunks_held();
  }
  return u;
}

void TcpEngine::check_invariants() const {
  conns_.check_invariants();
  tw_.check_invariants(core_.timers());
  std::uint32_t live = 0;
  std::size_t in_table = 0;
  for (std::size_t i = 0; i < slots_.size(); ++i) {
    const Slot& s = slots_[i];
    if (!s.tcb) {
      continue;
    }
    ++live;
    const Tcb& t = *s.tcb;
    UTCP_CHECK(t.self.slot == i);
    if (t.in_conn_table) {
      ++in_table;
      const auto f = conns_.find(t.tuple);
      UTCP_CHECK(f && *f == i);
    }
    if (t.listen) {
      UTCP_CHECK(listener_for(t.tuple.local.port) == i);
    }
    UTCP_CHECK(t.state != TcpState::closed || !t.in_conn_table);
    if (t.state == TcpState::closed || t.state == TcpState::time_wait) {
      // Kept only because the application holds the handle (close_conn,
      // enter_time_wait): no connection timer runs, the slot is not waiting
      // in the blocked FIFO (§3.4), and the send side is released.
      for (const TimerId id : {t.t_xmit, t.t_delack, t.t_pace, t.t_fin_wait2}) {
        UTCP_CHECK(!core_.timers().armed(id));
      }
      UTCP_CHECK(!core_.blocked().contains(static_cast<std::uint32_t>(i)));
      UTCP_CHECK(t.sndq.segs().empty() && t.sndq.chunks_held() == 0);
    }
    t.check_invariants();
  }
  UTCP_CHECK(live == live_);
  UTCP_CHECK(in_table == conns_.size());
  UTCP_CHECK(std::ranges::is_sorted(listeners_));
}

}  // namespace utcp
