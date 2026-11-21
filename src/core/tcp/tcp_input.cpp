// Segment arrival (DESIGN §4.4; RFC 9293 §3.10.7 with RFC 5961, RFC 7323 and
// the Linux deviations of §4.4).
#include <algorithm>
#include <array>

#include "core/stack_impl.hpp"
#include "core/tcp/ack_pipeline.hpp"
#include "core/tcp/tcp_engine.hpp"
#include "utcp/check.hpp"

namespace utcp {

namespace {

using namespace wire;

constexpr Duration paws_24days = std::chrono::hours{24 * 24};
constexpr Duration paws_msl = std::chrono::seconds{60};  // Linux TCP_PAWS_MSL
// Linux TCP_TIMEOUT_MIN (2 jiffies at HZ = 1000): the SYN timer after an
// unacceptable ACK in SYN-SENT.
constexpr Duration syn_rearm_delay = std::chrono::milliseconds{2};

// RFC 7323 §2.3: a shift above 14 is used as 14.
std::uint8_t clamp_wscale(std::uint8_t s) { return std::min<std::uint8_t>(s, max_wscale); }

}  // namespace

bool TcpEngine::alive(std::uint32_t slot, std::uint32_t gen) const {
  if (slot >= slots_.size() || slots_[slot].gen != gen || !slots_[slot].tcb) {
    return false;
  }
  const TcpState st = slots_[slot].tcb->state;
  return st != TcpState::closed && st != TcpState::time_wait;
}

void TcpEngine::on_segment(Time now, const wire::Ipv4Header& ip, const wire::TcpView& seg,
                           RxMeta meta) {
  const FourTuple tuple{Endpoint{ip.dst, seg.h.dport}, Endpoint{ip.src, seg.h.sport}};
  const auto slot = conns_.find(tuple);
  if (meta.gso_size != 0) {
    const Tcb* t = slot ? &at(*slot) : nullptr;
    // A normal in-order run can be inserted once. Preserve logical segment
    // boundaries where they affect acceptability, DSACK, FIN, or admission to
    // a chunk-limited queue. Keep the existing RFC 9293 processing in that case.
    if (t == nullptr || t->state != TcpState::established || t->app_read_shut ||
        seg.h.seq != t->rcv_nxt() || seg.payload.size() > t->rcv_window() ||
        (seg.h.flags & tcp_fin) != 0 ||
        (t->stream ? !t->stream->rcvq.ooo_ranges().empty() ||
                     !t->stream->rcvq.can_insert_in_order(seg.payload.size())
                   : !RecvBuffer(t->rwin.rcv_buf(), core_.chunks()).can_insert_in_order(seg.payload.size()))) {
      const std::uint16_t stride = meta.gso_size;
      meta.gso_size = 0;
      wire::TcpView slice = seg;
      std::size_t offset = 0;
      while (offset < seg.payload.size()) {
        const std::size_t len = std::min<std::size_t>(stride, seg.payload.size() - offset);
        slice.h.seq = seg.h.seq + static_cast<std::uint32_t>(offset);
        slice.h.flags = seg.h.flags;
        slice.payload = seg.payload.subspan(offset, len);
        offset += len;
        if (offset < seg.payload.size()) {
          slice.h.flags = static_cast<std::uint16_t>(slice.h.flags & ~(tcp_fin | tcp_psh));
        }
        on_segment(now, ip, slice, meta);
      }
      return;
    }
  }

  InSeg s;
  s.now = now;
  s.v = &seg;
  s.meta = meta;
  s.seq = seg.h.seq;
  s.ack = seg.h.ack;
  s.flags = seg.h.flags;
  s.plen = static_cast<std::uint32_t>(seg.payload.size());
  s.len = s.plen + (s.has(tcp_syn) ? 1u : 0u) + (s.has(tcp_fin) ? 1u : 0u);

  if (slot) {
    Tcb& t = at(*slot);
    const auto segments = meta.segments(s.plen);
    t.ctr.segs_in += segments;
    if (s.plen > 0) {
      t.ctr.data_segs_in += segments;
    }
    if (core_.tracing(TraceKind::rx)) {
      TraceEvent e = trace_base(t, TraceKind::rx);
      e.seq = s.seq.raw();
      e.ack = s.ack.raw();
      e.len = s.plen;
      e.wnd = seg.h.window;
      e.flags = s.flags;
      core_.trace(e);
    }
    if (t.state == TcpState::syn_sent) {
      syn_sent_input(t, s);
    } else {
      sync_input(t, s);
    }
    wake_chunk_waiters();  // ACKed or discarded data freed chunks
    return;
  }
  if (const auto index = tw_.find(tuple)) {
    time_wait_input(*index, s);
    return;
  }
  if (const auto l = listener_for(tuple.local.port)) {
    listen_input(at(*l), tuple, s);
    return;
  }
  closed_input(tuple, s);
}

// RFC 9293 §3.10.7.1: no connection. An RST is dropped; anything else gets
// an RST.
void TcpEngine::closed_input(const FourTuple& tuple, const InSeg& s) {
  if (s.has(tcp_rst)) {
    return;
  }
  send_reset_reply(tuple, s);
}

// RFC 9293 §3.10.7.2.
void TcpEngine::listen_input(Tcb& l, const FourTuple& tuple, const InSeg& s,
                             std::optional<Seq32> iss) {
  if (s.has(tcp_rst)) {
    return;
  }
  if (s.has(tcp_ack)) {
    send_reset_reply(tuple, s);
    return;
  }
  if (!s.has(tcp_syn)) {
    return;
  }
  // Linux tcp_rcv_state_process (TCP_LISTEN): a SYN that also carries FIN is
  // dropped (SKB_DROP_REASON_TCP_FLAGS), before the queue checks.
  if (s.has(tcp_fin)) {
    return;
  }
  ListenState& ls = *l.listen;
  StackStats& st = core_.stats();
  // Linux tcp_conn_request: a full accept queue (sk_acceptq_is_full: more
  // than backlog) drops the SYN; so does a full SYN queue.
  if (ls.accept_q.size() > ls.backlog) {
    ++st.TcpExtListenOverflows;
    ++st.TcpExtListenDrops;
    return;
  }
  if (ls.syn_children >= std::max<std::uint32_t>(ls.backlog, 1)) {
    ++st.TcpExtListenDrops;
    return;
  }
  const std::uint32_t lslot = l.self.slot;
  const SockOpts opts = l.opts;
  Tcb* c = alloc_tcb(opts);
  if (c == nullptr) {
    ++st.TcpExtListenDrops;
    return;
  }
  Tcb& t = *c;
  // alloc_tcb may have grown slots_: `l` is still valid (unique_ptr), `ls` too.
  t.tuple = tuple;
  t.passive = true;
  t.listener = lslot;
  t.pmtu = core_.pmtu(tuple.remote.addr);
  t.iss = iss ? *iss : (cfg_.test_isn ? Seq32{*cfg_.test_isn} : core_.isn(tuple));
  t.ts_offset = core_.ts_offset(tuple);
  t.ip_id = core_.ip_id_start(tuple);
  const bool inserted = conns_.insert(tuple, t.self.slot);
  UTCP_CHECK(inserted);
  t.in_conn_table = true;
  ++at(lslot).listen->syn_children;
  set_state(t, TcpState::syn_received);
  ++st.TcpPassiveOpens;
  take_peer_syn(t, s);
  send_syn(t, s.now);
  core_.timers().arm(t.t_xmit, s.now + t.rtt.rto_backed_off(0));
  t.xmit_kind = XmitTimer::rto;
  trace_timer(t, TraceTimer::rto, TimerOp::armed);
}

// The peer's SYN: IRS, options (§4.5), the receive side.
void TcpEngine::take_peer_syn(Tcb& t, const InSeg& s) {
  t.irs = s.seq;
  t.have_irs = true;
  negotiate(t, s.v->opt);
  if (t.ts_ok) {
    t.ts_recent = s.v->opt.ts->val;
    t.ts_recent_stamp = s.now;
    t.ts_recent_valid = true;
  }
  if (t.passive) {
    // RcvWindow::syn_window: a SYN-ACK to a SYN with timestamps rounds to
    // the MSS it will receive (tcp_openreq_init_rwin).
    t.syn_wnd = t.rwin.syn_window(
        static_cast<std::uint16_t>(t.ts_ok ? t.adv_mss - 12 : t.adv_mss));
  }
  // RFC 7323 §2.2: the window of a SYN is never scaled.
  t.snd_wnd = s.v->h.window;
  t.max_snd_wnd = t.snd_wnd;
  t.snd_wl1 = s.seq;
  t.snd_wl2 = s.ack;
  t.rwin.on_established(t.rcv_wscale, t.adv_mss, std::uint64_t{t.syn_wnd});
  t.rcv_wnd = t.syn_wnd;
  t.ackp.init(t.adv_mss, t.mss_cache, t.syn_wnd);
}

// §4.5: what both SYNs carried decides.
void TcpEngine::negotiate(Tcb& t, const wire::TcpOptions& peer) {
  // RFC 9293 §3.7.1: no MSS option means 536; MSS 0 is treated the same
  // (Linux tcp_parse_options ignores it).
  t.peer_mss = peer.mss && *peer.mss != 0 ? *peer.mss : cfg_.default_snd_mss;
  t.ws_ok = cfg_.window_scaling && peer.wscale.has_value();
  t.snd_wscale = t.ws_ok ? clamp_wscale(*peer.wscale) : 0;
  t.rcv_wscale = t.ws_ok ? t.offered_wscale : 0;
  t.ts_ok = cfg_.timestamps && peer.ts.has_value();
  t.sack_ok = cfg_.sack && peer.sack_permitted;
  if (t.stream) t.stream->sndq.set_sack_ok(t.sack_ok);
  update_mss(t);
}

std::uint32_t TcpEngine::initial_window(const Tcb& t) const {
  if (cfg_.initial_cwnd) {
    return *cfg_.initial_cwnd;
  }
  // RFC 5681 §3.1 by SMSS.
  return t.mss_cache > 2190 ? 2u : t.mss_cache > 1095 ? 3u : 4u;
}

// Install the negotiated sender model, including for a lazy passive socket.
void TcpEngine::init_sender(Tcb& t, Time now) {
  // IW (RFC 5681 §3.1; Linux tcp_init_transfer).
  const bool syn_loss = cfg_.iw_after_syn_loss == IwAfterSynLoss::after_any ? t.syn_tries > 1
                                                                             : t.syn_tries > 2;
  CcConn initial;
  CcConn& c = t.stream ? t.stream->cc_conn : initial;
  c.cwnd = syn_loss ? 1u : initial_window(t);
  c.ssthresh = cfg_.initial_ssthresh;
  // Linux counts the SYN via tcp_ack/tcp_rate_gen on active open. The
  // passive SYN-ACK is credited directly in TCP_SYN_RECV. Neither control
  // segment carries the data snapshot needed for a bandwidth record.
  ++t.rate.delivered;
  if (!t.passive) {
    (void)rate_gen(t.rate, {}, 1, 0, 1, false, t.rtt.min_rtt(), Duration{-1}, false, now);
  }
  refresh_cc(t, now, c);
  c.delivered = t.rate.delivered;
  c.delivered_time = t.rate.delivered_time;
  t.algo().init(c);
  t.rate.app_limited = c.app_limited;
  if (!t.algo().has_cong_control()) {
    c.pacing_rate = pacing_rate_for(c, c.packets_out, cfg_);
  }
  if (!t.stream) {
    t.initial_cc = {c.cwnd, c.ssthresh, c.pacing_rate, c.pacing_needed};
  }
  t.lsndtime = now;
  t.backoff = 0;
  t.rto_count = 0;
  if (t.stream) t.stream->retrans_stamp.reset();
}

// Our SYN (or SYN-ACK) was acknowledged: ESTABLISHED (§4.8 handshake RTT,
// IW after SYN loss).
void TcpEngine::handshake_done(Tcb& t, const InSeg& s) {
  const Time now = s.now;
  t.syn_acked = true;
  // Handshake RTT sample: the SYN is not a TxSeg (§3.2), so the engine takes
  // it (Karn: only from a SYN sent once, else from TSecr).
  std::optional<Duration> sample;
  if (t.syn_tries == 1) {
    sample = now - t.syn_last_tx;
  } else if (t.ts_ok && s.v->opt.ts && s.v->opt.ts->ecr != 0) {
    const std::uint32_t d = ts_now(t, now) - s.v->opt.ts->ecr;
    if (d < 2'147'483u) {
      sample = std::chrono::milliseconds{std::max(d, 1u)};
    }
  }
  if (sample) {
    t.rtt.on_srtt_sample(*sample, 0, 0);
    t.rtt.on_min_rtt_sample(*sample, false, now);
    t.ackp.set_srtt(t.rtt.srtt());
  } else if (t.syn_tries > 1) {
    t.rtt.reset_after_syn_rexmit();  // RFC 6298 §5.7
  }
  observe_cc(t, TraceTrigger::handshake, &s, [&](RecoveryTransition) {
    init_sender(t, now);
  });
  // The handshake's ACK is an acceptable ACK (§4.7): the peer answered, so a
  // soft error stored in a SYN state (an ICMP unreachable for an earlier
  // SYN) is no longer the connection's error (Linux tcp_ack, reached from
  // tcp_rcv_synsent_state_process and tcp_rcv_state_process, clears
  // sk_err_soft and icsk_probes_out).
  t.soft_error.reset();
  t.probes_out = 0;
  core_.timers().cancel(t.t_xmit);
  t.xmit_kind = XmitTimer::none;
  if (sample) trace_rtt(t, s, TraceTrigger::handshake, *sample);
  set_state(t, TcpState::established);
  if (t.passive) {
    if (t.listener) {
      Tcb& l = at(*t.listener);
      ListenState& ls = *l.listen;
      UTCP_CHECK(ls.syn_children > 0);
      --ls.syn_children;
      ls.accept_q.push_back(t.self.slot);
      raise(l, ev_acceptable);
    }
  } else {
    raise(t, ev_connected | ev_writable);
  }
  // shutdown(write) or close in a SYN state took effect now (§3.5).
  if (t.app_write_shut && !t.fin_queued) {
    t.fin_queued = true;
    set_state(t, TcpState::fin_wait_1);
  }
}

// RFC 9293 §3.10.7.3.
void TcpEngine::syn_sent_input(Tcb& t, const InSeg& s) {
  const Time now = s.now;
  bool ack_ok = false;
  if (s.has(tcp_ack)) {
    // SEG.ACK =< ISS or SEG.ACK > SND.NXT: unacceptable.
    if (s.ack != t.iss + 1) {
      if (!s.has(tcp_rst)) {
        send_reset_reply(t.tuple, s);
      }
      // As built, Linux tcp_rcv_synsent_state_process ("Previous FIN/ACK or
      // RST/ACK might be ignored"): before any SYN retransmission, the SYN
      // goes again after syn_rearm_delay instead of the full RTO. The usual
      // case is a peer holding a stale connection on the reused tuple: it
      // answers our SYN with a challenge ACK, our RST frees it, and the next
      // SYN can complete at once. The early expiry counts as a retry.
      if (t.rto_count == 0) {
        core_.timers().arm(t.t_xmit, now + syn_rearm_delay);
        t.xmit_kind = XmitTimer::rto;
        trace_timer(t, TraceTimer::rto, TimerOp::armed);
      }
      trace_drop(&t, s);
      return;
    }
    ack_ok = true;
    // TSecr validation (Linux tcp_rcv_synsent_state_process,
    // PAWSActiveRejected): a nonzero TSecr must echo a TSval sent between
    // our first SYN and now, else the segment is an old duplicate: RST
    // <SEQ=SEG.ACK> (none to an RST) and drop, still in SYN-SENT. Only if
    // our SYN offered timestamps: otherwise the option is ignored, as Linux
    // tcp_parse_options does in SYN-SENT with tcp_timestamps off.
    if (cfg_.timestamps && s.v->opt.ts && s.v->opt.ts->ecr != 0) {
      const std::uint32_t lo = ts_now(t, t.syn_first_tx);
      if (s.v->opt.ts->ecr - lo > ts_now(t, s.now) - lo) {
        ++core_.stats().TcpExtPAWSActive;
        if (!s.has(tcp_rst)) {
          send_reset_reply(t.tuple, s);
        }
        trace_drop(&t, s);
        return;
      }
    }
  }
  if (s.has(tcp_rst)) {
    if (ack_ok) {
      close_conn(t, CloseCause::refused, Error::connection_refused);
    } else {
      trace_drop(&t, s);
    }
    return;
  }
  if (!s.has(tcp_syn)) {
    trace_drop(&t, s);
    return;
  }
  take_peer_syn(t, s);
  if (ack_ok) {
    // SYN-ACK. Data on it is not acknowledged (no TCP Fast Open): RCV.NXT
    // is IRS + 1.
    handshake_done(t, s);
    t.ackp.ack_now();
    transmit(t, now);
    return;
  }
  // Simultaneous open: SYN-RECEIVED, and our SYN goes again as a SYN-ACK.
  set_state(t, TcpState::syn_received);
  send_syn(t, now, false);
}

bool TcpEngine::paws_reject(const Tcb& t, const InSeg& s) const {
  if (!t.ts_ok || !s.v->opt.ts || !t.ts_recent_valid || s.has(tcp_rst)) {
    return false;
  }
  // RFC 7323 §5.5: TS.Recent older than 24 days is invalid.
  if (s.now - t.ts_recent_stamp > paws_24days) {
    return false;
  }
  const auto older = static_cast<std::int32_t>(t.ts_recent - s.v->opt.ts->val);
  if (cfg_.paws_disordered_ack == PawsDisorderedAck::strict) {
    return older > 0;  // RFC 7323 §5.3 R1: SEG.TSval < TS.Recent
  }
  if (older <= 1) {  // Linux TCP_PAWS_WINDOW
    return false;
  }
  // Linux tcp_disordered_ack: a pure duplicate ACK at RCV.NXT, reordered
  // behind newer segments, that would not update the window
  // (tcp_may_update_window) is kept if its TSval lies within the replay
  // window, the backed-off RTO at 1200 ticks per second (tcp_tsval_replay).
  if (!s.has(tcp_ack) || s.has(tcp_syn) || s.len != 0 || s.seq != t.rcv_nxt() ||
      s.ack != t.snd_una()) {
    return true;
  }
  const std::uint32_t nwin = peer_window(t, s.v->h.window);
  const bool may_update_window =
      after(s.seq, t.snd_wl1) || (s.seq == t.snd_wl1 && (nwin > t.snd_wnd || nwin == 0));
  const auto rto_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          t.rtt.rto_backed_off(t.backoff))
                          .count();
  return may_update_window || static_cast<std::int64_t>(older) > rto_ms * 1200 / 1000;
}

bool TcpEngine::oow_allowed(std::optional<Time>& last, const InSeg& s, std::uint64_t& skipped,
                            bool exempt_data) {
  // Linux tcp_oow_rate_limited: data or FIN without SYN cannot be an ACK loop.
  if (exempt_data && s.len > 0 && !s.has(tcp_syn)) {
    return true;
  }
  if (last && s.now - *last < cfg_.oow_ack_interval) {
    ++skipped;
    return false;
  }
  last = s.now;
  return true;
}

// RFC 5961 §3.2, §4.2, §5.2, rate-limited per §7 whatever the segment
// carries (Linux tcp_send_challenge_ack calls __tcp_oow_rate_limited, which
// has no data exemption): an RST, SYN or bad ACK with payload is still a
// challenge, not a duplicate to acknowledge at once.
void TcpEngine::challenge_ack(Tcb& t, const InSeg& s) {
  StackStats& st = core_.stats();
  if (oow_allowed(t.last_oow_ack, s, st.TcpExtTCPACKSkippedChallenge, false)) {
    ++st.TcpExtTCPChallengeACK;
    send_ack(t, s.now, TxKind::challenge_ack);
  }
}

// An unacceptable segment (RFC 9293 §3.10.7.4 step 1): ACK it, with a
// D-SACK for payload below RCV.NXT (RFC 2883 §4; Linux tcp_send_dupack).
// SYN and FIN never produce a D-SACK block (§3.2).
void TcpEngine::dup_ack(Tcb& t, const InSeg& s, std::uint64_t& skipped) {
  if (!oow_allowed(t.last_oow_ack, s, skipped, true)) {
    return;
  }
  if (s.plen > 0 && t.sack_ok && cfg_.dsack) {
    const Seq32 data = s.seq + (s.has(tcp_syn) ? 1u : 0u);
    const std::int64_t off = unwrap(data, t.rcv_base(), t.rcv_nxt_off());
    const std::int64_t end = off + s.plen;
    const auto nxt = static_cast<std::int64_t>(t.rcv_nxt_off());
    if (off < nxt && end > 0) {
      const Range dup{static_cast<std::uint64_t>(std::max<std::int64_t>(off, 0)),
                      static_cast<std::uint64_t>(std::min(end, nxt))};
      activate_stream(t);
      t.stream->sackgen.on_duplicate(dup, t.stream->rcvq);
      ++core_.stats().TcpExtTCPDSACKOldSent;
    }
  }
  send_ack(t, s.now);
}

// RFC 9293 §3.10.7.4, synchronized states and SYN-RECEIVED.
void TcpEngine::sync_input(Tcb& t, const InSeg& s) {
  const Time now = s.now;
  const std::uint32_t slot = t.self.slot, gen = t.self.gen;
  StackStats& st = core_.stats();
  bool crossing = false, syn_rexmit = false;
  // Step 0 (§4.4): SYN-RECEIVED.
  if (t.state == TcpState::syn_received && !s.has(tcp_rst)) {
    // The peer retransmitted its SYN: our SYN-ACK was lost.
    syn_rexmit = t.passive && s.has(tcp_syn) && !s.has(tcp_ack) && s.seq == t.irs;
    // Crossing SYN-ACKs of a simultaneous open (Linux tcp_validate_incoming):
    // the peer's SYN-ACK repeats its SYN and acknowledges ours.
    crossing = !t.passive && s.has(tcp_syn) && s.has(tcp_ack) && s.seq == t.irs &&
               s.ack == t.snd_nxt();
  }
  const bool paws = !crossing && paws_reject(t, s);
  if (syn_rexmit && !paws) {
    // Only a SYN passing PAWS resends the SYN-ACK (Linux tcp_check_req,
    // inet_rtx_syn_ack), rate-limited; an older duplicate takes the PAWS
    // path below.
    if (oow_allowed(t.last_oow_ack, s, st.TcpExtTCPACKSkippedSynRecv, true)) {
      send_syn(t, now);
    }
    return;
  }
  // Step 1 (RFC 7323 §5.3 R1): PAWS. As Linux tcp_validate_incoming: a
  // SYN that fails it in a synchronized state gets the RFC 5961 §4.2
  // challenge ACK; under paws_disordered_ack = linux an old pure ACK (below
  // RCV.NXT) is dropped without a reply (PAWSOldAck), since reordered ACKs
  // are common; else the duplicate ACK of R1, through the limiter (§4.7).
  if (paws) {
    ++t.ctr.paws_drops;
    trace_drop(&t, s);
    if (s.has(tcp_syn) && t.state != TcpState::syn_received) {
      ++st.TcpExtTCPSYNChallenge;
      challenge_ack(t, s);
    } else if (cfg_.paws_disordered_ack == PawsDisorderedAck::linux && s.len == 0 &&
               before(s.seq, t.rcv_nxt())) {
      ++st.TcpExtPAWSOldAck;
    } else {
      ++st.TcpExtPAWSEstab;
      dup_ack(t, s, st.TcpExtTCPACKSkippedPAWS);
    }
    transmit(t, now);
    return;
  }
  // Step 2: acceptability against RCV.NXT and the advertised window.
  const Seq32 rcv_nxt = t.rcv_nxt();
  const std::uint32_t wnd = t.rcv_window();
  bool acceptable = false;
  bool window_drop = false;  // starts at RCV.NXT with a zero window (§4.4)
  if (crossing) {
    acceptable = true;
  } else if (s.len == 0) {
    acceptable = wnd == 0 ? s.seq == rcv_nxt
                          : before_eq(rcv_nxt, s.seq) && before(s.seq, rcv_nxt + wnd);
  } else if (wnd > 0) {
    const Seq32 last = s.seq + (s.len - 1);
    acceptable = (before_eq(rcv_nxt, s.seq) && before(s.seq, rcv_nxt + wnd)) ||
                 (before_eq(rcv_nxt, last) && before(last, rcv_nxt + wnd));
  } else if (s.seq == rcv_nxt) {
    // RFC 9293: with a zero window, valid ACKs and RSTs are still processed.
    acceptable = true;
    window_drop = true;
  }
  if (!acceptable) {
    if (s.has(tcp_rst)) {
      // Out of the window: dropped silently (RFC 5961 §3.2), unless it is
      // the RCV.NXT − 1 case of rst_exact.
      if (rst_exact(t, s)) {
        reset_input(t);
        return;
      }
      trace_drop(&t, s);
      return;
    }
    trace_drop(&t, s);
    if (s.has(tcp_syn)) {
      ++st.TcpExtTCPSYNChallenge;
      challenge_ack(t, s);
    } else {
      dup_ack(t, s, st.TcpExtTCPACKSkippedSeq);
    }
    transmit(t, now);
    return;
  }
  // R3 (TS.Recent) waits for step 6: a segment that steps 3, 5 or 6 reject
  // must not move it (update_ts_recent).
  // Step 3 (RFC 5961 §3.2): RST.
  if (s.has(tcp_rst)) {
    if (!rst_exact(t, s)) {
      challenge_ack(t, s);
      transmit(t, now);
      return;
    }
    reset_input(t);
    return;
  }
  // Step 5 (RFC 5961 §4.2): SYN.
  if (s.has(tcp_syn) && !crossing) {
    ++st.TcpExtTCPSYNChallenge;
    challenge_ack(t, s);
    transmit(t, now);
    return;
  }
  // Step 6: ACK.
  if (!s.has(tcp_ack)) {
    trace_drop(&t, s);
    return;
  }
  if (t.state == TcpState::syn_received) {
    if (s.ack != t.snd_nxt()) {
      send_reset_reply(t.tuple, s);
      trace_drop(&t, s);
      return;
    }
    update_ts_recent(t, s);  // as Linux tcp_check_req, before the queue check
    // Linux tcp_v4_syn_recv_sock / tcp_check_req (tcp_abort_on_overflow =
    // 0): with the accept queue full (more than backlog) the completing ACK
    // is dropped; the child stays in SYN-RECEIVED and its SYN-ACK schedule
    // runs on, so a later ACK completes it once the application accepts.
    if (t.passive && t.listener) {
      const ListenState& ls = *at(*t.listener).listen;
      if (ls.accept_q.size() > ls.backlog) {
        ++st.TcpExtListenOverflows;
        ++st.TcpExtListenDrops;
        trace_drop(&t, s);
        return;
      }
    }
    handshake_done(t, s);
    // The window of the completing ACK is scaled; that of a crossing
    // SYN-ACK is not (RFC 7323 §2.2).
    t.snd_wnd = s.has(tcp_syn) ? s.v->h.window : peer_window(t, s.v->h.window);
    t.max_snd_wnd = std::max(t.max_snd_wnd, t.snd_wnd);
    t.snd_wl1 = s.seq;
    t.snd_wl2 = s.ack;
    t.last_ack_recv = now;
    if (crossing) {
      transmit(t, now);
      return;
    }
  } else if (!process_ack_input(t, s)) {
    return;
  }
  if (!alive(slot, gen)) {
    return;
  }
  // Steps 7-9: text and FIN.
  if (window_drop && s.plen > 0) {
    ++st.TcpExtTCPZeroWindowDrop;
    t.ackp.enter_quickack(t.rcv_wnd);
  } else if ((s.plen > 0 || s.has(tcp_fin)) && !data_input(t, s)) {
    return;
  }
  transmit(t, now);
}

// RFC 5961 §3.2: an RST resets only at SEG.SEQ == RCV.NXT. As built, both
// profiles also take the two extensions of Linux tcp_validate_incoming
// (§4.4 step 3): RCV.NXT − 1 once the peer's FIN is in (CLOSE-WAIT, CLOSING,
// LAST-ACK; tcp_reset_check), since a peer may reset at its FIN's sequence
// number, and, with SACK, the right edge of the highest out-of-order block,
// which is the peer's SND.NXT when only a hole is missing.
bool TcpEngine::rst_exact(const Tcb& t, const InSeg& s) const {
  const Seq32 rcv_nxt = t.rcv_nxt();
  if (s.seq == rcv_nxt) {
    return true;
  }
  if (s.seq == rcv_nxt - 1 && (t.state == TcpState::close_wait || t.state == TcpState::closing ||
                               t.state == TcpState::last_ack)) {
    return true;
  }
  if (!t.stream) return false;
  const auto ooo = t.stream->rcvq.ooo_ranges();
  return t.sack_ok && !ooo.empty() && s.seq == seq_at(t.rcv_base(), ooo.back().end);
}

// Step 3, an exact RST: the reset per state (RFC 9293 §3.10.7.4).
void TcpEngine::reset_input(Tcb& t) {
  switch (t.state) {
    case TcpState::syn_received:
      if (t.passive) {
        close_conn(t, CloseCause::child_reset);
      } else {
        close_conn(t, CloseCause::refused, Error::connection_refused);
      }
      return;
    case TcpState::closing:
    case TcpState::last_ack:
      close_conn(t, CloseCause::rst_received);
      return;
    default:
      close_conn(t, CloseCause::rst_received, Error::connection_reset);
      return;
  }
}

// The window field of a non-SYN segment in bytes (RFC 7323 §2.3), or as a
// planted fault gets it wrong (§7.3, TcpConfig::test_fault).
std::uint32_t TcpEngine::peer_window(const Tcb& t, std::uint16_t field) const {
  switch (cfg_.test_fault) {
    case TestFault::unscaled_peer_window:
      return field;
    case TestFault::overscaled_peer_window:
      return std::uint32_t{field} << max_wscale;
    case TestFault::none:
    case TestFault::prr_skip_force:      // LossRecovery (M2a)
    case TestFault::double_tlp:          // LossRecovery (M2a)
    case TestFault::ignore_pacing_gate:  // transmit()
      break;
  }
  return std::uint32_t{field} << t.snd_wscale;
}

// RFC 7323 §4.3 (2), §5.3 R3: TS.Recent, for a segment that passed every
// check (sync_input calls it once the ACK is accepted).
void TcpEngine::update_ts_recent(Tcb& t, const InSeg& s) {
  if (t.ts_ok && s.v->opt.ts && !s.has(tcp_rst) && before_eq(s.seq, t.last_ack_sent) &&
      (!t.ts_recent_valid || static_cast<std::int32_t>(s.v->opt.ts->val - t.ts_recent) >= 0 ||
       s.now - t.ts_recent_stamp > paws_24days)) {
    t.ts_recent = s.v->opt.ts->val;
    t.ts_recent_stamp = s.now;
    t.ts_recent_valid = true;
  }
}

// Step 6 for synchronized states: the ACK pipeline (§5.1) and the window.
bool TcpEngine::process_ack_input(Tcb& t, const InSeg& s) {
  const Time now = s.now;
  StackStats& st = core_.stats();
  const Seq32 una = t.snd_una();
  // RFC 5961 §5.2: SEG.ACK must lie in [SND.UNA - MAX.SND.WND, SND.NXT].
  if (after(s.ack, t.snd_nxt()) || before(s.ack, una - t.max_snd_wnd)) {
    trace_drop(&t, s);
    challenge_ack(t, s);
    transmit(t, now);
    return false;
  }
  const bool old_ack = before(s.ack, una);
  if (!old_ack) {
    // R3 (RFC 7323 §4.3, §5.3) only now that the ACK is accepted, as Linux
    // (tcp_ack, FLAG_UPDATE_TS_RECENT): an in-window SYN or an ACK above
    // SND.NXT must not move TS.Recent. Linux skips it for an old ACK too.
    update_ts_recent(t, s);
    // Linux tcp_ack after the old_ack branch: the peer is alive, so the
    // probe count, the receive stamp (tcp_rtx_probe0_timed_out) and any soft
    // error (sk_err_soft, §4.7) are reset.
    t.last_ack_recv = now;
    t.probes_out = 0;
    t.soft_error.reset();
  }
  // MUST-20 (RFC 9293 §3.10.7.4): window update. As Linux
  // tcp_may_update_window, an ACK that advances SND.UNA always takes the
  // window: the usable window is computed from SND.UNA (SND.UNA + SND.WND,
  // Linux tcp_wnd_end), so a window kept from an older ACK would move the
  // right edge past the one the peer offered (e.g. a retransmitted peer
  // segment with a lower SEQ than SND.WL1 that acknowledges new data).
  const std::uint32_t nwin = peer_window(t, s.v->h.window);
  bool window_update = false;
  if (!old_ack && (after(s.ack, una) || before(t.snd_wl1, s.seq) ||
                   (t.snd_wl1 == s.seq && before_eq(t.snd_wl2, s.ack)))) {
    window_update = nwin != t.snd_wnd;
    t.snd_wnd = nwin;
    t.snd_wl1 = s.seq;
    t.snd_wl2 = s.ack;
    t.max_snd_wnd = std::max(t.max_snd_wnd, nwin);
  }
  const bool advanced = after(s.ack, una);
  // SACK blocks to offsets (§3.2), validated as Linux tcp_sacktag_write_queue.
  activate_stream(t);
  auto& stream = *t.stream;
  const std::uint64_t prior_una = stream.sndq.una();
  const std::uint64_t nxt_off = stream.sndq.nxt_with_fin();
  std::array<Range, wire::max_sack_blocks> blocks{};
  std::size_t nblocks = 0;
  std::optional<Range> dsack;
  const wire::TcpOptions& o = s.v->opt;
  if (t.sack_ok && o.sack_count > 0) {
    for (std::size_t i = 0; i < o.sack_count; ++i) {
      const std::int64_t b = unwrap(o.sack[i].first, t.snd_base(), prior_una);
      const std::int64_t e = unwrap(o.sack[i].second, t.snd_base(), prior_una);
      // D-SACK (RFC 2883 §4, Linux tcp_check_dsack): the first block lies
      // below SEG.ACK or inside the second.
      if (i == 0) {
        bool is_dsack = before(o.sack[0].first, s.ack);
        if (!is_dsack && o.sack_count > 1) {
          is_dsack = !after(o.sack[1].first, o.sack[0].first) &&
                     !before(o.sack[1].second, o.sack[0].second);
        }
        if (is_dsack) {
          // §4.5: inside [SND.UNA − MAX.SND.WND, SND.NXT] like any block
          // (Linux tcp_is_sackblock_valid; tcp_dsack_seen also refuses one
          // longer than the largest window). An invalid D-SACK is discarded
          // and the ACK counts as one without D-SACK.
          const std::int64_t lo =
              static_cast<std::int64_t>(prior_una) - std::int64_t{t.max_snd_wnd};
          if (b < e && e > 0 && static_cast<std::uint64_t>(e) <= nxt_off && b >= lo) {
            dsack = Range{static_cast<std::uint64_t>(std::max<std::int64_t>(b, 0)),
                          static_cast<std::uint64_t>(e)};
          } else {
            ++st.TcpExtTCPSACKDiscard;
          }
          continue;
        }
      }
      if (b >= e || b < 0 || static_cast<std::uint64_t>(e) > nxt_off) {
        ++st.TcpExtTCPSACKDiscard;
        continue;
      }
      if (static_cast<std::uint64_t>(e) <= prior_una) {
        continue;  // too old
      }
      blocks[nblocks++] = Range{static_cast<std::uint64_t>(b), static_cast<std::uint64_t>(e)};
    }
  }
  // Below SND.UNA (inside MAX.SND.WND): an old ACK, reordered behind a newer
  // one. Neither the window nor SND.UNA moves, but its SACK and D-SACK
  // blocks still count (Linux tcp_ack, old_ack: tcp_sacktag_write_queue and
  // tcp_fastretrans_alert, no RTT sample and no CC).
  if (old_ack && nblocks == 0 && !dsack) {
    return true;
  }
  AckInput in;
  in.now = now;
  in.prior_una = prior_una;
  in.new_una = old_ack ? prior_una
                       : static_cast<std::uint64_t>(unwrap(s.ack, t.snd_base(), prior_una));
  if (o.ts && t.ts_ok) {
    in.tsecr = o.ts->ecr;
  }
  in.now_ts = ts_now(t, now);
  in.sack = std::span<const Range>(blocks.data(), nblocks);
  in.dsack = dsack;
  in.window_update = window_update;
  in.dupack = !old_ack && !advanced && s.len == 0 && !window_update;
  in.old_ack = old_ack;
  refresh_cc(t, now);
  const std::uint32_t prior_packets = t.counters().packets_out;
  AckContext c{stream.sndq,  stream.recovery, t.rtt,     stream.cc_conn, t.algo(),  t.rate,      cfg_,
               st,      t.ctr,      t.snd_wnd, t.sack_ok, t.backoff, t.rto_count};
  c.max_snd_wnd = t.max_snd_wnd;
  c.ts_offset = t.ts_offset;
  c.pacing_delay = t.pacing_delay(now);
  AckOutcome out;
  observe_cc(t, TraceTrigger::ack, &s, [&](RecoveryTransition observe) {
    c.on_transition = observe;
    out = process_ack(c, in);
  });
  if (old_ack) {
    return true;
  }
  // Linux tcp_ack_probe: nothing was in flight and the window now takes the
  // next segment, so the backoff that zero-window probing built up ends
  // (else the first segment after the window opens would wait for the
  // backed-off RTO).
  if (prior_packets == 0 && stream.sndq.end() > stream.sndq.nxt() &&
      t.snd_wnd >= std::min<std::uint64_t>(stream.sndq.end() - stream.sndq.nxt(), t.mss_cache)) {
    t.backoff = 0;
  }
  if (out.seq_rtt >= Duration::zero()) {
    t.backoff = 0;  // RFC 6298 §5.7
    trace_rtt(t, s, TraceTrigger::ack, out.seq_rtt);
  }
  if (advanced) {
    t.rto_count = 0;
    if (t.counters().retrans_out == 0) {
      stream.retrans_stamp.reset();
    }
    if (stream.pmtu_rexmit_end && stream.sndq.una() >= *stream.pmtu_rexmit_end) {
      stream.pmtu_rexmit_end.reset();
    }
  }
  t.ackp.set_srtt(t.rtt.srtt());
  if (core_.tracing(TraceKind::ack)) {
    TraceEvent e = trace_base(t, TraceKind::ack);
    e.seq = s.seq.raw();
    e.ack = s.ack.raw();
    core_.trace(e);
  }
  if (stream.sndq.segs().empty()) {
    chrono_stop(t, ChronoType::busy, now);
  }
  // Our FIN acknowledged (§3.2: SendQueue::fin_acked is the state).
  if (stream.sndq.fin_acked()) {
    switch (t.state) {
      case TcpState::fin_wait_1:
        set_state(t, TcpState::fin_wait_2);
        if (t.orphan) {
          core_.timers().arm(t.t_fin_wait2, now + cfg_.orphan_fin_wait2_timeout);
          trace_timer(t, TraceTimer::fin_wait2, TimerOp::armed);
        }
        break;
      case TcpState::closing:
        enter_time_wait(t);
        return false;
      case TcpState::last_ack:
        close_conn(t, CloseCause::last_ack);
        return false;
      default:
        break;
    }
  }
  if (advanced) {
    sndbuf_expand(t);
    window_writable(t, now);
  }
  // RFC 5681 §4.1 after the window opened on an idle connection (rfc5681
  // only). Linux restarts only when new data is queued (tcp_skb_entail, our
  // tcp_send), so idle_restart = linux keeps cwnd across a zero-window stall:
  // zero-window probes do not move lsndtime, and a halving per RTO of the
  // stall would collapse cwnd to IW.
  if (cfg_.idle_restart == IdleRestart::rfc5681 && window_update &&
      t.counters().packets_out == 0 && stream.sndq.end() > stream.sndq.nxt()) {
    restart_window(t, now, &s);
  }
  return true;
}

// Linux tcp_sndbuf_expand, from tcp_new_space (data was acknowledged).
void TcpEngine::sndbuf_expand(Tcb& t) {
  if (t.opts.snd_buf || cfg_.snd_buf_init >= cfg_.snd_buf_max) {
    return;
  }
  const Counters& k = t.counters();
  if (packets_in_flight(k) >= t.stream->cc_conn.cwnd) {
    return;  // tcp_should_expand_sndbuf
  }
  const std::uint64_t segs =
      std::max<std::uint64_t>({10, t.stream->cc_conn.cwnd, std::uint64_t{cfg_.dupthresh} + 1});
  const std::uint64_t want =
      std::uint64_t{t.algo().sndbuf_expand()} * segs * std::uint64_t{t.mss_cache};
  const auto cap = static_cast<std::uint32_t>(std::min<std::uint64_t>(want, cfg_.snd_buf_max));
  if (cap > t.stream->sndq.capacity()) {
    t.stream->sndq.set_capacity(cap);
  }
}

// ev_writable once free send space is at least half the space in use (Linux
// sk_stream_is_writeable).
void TcpEngine::window_writable(Tcb& t, Time now) {
  const std::uint64_t queued = t.stream->sndq.held();
  if (t.stream->sndq.free_space() > 0 && t.stream->sndq.free_space() >= queued / 2) {
    chrono_stop(t, ChronoType::sndbuf_limited, now);
    if (t.send_blocked) {
      t.send_blocked = false;
      raise(t, ev_writable);
    }
  }
}

// Steps 7-8: segment text, then the FIN (step 9, fin_check).
bool TcpEngine::data_input(Tcb& t, const InSeg& s) {
  const Time now = s.now;
  StackStats& st = core_.stats();
  if (t.state != TcpState::established && t.state != TcpState::fin_wait_1 &&
      t.state != TcpState::fin_wait_2) {
    return true;  // the peer's FIN is in: nothing more is taken
  }
  const Seq32 data = s.seq + (s.has(tcp_syn) ? 1u : 0u);
  std::int64_t off = unwrap(data, t.rcv_base(), t.rcv_nxt_off());
  std::span<const std::byte> payload = s.v->payload;
  if (off < 0) {  // before IRS + 1: cannot be held
    const auto skip = static_cast<std::size_t>(std::min<std::int64_t>(-off, s.plen));
    payload = payload.subspan(skip);
    off += static_cast<std::int64_t>(skip);
  }
  const auto uoff = static_cast<std::uint64_t>(off);
  activate_stream(t);
  auto& stream = *t.stream;
  const std::uint64_t old_nxt = stream.rcvq.contiguous_end();
  // The ACK decision's reader (RcvWindow::on_in_order_data, ack_view): a
  // Linux reader runs alongside the softirq, while the host's application
  // reads only after the host's receive batch. In-order data that arrived
  // earlier in this batch counts as read, so the decision does not depend on
  // the batch size (DESIGN §3; M2 coordinator decision on the ACK
  // frequency); data left unread from earlier batches still fills the buffer
  // (a slow or stopped reader, Linux tcp_space).
  if (stream.rx_batch_id != core_.host_batch()) {
    stream.rx_batch_id = core_.host_batch();
    stream.rx_batch_nxt = old_nxt;
  }
  const std::uint64_t batch_from = std::max(stream.rx_batch_nxt, stream.rcvq.read_offset());
  const std::uint64_t read_upto =
      stream.rcvq.read_offset() + (old_nxt > batch_from ? old_nxt - batch_from : 0);
  // Linux tcp_rcv_state_process: new data after the application closed (or
  // shut down reading) in FIN-WAIT-1/2 aborts (RFC 1122 §4.2.2.13). In
  // ESTABLISHED, shutdown(read) alone acknowledges and discards it (§3.5).
  const bool fin_wait = t.state == TcpState::fin_wait_1 || t.state == TcpState::fin_wait_2;
  if (fin_wait && (t.orphan || t.app_read_shut) && uoff + payload.size() > old_nxt &&
      !payload.empty()) {
    ++st.TcpExtTCPAbortOnData;
    send_rst(t, now);
    close_conn(t, CloseCause::aborted, Error::connection_reset);
    return false;
  }
  if (!payload.empty()) {
    const std::uint32_t ssthresh_before = t.rwin.rcv_ssthresh();
    const auto limit = t.rwin.rcv_adv();
    const InsertResult r = t.app_read_shut
        ? stream.rcvq.insert_after_read_shutdown(uoff, payload.size(), limit)
        : stream.rcvq.insert(uoff, payload, limit);
    const std::uint64_t new_nxt = r.contiguous_end;
    t.ctr.bytes_received += new_nxt - old_nxt;
    if (r.out_of_order && !r.stored.empty()) {
      ++t.ctr.rcv_ooopack;
      ++st.TcpExtTCPOFOQueue;
    }
    if (r.dropped > 0) {
      if (r.out_of_order) {
        ++st.TcpExtTCPOFODrop;
      } else {
        ++st.TcpExtTCPRcvQDrop;
      }
    }
    if (r.pruned > 0) {
      ++st.TcpExtOfoPruned;
    }
    if (r.stored.empty() && r.dropped == 0 && !r.duplicate && uoff >= old_nxt &&
        t.rcv_window() == 0) {
      ++st.TcpExtTCPZeroWindowDrop;
    }
    stream.sackgen.on_arrival(r.stored, stream.rcvq);
    if (r.duplicate && t.sack_ok && cfg_.dsack) {
      stream.sackgen.on_duplicate(*r.duplicate, stream.rcvq);
      t.ackp.ack_now();
      if (r.duplicate->end <= old_nxt) {
        ++st.TcpExtTCPDSACKOldSent;
      } else {
        ++st.TcpExtTCPDSACKOfoSent;
      }
    }
    t.ackp.on_data(now, static_cast<std::uint32_t>(payload.size()), s.meta.gso_size, r,
                   t.rcv_wnd, t.rtt.rto_backed_off(t.backoff));
    if (r.advanced) {
      t.rwin.on_in_order_data(static_cast<std::uint32_t>(payload.size()), t.ackp.rcv_mss(),
                              stream.rcvq, read_upto);
      if (t.rwin.rcv_ssthresh() > ssthresh_before) {
        t.ackp.on_rcv_ssthresh_grew();
      }
    }
    // Receiver RTT (Linux tcp_rcv_rtt_measure_ts): a new TSecr.
    std::optional<Duration> ts_rtt;
    if (t.ts_ok && s.v->opt.ts && s.v->opt.ts->ecr != 0 && stream.last_tsecr != s.v->opt.ts->ecr) {
      stream.last_tsecr = s.v->opt.ts->ecr;
      if (payload.size() >= t.ackp.rcv_mss()) {
        const std::uint32_t d = ts_now(t, now) - s.v->opt.ts->ecr;
        if (d < 2'147'483u) {
          ts_rtt = std::chrono::milliseconds{std::max(d, 1u)};
        }
      }
    }
    t.rwin.on_data_rtt(now, stream.rcvq.contiguous_end(), ts_rtt);
    // §7.2 test knob: reneging.
    if (cfg_.test_renege_ppm > 0 && !stream.rcvq.ooo_ranges().empty() &&
        core_.rng().chance_ppm(cfg_.test_renege_ppm)) {
      stream.rcvq.drop_out_of_order();
    }
    if (r.advanced) {
      stream.last_data_recv = now;
      if (t.app_read_shut) {
        stream.rcvq.discard_readable();
      } else {
        raise(t, ev_readable);
      }
    }
    // __tcp_ack_snd_check per segment, with the data received earlier in
    // this host batch taken by the reader (RcvWindow::ack_view): one ACK per
    // two full segments whether the host hands the stack 1 or 64 segments
    // per batch.
    t.ackp.on_window(now, t.rwin.ack_view(stream.rcvq, t.ackp.rcv_mss(), read_upto));
  }
  if (s.has(tcp_fin)) {
    const std::uint64_t fin_off = uoff + payload.size();
    if (fin_off <= t.rwin.rcv_adv()) {
      stream.rcvq.set_fin(fin_off);
    }
    if (!stream.rcvq.fin_reached()) {
      t.ackp.ack_now();  // out-of-order FIN: a duplicate ACK
    }
  }
  return fin_check(t, now);
}

// Step 9: the FIN once RCV.NXT reaches it.
bool TcpEngine::fin_check(Tcb& t, Time now) {
  if (t.fin_rcvd || !t.stream->rcvq.fin_reached()) {
    return true;
  }
  t.fin_rcvd = true;
  t.ackp.ack_now();
  raise(t, ev_read_closed | ev_readable);
  switch (t.state) {
    case TcpState::syn_received:
    case TcpState::established:
      set_state(t, TcpState::close_wait);
      return true;
    case TcpState::fin_wait_1:
      if (!t.stream->sndq.fin_acked()) {
        set_state(t, TcpState::closing);
        return true;
      }
      [[fallthrough]];
    case TcpState::fin_wait_2:
      send_ack(t, now);
      enter_time_wait(t);
      return false;
    default:
      return true;
  }
}

// TIME-WAIT (§4.4, §4.12; Linux tcp_timewait_state_process).
void TcpEngine::time_wait_input(std::uint32_t index, const InSeg& s) {
  TimeWaitEntry& e = tw_.entry(index);
  StackStats& st = core_.stats();
  const Time now = s.now;
  // Linux tcp_paws_reject (window 0): any TSval older than TS.Recent is
  // rejected; an RST only while TS.Recent is younger than TCP_PAWS_MSL, so an
  // old duplicate RST cannot end TIME-WAIT (the RFC 1337 hazard).
  bool paws = false;
  const auto& ts = s.v->opt.ts;
  if (e.ts_ok && ts && now - e.ts_recent_stamp <= paws_24days &&
      static_cast<std::int32_t>(e.ts_recent - ts->val) > 0) {
    paws = !s.has(tcp_rst) || now - e.ts_recent_stamp < paws_msl;
  }
  const Time expiry = now + cfg_.time_wait;
  // In window: only an RST or a bare ACK.
  if (!paws && s.seq == e.rcv_nxt && (s.len == 0 || s.has(tcp_rst))) {
    if (s.has(tcp_rst)) {
      if (cfg_.rst_in_time_wait == RstInTimeWait::accept) {
        trace_tw_state(e, CloseCause::time_wait_rst);
        tw_.erase(index, core_.timers());
      }
      return;
    }
    tw_.restart(index, core_.timers(), expiry);
    if (e.ts_ok && ts) {
      e.ts_recent = ts->val;
      e.ts_recent_stamp = now;
    }
    return;
  }
  // A new SYN: newer TSval, or a higher SEQ (RFC 6191).
  if (s.has(tcp_syn) && !s.has(tcp_rst) && !s.has(tcp_ack) && !paws &&
      (after(s.seq, e.rcv_nxt) ||
       (e.ts_ok && ts && static_cast<std::int32_t>(e.ts_recent - ts->val) < 0))) {
    if (const auto l = listener_for(e.tuple.local.port)) {
      Seq32 iss = e.snd_nxt + 65537;
      if (iss.raw() == 0) {
        iss = Seq32{1};
      }
      const FourTuple tuple = e.tuple;
      trace_tw_state(e, CloseCause::time_wait_reused);
      tw_.erase(index, core_.timers());
      listen_input(at(*l), tuple, s, iss);
      return;
    }
    send_tw_ack(e, now);
    return;
  }
  if (paws) {
    ++st.TcpExtPAWSEstab;
  }
  if (s.has(tcp_rst)) {
    return;
  }
  if (paws || s.has(tcp_ack)) {
    tw_.restart(index, core_.timers(), expiry);
  }
  std::optional<Time> last;
  if (e.has_oow_ack) {
    last = e.last_oow_ack;
  }
  if (oow_allowed(last, s, st.TcpExtTCPACKSkippedTimeWait, true)) {
    if (last) {
      e.last_oow_ack = *last;
      e.has_oow_ack = true;
    }
    send_tw_ack(e, now);
  }
}

}  // namespace utcp
