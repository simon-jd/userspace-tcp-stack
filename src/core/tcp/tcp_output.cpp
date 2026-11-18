// The output path (DESIGN §4.9) and segment construction (§4.5).
#include <algorithm>
#include <array>
#include <limits>
#include <optional>

#include "core/stack_impl.hpp"
#include "core/tcp/tcp_engine.hpp"
#include "core/wire/ipv4.hpp"
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp {

namespace {

using namespace wire;

[[nodiscard]] bool sends_data(TcpState s) {
  switch (s) {
    case TcpState::established:
    case TcpState::close_wait:
    case TcpState::fin_wait_1:
    case TcpState::closing:
    case TcpState::last_ack:
      return true;
    default:
      return false;
  }
}

}  // namespace

std::size_t TcpEngine::sack_blocks(const Tcb& t, std::span<Range> out) const {
  if (!t.sack_ok || !t.have_irs) {
    return 0;
  }
  const std::size_t max = t.ts_ok ? max_sack_blocks_with_ts : max_sack_blocks;
  return t.sackgen.fill(t.rcvq, out, std::min(max, out.size()));
}

// Linux tcp_current_mss: the payload of a full segment with the SACK blocks
// the next ACK carries (4 + 8n option bytes).
std::uint32_t TcpEngine::mss_now(const Tcb& t) const {
  std::array<Range, max_sack_blocks> b{};
  const std::size_t n = sack_blocks(t, b);
  const std::uint32_t opt = n == 0 ? 0u : static_cast<std::uint32_t>(4 + 8 * n);
  return t.mss_cache > opt + 8 ? t.mss_cache - opt : 8u;
}

bool TcpEngine::send_segment(Tcb& t, Time now, const SegOut& o) {
  const bool syn = (o.flags & tcp_syn) != 0;
  const bool rst = (o.flags & tcp_rst) != 0;
  const bool ack = (o.flags & tcp_ack) != 0;
  TcpOptions opt;
  if (syn) {
    // §4.5: an active open offers what the configuration enables (its
    // simultaneous-open SYN-ACK repeats the SYN); a passive SYN-ACK echoes
    // what both sides support.
    const bool offer = !t.passive;
    opt.mss = t.adv_mss;
    if (offer ? cfg_.window_scaling : t.ws_ok) {
      opt.wscale = t.offered_wscale;
    }
    opt.sack_permitted = offer ? cfg_.sack : t.sack_ok;
    if (offer ? cfg_.timestamps : t.ts_ok) {
      opt.ts = Timestamps{ts_now(t, now), ack && t.ts_ok ? t.ts_recent : 0u};
    }
  } else if (!rst) {
    if (t.ts_ok) {
      opt.ts = Timestamps{ts_now(t, now), t.ts_recent};  // RFC 7323 §3.2
    }
    if (ack) {
      std::array<Range, max_sack_blocks> b{};
      const std::size_t n = sack_blocks(t, b);
      for (std::size_t i = 0; i < n; ++i) {
        opt.sack[i] = {seq_at(t.rcv_base(), b[i].begin), seq_at(t.rcv_base(), b[i].end)};
      }
      opt.sack_count = static_cast<std::uint8_t>(n);
    }
  }
  std::uint16_t field = 0;
  if (syn) {
    field = t.syn_wnd;  // RFC 7323 §2.2: never scaled
  } else if (!rst && t.have_irs) {
    const SelectedWindow w = t.rwin.select(t.rcvq, t.ackp.rcv_mss());
    field = w.field;
    t.rcv_wnd = t.rwin.last_window();
    if (t.rwin.went_to_zero()) {
      ++core_.stats().TcpExtTCPToZeroWindowAdv;
    }
    if (t.rwin.went_from_zero()) {
      ++core_.stats().TcpExtTCPFromZeroWindowAdv;
    }
  }
  TcpHeader h;
  h.sport = t.tuple.local.port;
  h.dport = t.tuple.remote.port;
  h.seq = o.seq;
  h.ack = ack ? t.rcv_nxt() : Seq32{};
  h.window = field;
  h.flags = o.flags;
  const std::size_t hl = tcp_header_len(opt, syn);
  auto buf = core_.alloc_packet(static_cast<std::uint32_t>(hl), o.data_len);
  if (!buf) {
    return false;
  }
  if (o.data_len > 0) {
    t.sndq.copy_out(o.data_off, std::span<std::byte>(buf->append(o.data_len), o.data_len));
  }
  buf->prepend(hl);
  const std::span<std::byte> l4 = buf->bytes();
  write_tcp_header(l4, h, opt, syn);
  set_l4_checksum(l4, t.tuple.local.addr, t.tuple.remote.addr, ip_proto_tcp);

  // Bookkeeping (§4.9, §4.11), before the trace so it shows the state after
  // the send.
  StackStats& st = core_.stats();
  if (ack && t.have_irs) {
    t.ackp.on_ack_sent(now);
    t.sackgen.on_ack_sent();
    t.last_ack_sent = h.ack;
  }
  const bool carries = !syn && !rst && (o.data_len > 0 || (o.flags & tcp_fin) != 0) &&
                       o.kind != TxKind::zwp;
  if (carries) {
    const Counters& k = t.sndq.counters();
    // Linux tcp_event_data_sent (tcp_output.c:185, from __tcp_transmit_skb
    // at 1669-1670 for every skb with payload, retransmissions included; not
    // for a bare FIN): tx_start when nothing is in flight before this
    // segment, and lsndtime = now (M2-DESIGN §2.1 item 8; an RTO
    // retransmission after everything was marked lost starts a new
    // transmission period).
    if (o.data_len > 0) {
      if (packets_in_flight(k) == 0) {
        refresh_cc(t, now);
        t.algo().cwnd_event(t.cc_conn, CaEvent::tx_start);
        t.recovery.observe_cc_event(t.cc_conn, CaEvent::tx_start);  // test seam
      }
      t.lsndtime = now;
    }
    rate_on_send(t.rate, k.packets_out, now);
    // A loss probe that resends a sent segment goes through Linux
    // __tcp_retransmit_skb only (tcp_send_loss_probe): no retrans_out, no
    // retrans_stamp (M2-DESIGN §1.7).
    const bool probe = o.retrans && o.kind == TxKind::tlp;
    const TxSeg& seg = t.sndq.on_transmit(o.data_off, o.data_len, (o.flags & tcp_fin) != 0, now,
                                          t.rate, probe);
    RecoveryCtx c = rctx(t, now);
    t.recovery.on_transmit(c, seg, o.kind);
    if (o.retrans) {
      if (!probe && !t.retrans_stamp) {
        t.retrans_stamp = now;  // Linux tcp_retransmit_skb
      }
    } else {
      // TcpExtTCPOrigDataSent is LossRecovery::on_transmit's (tx_count 1).
      t.txp.on_data_sent(o.data_off, o.data_len, mss_now(t));
      chrono_start(t, ChronoType::busy, now);
    }
    if (o.data_len > 0) {
      ++t.ctr.data_segs_out;
    }
  }
  ++t.ctr.segs_out;
  if (o.retrans) {
    ++st.TcpRetransSegs;
    ++t.ctr.total_retrans;
  } else {
    ++st.TcpOutSegs;
  }
  if (rst) {
    ++st.TcpOutRsts;
  }
  trace_tx(t, o.kind, o.seq, h.ack, o.data_len, field, o.flags);
  t.tx_gate_rate = 0;
  t.tx_burst_start = false;
  core_.send_ipv4(t.tuple.remote.addr, ip_proto_tcp, t.ip_id++, std::move(*buf), t.self.slot);
  return true;
}

bool TcpEngine::send_ack(Tcb& t, Time now, TxKind kind) {
  if (!core_.can_transmit()) {
    core_.block_tx(t.self.slot);
    return false;
  }
  SegOut o;
  o.seq = t.snd_nxt();
  o.flags = tcp_ack;
  o.kind = kind;
  return send_segment(t, now, o);
}

void TcpEngine::send_syn(Tcb& t, Time now, bool counts) {
  SegOut o;
  o.seq = t.iss;
  o.flags = static_cast<std::uint16_t>(tcp_syn | (t.have_irs ? tcp_ack : 0));
  o.kind = t.have_irs ? TxKind::synack : TxKind::syn;
  if (counts) {
    o.retrans = t.syn_tries > 0;
    if (t.syn_tries == 0) {
      t.syn_first_tx = now;
    }
    if (t.syn_tries < 0xff) {
      ++t.syn_tries;
    }
    t.syn_last_tx = now;
    if (o.retrans) {
      ++core_.stats().TcpExtTCPSynRetrans;
    }
  }
  if (core_.can_transmit()) {
    (void)send_segment(t, now, o);
  }
}

void TcpEngine::send_rst(Tcb& t, Time now) {
  SegOut o;
  o.seq = t.snd_nxt();
  o.flags = tcp_rst | tcp_ack;
  o.kind = TxKind::rst;
  if (!core_.can_transmit() || !send_segment(t, now, o)) {
    // Traced even when the queue drops it (§10.2), so the checkers see the
    // abort.
    trace_tx(t, TxKind::rst, o.seq, t.rcv_nxt(), 0, 0, o.flags);
  }
}

// RFC 9293 §3.10.7.1: <SEQ=SEG.ACK><CTL=RST> for a segment with ACK, else
// <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>.
void TcpEngine::send_reset_reply(const FourTuple& tuple, const InSeg& s) {
  TcpHeader h;
  h.sport = tuple.local.port;
  h.dport = tuple.remote.port;
  if (s.has(tcp_ack)) {
    h.seq = s.ack;
    h.flags = tcp_rst;
  } else {
    h.ack = s.seq + s.len;
    h.flags = tcp_rst | tcp_ack;
  }
  const TcpOptions opt;
  const std::size_t hl = tcp_header_len(opt, false);
  if (!core_.can_transmit()) {
    return;
  }
  auto buf = core_.alloc_packet(static_cast<std::uint32_t>(hl), 0);
  if (!buf) {
    return;
  }
  buf->append(hl);
  const std::span<std::byte> l4 = buf->bytes();
  write_tcp_header(l4, h, opt, false);
  set_l4_checksum(l4, tuple.local.addr, tuple.remote.addr, ip_proto_tcp);
  ++core_.stats().TcpOutSegs;
  ++core_.stats().TcpOutRsts;
  // RFC 6864 §4.1: an atomic datagram of no connection, ID 0 (as Linux).
  core_.send_ipv4(tuple.remote.addr, ip_proto_tcp, 0, std::move(*buf));
}

// A TIME-WAIT ACK: the scaled window and a TSval (§4.12).
void TcpEngine::send_tw_ack(TimeWaitEntry& e, Time now) {
  TcpOptions opt;
  if (e.ts_ok) {
    const auto ms = static_cast<std::uint64_t>(now.ns / 1'000'000);
    opt.ts = Timestamps{static_cast<std::uint32_t>(ms) + e.ts_offset, e.ts_recent};
  }
  TcpHeader h;
  h.sport = e.tuple.local.port;
  h.dport = e.tuple.remote.port;
  h.seq = e.snd_nxt;
  h.ack = e.rcv_nxt;
  h.flags = tcp_ack;
  h.window = static_cast<std::uint16_t>(std::min<std::uint32_t>(e.rcv_wnd >> e.rcv_wscale, 0xffff));
  const std::size_t hl = tcp_header_len(opt, false);
  if (!core_.can_transmit()) {
    return;
  }
  auto buf = core_.alloc_packet(static_cast<std::uint32_t>(hl), 0);
  if (!buf) {
    return;
  }
  buf->append(hl);
  const std::span<std::byte> l4 = buf->bytes();
  write_tcp_header(l4, h, opt, false);
  set_l4_checksum(l4, e.tuple.local.addr, e.tuple.remote.addr, ip_proto_tcp);
  ++core_.stats().TcpOutSegs;
  if (core_.tracing(TraceKind::tx)) {
    TraceEvent ev;
    ev.t = now;
    ev.conn_id = e.conn_id;
    ev.tuple = e.tuple;
    ev.kind = TraceKind::tx;
    ev.tx = TxKind::ack;
    ev.state = TcpState::time_wait;
    ev.seq = h.seq.raw();
    ev.ack = h.ack.raw();
    ev.wnd = h.window;
    ev.flags = h.flags;
    core_.trace(ev);
  }
  core_.send_ipv4(e.tuple.remote.addr, ip_proto_tcp, 0, std::move(*buf));
}

bool TcpEngine::retransmit_seg(Tcb& t, Time now, const TxSeg& whole, TxKind kind) {
  // Linux tcp_retransmit_skb: a segment sent before the SACK blocks we now
  // carry (or a PMTU drop) took more room is cut to the current MSS; the
  // tail stays lost and goes next.
  TxSeg seg = whole;
  const std::uint32_t mss = mss_now(t);
  if (seg.len > mss) {
    t.sndq.split(seg.off, mss);
    seg = *t.sndq.find(seg.off);
  }
  SegOut o;
  o.seq = seq_at(t.snd_base(), seg.off);
  o.flags = tcp_ack;
  if (seg.fin) {
    o.flags |= tcp_fin;
  }
  if (seg.len > 0 && seg.end() == t.sndq.end()) {
    o.flags |= tcp_psh;
  }
  o.data_off = seg.off;
  o.data_len = seg.len;
  o.kind = kind;
  o.retrans = true;
  return send_segment(t, now, o);
}

bool TcpEngine::send_new_data(Tcb& t, Time now, std::uint32_t len, bool fin) {
  SegOut o;
  const std::uint64_t off = t.sndq.nxt();
  o.seq = seq_at(t.snd_base(), off);
  o.flags = tcp_ack;
  if (fin) {
    o.flags |= tcp_fin;
  }
  if (len > 0 && off + len == t.sndq.end()) {
    o.flags |= tcp_psh;  // the last queued byte (Linux tcp_mark_push on the tail)
  }
  o.data_off = off;
  o.data_len = len;
  o.kind = len > 0 ? TxKind::data : TxKind::fin;
  return send_segment(t, now, o);
}

void TcpEngine::flush_ack(Tcb& t, Time now) {
  if (!t.have_irs || !t.synchronized() || t.state == TcpState::time_wait) {
    return;
  }
  if (t.ackp.need() == AckNeed::now) {
    (void)send_ack(t, now);
  }
}

// §4.9: lost segments, new data (cwnd gate, receive window, sender SWS and
// Nagle, pacing, transmit space), FIN, the extra segment of RFC 6675 NextSeg
// rules 3-4, then the ACK owed.
void TcpEngine::transmit(Tcb& t, Time now) {
  if (t.state == TcpState::closed || t.state == TcpState::time_wait || t.listen) {
    return;
  }
  if (sends_data(t.state) && t.syn_acked) {
    refresh_cc(t, now);
    CcConn& cc = t.cc_conn;
    bool cwnd_limited = false, rwnd_limited = false, blocked = false, paced_out = false;
    std::uint32_t sent = 0, new_sent = 0;
    const std::uint32_t mss = mss_now(t);
    // The pacing gate (§5.5, M2-DESIGN §2.5) applies to new data and, as
    // Linux tcp_xmit_retransmit_queue checks tcp_pacing_check before each
    // retransmission, to the lost segments; every paced send moves
    // pacing_next (tcp_update_skb_after_send).
    const bool pacing = cc.paced && t.txp.gate_rate(cc) != 0;
    const std::uint64_t rate = pacing ? t.txp.gate_rate(cc) : 0;
    // Linux sets the departure stamp of every skb to at least now; after
    // incrementing data_segs_out it charges the full skb reaching ten.
    const auto finish_burst = [&](std::uint64_t bytes) {
      if (t.txp.pacing_applies(cc, t.ctr.data_segs_out)) {
        t.pacing_next = pacing_next_after_send(t.pacing_next, now, bytes, rate);
      } else {
        t.pacing_next = std::max(t.pacing_next, now);
      }
    };
    const auto hold_for_pacing = [&] {
      if (core_.timers().deadline(t.t_pace) != t.pacing_next) {
        core_.timers().arm(t.t_pace, t.pacing_next);
        trace_timer(t, TraceTimer::pace, TimerOp::armed);
      }
      paced_out = true;
    };
    // One retransmission, after the caller passed the pacing gate; returns
    // the bytes sent (retransmit_seg may cut the segment to the current MSS).
    const auto paced_retransmit = [&](const TxSeg& seg, TxKind kind,
                                      bool burst_start) -> std::optional<std::uint32_t> {
      if (pacing) {
        t.tx_gate_rate = rate;
        t.tx_burst_start = burst_start;
      }
      if (!core_.can_transmit() || !retransmit_seg(t, now, seg, kind)) {
        t.tx_gate_rate = 0;
        t.tx_burst_start = false;
        blocked = true;
        return std::nullopt;
      }
      ++sent;
      const TxSeg* s = t.sndq.find(seg.off);
      return s != nullptr ? s->len : seg.len;
    };
    // Paced bursts of the lost loop. Linux checks tcp_pacing_check once per
    // retransmission-queue skb and resends up to min(cwnd quota, tcp_tso_segs)
    // packets of it in one burst, moving tcp_wstamp_ns once for the skb
    // (tcp_xmit_retransmit_queue, tcp_output.c:3741-3782). The stack has no
    // skbs: a run of adjacent lost segments, up to the burst size new data
    // uses (pacing_burst_segments, tcp_tso_autosize), is one burst.
    std::uint32_t rtx_left = 0;
    std::uint64_t rtx_bytes = 0, rtx_end = 0;
    const auto end_rtx_burst = [&] {
      if (pacing && rtx_bytes > 0) {
        finish_burst(rtx_bytes);
      }
      rtx_left = 0;
      rtx_bytes = 0;
    };
    // 1. Segments marked lost (RFC 6582, RFC 5681 §3.2; Linux
    // tcp_xmit_retransmit_queue): each burst through the pacing gate, each
    // segment through the cwnd gate unless recovery exempts it (RFC 6675 §5
    // (4.3), the fast retransmit with recovery_reduction = rfc6675).
    // The walk stops after the last lost segment (lost_out counts them), so
    // a long queue with nothing lost costs nothing per call.
    std::uint32_t lost_seen = 0;
    for (std::size_t i = 0; lost_seen < t.sndq.counters().lost_out; ++i) {
      const std::span<const TxSeg> segs = t.sndq.segs();
      if (i >= segs.size()) {
        break;
      }
      const TxSeg seg = segs[i];
      if (seg.lost) {
        ++lost_seen;
      }
      if (!seg.lost || seg.retrans_inflight || seg.sacked) {
        continue;
      }
      const bool in_burst = pacing && rtx_left > 0 && seg.off == rtx_end;
      if (!in_burst) {
        end_rtx_burst();
        if (t.pacing_gated(pacing, now, cfg_.test_fault)) {
          hold_for_pacing();
          break;
        }
      }
      const RecoveryCtx rc = rctx(t, now);
      const bool exempt = t.recovery.exempt_from_cwnd(rc, seg);
      if (!exempt && packets_in_flight(t.sndq.counters()) >= cc.cwnd) {
        cwnd_limited = true;
        break;
      }
      // Linux tcp_retransmit_skb: beyond the receive window only the head.
      if (i != 0 && seg.off >= t.sndq.una() + t.snd_wnd) {
        break;
      }
      const TxKind kind = exempt ? TxKind::fast_rexmit
                          : t.pmtu_rexmit_end && seg.off < *t.pmtu_rexmit_end ? TxKind::pmtu_rexmit
                                                                              : TxKind::rexmit;
      if (pacing && !in_burst) {
        rtx_left = pacing_burst_segments(rate, t.rtt.min_rtt(), cfg_.gso_max_size, mss,
                                         t.algo().min_tso_segs(cc));
      }
      const std::optional<std::uint32_t> len = paced_retransmit(seg, kind, !in_burst);
      if (!len) {
        break;
      }
      if (pacing) {
        rtx_bytes += *len;
        rtx_end = seg.off + *len;
        if (--rtx_left == 0) {
          end_rtx_burst();
        }
      }
    }
    end_rtx_burst();
    // 2. New data.
    std::uint32_t burst_left = 0;
    std::uint64_t burst_bytes = 0;
    while (!blocked && !paced_out && t.sndq.nxt() < t.sndq.end()) {
      if (packets_in_flight(t.sndq.counters()) >= cc.cwnd) {
        cwnd_limited = true;
        break;
      }
      const std::uint64_t una = t.sndq.una(), nxt = t.sndq.nxt(), end = t.sndq.end();
      const std::uint64_t wnd_end = una + t.snd_wnd;
      const std::uint64_t usable = wnd_end > nxt ? wnd_end - nxt : 0;
      const std::uint64_t unsent = end - nxt;
      const auto len = static_cast<std::uint32_t>(std::min({unsent, std::uint64_t{mss}, usable}));
      if (len == 0) {
        rwnd_limited = true;
        break;
      }
      const bool fin = t.fin_queued && len == unsent;
      SendCheck c;
      c.seg_len = len;
      c.mss = mss;
      c.usable_window = static_cast<std::uint32_t>(
          std::min<std::uint64_t>(usable, std::numeric_limits<std::uint32_t>::max()));
      c.max_snd_wnd = t.max_snd_wnd;
      c.unsent = unsent;
      c.snd_una = una;
      c.snd_nxt = nxt;
      c.fin = fin;
      c.nodelay = t.opts.nodelay;
      if (!t.txp.sws_allows(c)) {
        if (usable < std::min(unsent, std::uint64_t{mss})) {
          rwnd_limited = true;
        }
        break;
      }
      bool burst_start = false;
      if (pacing && burst_left == 0) {
        if (t.pacing_gated(pacing, now, cfg_.test_fault)) {
          hold_for_pacing();
          break;
        }
        burst_left = pacing_burst_segments(rate, t.rtt.min_rtt(), cfg_.gso_max_size, mss,
                                           t.algo().min_tso_segs(cc));
        burst_bytes = 0;
        burst_start = true;
      }
      if (pacing) {
        t.tx_gate_rate = rate;
        t.tx_burst_start = burst_start;
      }
      if (!core_.can_transmit() || !send_new_data(t, now, len, fin)) {
        t.tx_gate_rate = 0;
        t.tx_burst_start = false;
        blocked = true;
        break;
      }
      ++sent;
      ++new_sent;
      if (pacing) {
        burst_bytes += len;
        if (--burst_left == 0) {
          finish_burst(burst_bytes);
        }
      }
    }
    if (pacing && burst_left > 0 && burst_bytes > 0) {
      finish_burst(burst_bytes);
    }
    // 3. A FIN with no data left to carry it. Like Linux tcp_cwnd_test, the
    // final bare FIN is exempt from the cwnd gate; it is sent at the window
    // edge too (deviation, DESIGN §4.9).
    if (!blocked && t.fin_queued && !t.sndq.fin_sent() && t.sndq.nxt() == t.sndq.end()) {
      if (!core_.can_transmit() || !send_new_data(t, now, 0, true)) {
        blocked = true;
      } else {
        ++sent;
        ++new_sent;
      }
    }
    // 4. RFC 6675 NextSeg rules 3 and 4 (M2-DESIGN §1.4): new data stopped
    // because none is left or the window is closed, not for the cwnd, the
    // pacing gate or transmit space; recovery may name more segments to
    // resend, each through the pacing and cwnd gates (RFC 6675 loss detection only).
    if (!blocked && !paced_out && !cwnd_limited &&
        (rwnd_limited || (t.sndq.nxt() == t.sndq.end() && (!t.fin_queued || t.sndq.fin_sent())))) {
      for (std::size_t n = t.sndq.segs().size(); n > 0; --n) {
        if (packets_in_flight(t.sndq.counters()) >= cc.cwnd) {
          cwnd_limited = true;
          break;
        }
        RecoveryCtx rc = rctx(t, now);
        const std::optional<std::uint64_t> off = t.recovery.next_seg_extra(rc);
        const TxSeg* s = off ? t.sndq.find(*off) : nullptr;
        if (s == nullptr || s->sacked) {
          break;
        }
        // retransmit_seg cuts a segment longer than the current MSS; the tail
        // of a segment not marked lost stays in flight, so the cut adds a
        // packet to in_flight besides the retransmission.
        const std::uint32_t need = s->len > mss && !s->lost ? 2u : 1u;
        if (packets_in_flight(t.sndq.counters()) + need > cc.cwnd) {
          cwnd_limited = true;
          break;
        }
        if (t.pacing_gated(pacing, now, cfg_.test_fault)) {
          hold_for_pacing();
          break;
        }
        const TxSeg seg = *s;
        const std::optional<std::uint32_t> len = paced_retransmit(seg, TxKind::rexmit, true);
        if (!len) {
          break;
        }
        if (pacing) {
          finish_burst(*len);
        }
      }
    }
    if (blocked) {
      core_.block_tx(t.self.slot);
    }
    if (rwnd_limited) {
      chrono_start(t, ChronoType::rwnd_limited, now);
    } else if (sent > 0) {
      chrono_stop(t, ChronoType::rwnd_limited, now);
    }
    // Linux tcp_cwnd_validate, from tcp_write_xmit only (tcp_output.c:3085-3087):
    // after new data was sent or when cwnd limits; never for a pass that only
    // retransmitted (tcp_xmit_retransmit_queue does not call it).
    const Counters& k = t.sndq.counters();
    cwnd_limited = cwnd_limited || packets_in_flight(k) >= cc.cwnd;
    if (new_sent > 0 || cwnd_limited) {
      if (t.sndq.una() >= t.cwnd_usage_seq || cwnd_limited ||
          (!cc.cwnd_limited && k.packets_out > cc.max_packets_out)) {
        cc.cwnd_limited = cwnd_limited;
        cc.max_packets_out = k.packets_out;
        t.cwnd_usage_seq = t.sndq.nxt();
      }
      // The network starves because of the send buffer (§10.1, M2-DESIGN
      // §5.3; tcp_cwnd_validate, tcp_output.c:2177-2180): data was sent, cwnd
      // does not limit, nothing unsent is left and the application was
      // refused (SOCK_NOSPACE). A refused write with data still held by the
      // window or cwnd stays rwnd_limited or busy.
      if (!is_cwnd_limited(cc) && t.sndq.nxt() == t.sndq.end() && t.send_blocked &&
          (t.state == TcpState::established || t.state == TcpState::close_wait)) {
        chrono_start(t, ChronoType::sndbuf_limited, now);
      }
    }
    // Linux tcp_write_xmit schedules the loss probe after sending new data
    // (sent_pkts > 0, push_one != 2).
    RecoveryCtx rc = rctx(t, now);
    t.recovery.on_burst_end(rc, new_sent > 0);
  }
  flush_ack(t, now);
  sync_timers(t, now);
}

}  // namespace utcp
