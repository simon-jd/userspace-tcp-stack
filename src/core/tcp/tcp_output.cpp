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
  if (!t.stream || !t.sack_ok || !t.have_irs) {
    return 0;
  }
  const std::size_t max = t.ts_ok ? max_sack_blocks_with_ts : max_sack_blocks;
  return t.stream->sackgen.fill(t.stream->rcvq, out, std::min(max, out.size()));
}

// Linux tcp_current_mss: the payload of a full segment with the SACK blocks
// the next ACK carries (4 + 8n option bytes).
std::uint32_t TcpEngine::mss_now(const Tcb& t) const {
  std::array<Range, max_sack_blocks> b{};
  const std::size_t n = sack_blocks(t, b);
  const std::uint32_t opt = n == 0 ? 0u : static_cast<std::uint32_t>(4 + 8 * n);
  return t.mss_cache > opt + 8 ? t.mss_cache - opt : 8u;
}

bool TcpEngine::send_segment(Tcb& t, Time now, const SegOut& o, std::uint32_t segments) {
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
    const SelectedWindow w = t.stream ? t.rwin.select(t.stream->rcvq, t.ackp.rcv_mss())
        : t.rwin.select(RecvBuffer(t.rwin.rcv_buf(), core_.chunks()), t.ackp.rcv_mss());
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
  const std::uint32_t payload = o.data_len * segments;
  const bool aggregate = segments > 1;
  auto buf = core_.alloc_packet(static_cast<std::uint32_t>(hl), payload, aggregate);
  if (!buf) {
    return false;
  }
  if (payload > 0) {
    t.stream->sndq.copy_out(o.data_off, std::span<std::byte>(buf->append(payload), payload));
  }
  buf->prepend(hl);
  const std::span<std::byte> l4 = buf->bytes();
  write_tcp_header(l4, h, opt, syn);
  const bool partial = core_.config().tcp_checksum_offload;
  if (partial) {
    ChecksumAccumulator sum;
    add_ipv4_pseudo_header(sum, t.tuple.local.addr.v, t.tuple.remote.addr.v, ip_proto_tcp,
                           static_cast<std::uint16_t>(l4.size()));
    store_be16(l4, 16, sum.sum());
  } else {
    set_l4_checksum(l4, t.tuple.local.addr, t.tuple.remote.addr, ip_proto_tcp);
  }

  SegOut logical = o;
  for (std::uint32_t i = 0; i < segments; ++i) {
    record_segment(t, now, logical, h.ack, field);
    if (i + 1 < segments) {
      if (t.tx_gate_rate != 0) {
        t.tx_gate_rate = t.txp.gate_rate(t.stream->cc_conn);
      }
      t.tx_burst_start = false;
      logical.seq += o.data_len;
      logical.data_off += o.data_len;
    }
  }
  t.tx_gate_rate = 0;
  t.tx_burst_start = false;
  const std::uint16_t id = t.ip_id;
  t.ip_id = static_cast<std::uint16_t>(t.ip_id + segments);
  const auto stride = static_cast<std::uint16_t>(aggregate ? o.data_len : 0);
  core_.send_ipv4(t.tuple.remote.addr, ip_proto_tcp, id, std::move(*buf), t.self.slot,
                  stride, partial);
  return true;
}

void TcpEngine::record_segment(Tcb& t, Time now, const SegOut& o, Seq32 ack_seq,
                                std::uint16_t field) {
  const bool syn = (o.flags & tcp_syn) != 0;
  const bool rst = (o.flags & tcp_rst) != 0;
  const bool ack = (o.flags & tcp_ack) != 0;
  // Bookkeeping (§4.9, §4.11), before the trace so it shows the state after
  // the send.
  StackStats& st = core_.stats();
  if (ack && t.have_irs) {
    t.ackp.on_ack_sent(now);
    if (t.stream) t.stream->sackgen.on_ack_sent();
    t.last_ack_sent = ack_seq;
  }
  const bool carries = !syn && !rst && (o.data_len > 0 || (o.flags & tcp_fin) != 0) &&
                       o.kind != TxKind::zwp;
  if (carries) {
    const Counters& k = t.counters();
    // Linux tcp_event_data_sent (tcp_output.c:185, from __tcp_transmit_skb
    // at 1669-1670 for every skb with payload, retransmissions included; not
    // for a bare FIN): tx_start when nothing is in flight before this
    // segment, and lsndtime = now (M2-DESIGN §2.1 item 8; an RTO
    // retransmission after everything was marked lost starts a new
    // transmission period).
    if (o.data_len > 0) {
      if (packets_in_flight(k) == 0) {
        refresh_cc(t, now);
        observe_cc(t, TraceTrigger::tx_start, nullptr, [&](RecoveryTransition) {
          t.algo().cwnd_event(t.stream->cc_conn, CaEvent::tx_start);
        });
        t.rate.app_limited = t.stream->cc_conn.app_limited;
        // tcp_event_data_sent precedes tcp_update_skb_after_send. An idle
        // BBR sender can select a new rate for the very burst now leaving.
        if (t.tx_gate_rate != 0) {
          t.tx_gate_rate = t.txp.gate_rate(t.stream->cc_conn);
        }
        t.stream->recovery.observe_cc_event(t.stream->cc_conn, CaEvent::tx_start);  // test seam
      }
      t.lsndtime = now;
    }
    rate_on_send(t.rate, k.packets_out, now);
    // A new transmission epoch resets delivered_mstamp. BBR reads it on
    // loss timer expiry even when no ACK has refreshed the CC view since.
    t.stream->cc_conn.delivered_time = t.rate.delivered_time;
    // A loss probe that resends a sent segment goes through Linux
    // __tcp_retransmit_skb only (tcp_send_loss_probe): no retrans_out, no
    // retrans_stamp (M2-DESIGN §1.7).
    const bool probe = o.retrans && o.kind == TxKind::tlp;
    const TxSeg& seg = t.stream->sndq.on_transmit(o.data_off, o.data_len, (o.flags & tcp_fin) != 0, now,
                                          t.rate, probe);
    RecoveryCtx c = rctx(t, now);
    t.stream->recovery.on_transmit(c, seg, o.kind);
    if (o.retrans) {
      if (!probe && !t.stream->retrans_stamp) {
        t.stream->retrans_stamp = now;  // Linux tcp_retransmit_skb
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
  trace_tx(t, o.kind, o.seq, ack_seq, o.data_len, field, o.flags);
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
    t.stream->sndq.split(seg.off, mss);
    seg = *t.stream->sndq.find(seg.off);
  }
  SegOut o;
  o.seq = seq_at(t.snd_base(), seg.off);
  o.flags = tcp_ack;
  if (seg.fin) {
    o.flags |= tcp_fin;
  }
  if (seg.len > 0 && seg.end() == t.stream->sndq.end()) {
    o.flags |= tcp_psh;
  }
  o.data_off = seg.off;
  o.data_len = seg.len;
  o.kind = kind;
  o.retrans = true;
  return send_segment(t, now, o);
}

bool TcpEngine::send_new_data(Tcb& t, Time now, std::uint32_t len, bool fin,
                               std::uint32_t segments) {
  SegOut o;
  const std::uint64_t off = t.stream->sndq.nxt();
  o.seq = seq_at(t.snd_base(), off);
  o.flags = tcp_ack;
  if (fin) {
    o.flags |= tcp_fin;
  }
  if (len > 0 && off + len == t.stream->sndq.end()) {
    o.flags |= tcp_psh;  // the last queued byte (Linux tcp_mark_push on the tail)
  }
  o.data_off = off;
  o.data_len = len;
  o.kind = len > 0 ? TxKind::data : TxKind::fin;
  return send_segment(t, now, o, segments);
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
  if (t.fin_queued) activate_stream(t);
  if (t.stream && sends_data(t.state) && t.syn_acked) {
    auto& stream = *t.stream;
    refresh_cc(t, now);
    CcConn& cc = stream.cc_conn;
    bool cwnd_limited = false, rwnd_limited = false, blocked = false, paced_out = false;
    std::uint32_t sent = 0, new_sent = 0;
    const std::uint32_t mss = mss_now(t);
    // The pacing gate (§5.5, M2-DESIGN §2.5) applies to new data and, as
    // Linux tcp_xmit_retransmit_queue checks tcp_pacing_check before each
    // retransmission, to the lost segments; every paced send moves
    // pacing_next (tcp_update_skb_after_send).
    const bool pacing = cc.paced && t.txp.gate_rate(cc) != 0;
    // Linux sets the departure stamp of every skb to at least now; after
    // incrementing data_segs_out it charges the full skb reaching ten.
    const auto finish_burst = [&](std::uint64_t bytes) {
      if (t.txp.pacing_applies(cc, t.ctr.data_segs_out)) {
        stream.pacing_next = pacing_next_after_send(stream.pacing_next, now, bytes, t.txp.gate_rate(cc));
      } else {
        stream.pacing_next = std::max(stream.pacing_next, now);
      }
    };
    const auto hold_for_pacing = [&] {
      if (core_.timers().deadline(t.t_pace) != stream.pacing_next) {
        core_.timers().arm(t.t_pace, stream.pacing_next);
        trace_timer(t, TraceTimer::pace, TimerOp::armed);
      }
      paced_out = true;
    };
    // One retransmission, after the caller passed the pacing gate; returns
    // the bytes sent (retransmit_seg may cut the segment to the current MSS).
    const auto paced_retransmit = [&](const TxSeg& seg, TxKind kind,
                                      bool burst_start) -> std::optional<std::uint32_t> {
      if (pacing) {
        t.tx_gate_rate = t.txp.gate_rate(cc);
        t.tx_burst_start = burst_start;
      }
      if (!core_.can_transmit() || !retransmit_seg(t, now, seg, kind)) {
        t.tx_gate_rate = 0;
        t.tx_burst_start = false;
        blocked = true;
        return std::nullopt;
      }
      ++sent;
      const TxSeg* s = stream.sndq.find(seg.off);
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
    for (std::size_t i = 0; lost_seen < t.counters().lost_out; ++i) {
      const std::span<const TxSeg> segs = stream.sndq.segs();
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
      const bool exempt = stream.recovery.exempt_from_cwnd(rc, seg);
      if (!exempt && packets_in_flight(t.counters()) >= cc.cwnd) {
        cwnd_limited = true;
        break;
      }
      // Linux tcp_retransmit_skb: beyond the receive window only the head.
      if (i != 0 && seg.off >= stream.sndq.una() + t.snd_wnd) {
        break;
      }
      const TxKind kind = exempt ? TxKind::fast_rexmit
                          : stream.pmtu_rexmit_end && seg.off < *stream.pmtu_rexmit_end ? TxKind::pmtu_rexmit
                                                                              : TxKind::rexmit;
      if (pacing && !in_burst) {
        rtx_left = pacing_burst_segments(t.txp.gate_rate(cc), t.rtt.min_rtt(), cfg_.gso_max_size, mss,
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
    while (!blocked && !paced_out && stream.sndq.nxt() < stream.sndq.end()) {
      const std::uint32_t in_flight = packets_in_flight(t.counters());
      if (in_flight >= cc.cwnd) {
        cwnd_limited = true;
        break;
      }
      const std::uint64_t una = stream.sndq.una(), nxt = stream.sndq.nxt(), end = stream.sndq.end();
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
        burst_left = pacing_burst_segments(t.txp.gate_rate(cc), t.rtt.min_rtt(), cfg_.gso_max_size, mss,
                                           t.algo().min_tso_segs(cc));
        burst_bytes = 0;
        burst_start = true;
      }
      if (pacing) {
        t.tx_gate_rate = t.txp.gate_rate(cc);
        t.tx_burst_start = burst_start;
      }
      // Full-sized fresh segments share one header and leave at the same
      // instant. Leave PSH/FIN and SACK options on the regular path. The
      // RFC 5681 window and RFC 9293 sender SWS checks still apply to each
      // logical segment; recovery never submits a retransmission here.
      std::uint32_t segments = 1;
      if (core_.gso_pool().available() > 0 && len == mss && unsent > mss &&
          stream.rcvq.ooo_ranges().empty() && !stream.sackgen.dsack_pending()) {
        constexpr std::uint32_t max_gso_segments = 64;
        constexpr auto header_budget = static_cast<std::uint32_t>(ipv4_header_len + tcp_header_max_len);
        const std::uint32_t max_bytes = std::min(
            cfg_.gso_max_size, gso_packet_buf_size - core_.config().tx_headroom - header_budget);
        const std::uint64_t quota = std::min({std::uint64_t{cc.cwnd - in_flight},
                                             usable / mss, (unsent - 1) / mss,
                                             std::uint64_t{max_bytes / mss},
                                             std::uint64_t{pacing ? burst_left : max_gso_segments},
                                             std::uint64_t{max_gso_segments}});
        segments = static_cast<std::uint32_t>(std::max<std::uint64_t>(1, quota));
      }
      if (!core_.can_transmit() || !send_new_data(t, now, len, fin, segments)) {
        t.tx_gate_rate = 0;
        t.tx_burst_start = false;
        blocked = true;
        break;
      }
      sent += segments;
      new_sent += segments;
      if (pacing) {
        burst_bytes += len * segments;
        burst_left -= segments;
        if (burst_left == 0) {
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
    if (!blocked && t.fin_queued && !stream.sndq.fin_sent() && stream.sndq.nxt() == stream.sndq.end()) {
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
        (rwnd_limited || (stream.sndq.nxt() == stream.sndq.end() && (!t.fin_queued || stream.sndq.fin_sent())))) {
      for (std::size_t n = stream.sndq.segs().size(); n > 0; --n) {
        if (packets_in_flight(t.counters()) >= cc.cwnd) {
          cwnd_limited = true;
          break;
        }
        RecoveryCtx rc = rctx(t, now);
        const std::optional<std::uint64_t> off = stream.recovery.next_seg_extra(rc);
        const TxSeg* s = off ? stream.sndq.find(*off) : nullptr;
        if (s == nullptr || s->sacked) {
          break;
        }
        // retransmit_seg cuts a segment longer than the current MSS; the tail
        // of a segment not marked lost stays in flight, so the cut adds a
        // packet to in_flight besides the retransmission.
        const std::uint32_t need = s->len > mss && !s->lost ? 2u : 1u;
        if (packets_in_flight(t.counters()) + need > cc.cwnd) {
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
    const Counters& k = t.counters();
    cwnd_limited = cwnd_limited || packets_in_flight(k) >= cc.cwnd;
    if (new_sent > 0 || cwnd_limited) {
      if (stream.sndq.una() >= stream.cwnd_usage_seq || cwnd_limited ||
          (!cc.cwnd_limited && k.packets_out > cc.max_packets_out)) {
        cc.cwnd_limited = cwnd_limited;
        cc.max_packets_out = k.packets_out;
        stream.cwnd_usage_seq = stream.sndq.nxt();
      }
      // The network starves because of the send buffer (§10.1, M2-DESIGN
      // §5.3; tcp_cwnd_validate, tcp_output.c:2177-2180): data was sent, cwnd
      // does not limit, nothing unsent is left and the application was
      // refused (SOCK_NOSPACE). A refused write with data still held by the
      // window or cwnd stays rwnd_limited or busy.
      if (!is_cwnd_limited(cc) && stream.sndq.nxt() == stream.sndq.end() && t.send_blocked &&
          (t.state == TcpState::established || t.state == TcpState::close_wait)) {
        chrono_start(t, ChronoType::sndbuf_limited, now);
      }
    }
    // Linux tcp_write_xmit schedules the loss probe after sending new data
    // (sent_pkts > 0, push_one != 2).
    RecoveryCtx rc = rctx(t, now);
    stream.recovery.on_burst_end(rc, new_sent > 0);
  }
  flush_ack(t, now);
  sync_timers(t, now);
}

}  // namespace utcp
