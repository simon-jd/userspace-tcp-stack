// The output path (DESIGN §4.9) and segment construction (§4.5).
#include <algorithm>
#include <array>
#include <limits>

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
    if (!o.retrans && packets_in_flight(k) == 0) {
      refresh_cc(t, now);
      t.algo().cwnd_event(t.cc_conn, CaEvent::tx_start);
    }
    rate_on_send(t.rate, k.packets_out, now);
    const TxSeg& seg =
        t.sndq.on_transmit(o.data_off, o.data_len, (o.flags & tcp_fin) != 0, now, t.rate);
    RecoveryCtx c = rctx(t, now);
    t.recovery.on_transmit(c, seg, o.kind);
    if (o.retrans) {
      if (!t.retrans_stamp) {
        t.retrans_stamp = now;  // Linux tcp_retransmit_skb
      }
    } else {
      t.txp.on_data_sent(o.data_off, o.data_len, mss_now(t));
      if (o.data_len > 0) {
        ++st.TcpExtTCPOrigDataSent;
      }
      t.lsndtime = now;
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
// Nagle, pacing, transmit space), FIN, then the ACK owed.
void TcpEngine::transmit(Tcb& t, Time now) {
  if (t.state == TcpState::closed || t.state == TcpState::time_wait || t.listen) {
    return;
  }
  if (sends_data(t.state) && t.syn_acked) {
    refresh_cc(t, now);
    CcConn& cc = t.cc_conn;
    bool cwnd_limited = false, rwnd_limited = false, blocked = false;
    std::uint32_t sent = 0;
    // 1. Segments marked lost (RFC 6582, RFC 5681 §3.2; Linux
    // tcp_xmit_retransmit_queue). The fast retransmit is exempt from the
    // cwnd gate (RFC 6675 §5 (4.3)).
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
      const bool fast = i == 0 && t.recovery.fast_rexmit_pending();
      if (!fast && packets_in_flight(t.sndq.counters()) >= cc.cwnd) {
        cwnd_limited = true;
        break;
      }
      // Linux tcp_retransmit_skb: beyond the receive window only the head.
      if (i != 0 && seg.off >= t.sndq.una() + t.snd_wnd) {
        break;
      }
      const TxKind kind = fast ? TxKind::fast_rexmit
                          : t.pmtu_rexmit_end && seg.off < *t.pmtu_rexmit_end ? TxKind::pmtu_rexmit
                                                                              : TxKind::rexmit;
      if (!core_.can_transmit() || !retransmit_seg(t, now, seg, kind)) {
        blocked = true;
        break;
      }
      ++sent;
    }
    // 2. New data.
    const std::uint32_t mss = mss_now(t);
    const bool pacing = t.txp.pacing_applies(cc, t.ctr.data_segs_out);
    const std::uint64_t rate = pacing ? t.txp.gate_rate(cc) : 0;
    std::uint32_t burst_left = 0;
    std::uint64_t burst_bytes = 0;
    while (!blocked && t.sndq.nxt() < t.sndq.end()) {
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
      if (pacing && burst_left == 0) {
        if (now < t.pacing_next) {
          if (core_.timers().deadline(t.t_pace) != t.pacing_next) {
            core_.timers().arm(t.t_pace, t.pacing_next);
            trace_timer(t, TraceTimer::pace, TimerOp::armed);
          }
          break;
        }
        burst_left = pacing_burst_segments(rate, t.rtt.min_rtt(), cfg_.gso_max_size, mss,
                                           t.algo().min_tso_segs());
        burst_bytes = 0;
      }
      if (!core_.can_transmit() || !send_new_data(t, now, len, fin)) {
        blocked = true;
        break;
      }
      ++sent;
      if (pacing) {
        burst_bytes += len;
        if (--burst_left == 0) {
          t.pacing_next = pacing_next_after_send(t.pacing_next, now, burst_bytes, rate);
        }
      }
    }
    if (pacing && burst_left > 0 && burst_bytes > 0) {
      t.pacing_next = pacing_next_after_send(t.pacing_next, now, burst_bytes, rate);
    }
    // 3. A FIN with no data left to carry it. Like Linux tcp_cwnd_test, the
    // final bare FIN is exempt from the cwnd gate; it is sent at the window
    // edge too (deviation, DESIGN §4.9).
    if (!blocked && t.fin_queued && !t.sndq.fin_sent() && t.sndq.nxt() == t.sndq.end()) {
      if (!core_.can_transmit() || !send_new_data(t, now, 0, true)) {
        blocked = true;
      } else {
        ++sent;
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
    // Linux tcp_cwnd_validate.
    const Counters& k = t.sndq.counters();
    cwnd_limited = cwnd_limited || packets_in_flight(k) >= cc.cwnd;
    if (sent > 0 || cwnd_limited) {
      if (t.sndq.una() >= t.cwnd_usage_seq || cwnd_limited ||
          (!cc.cwnd_limited && k.packets_out > cc.max_packets_out)) {
        cc.cwnd_limited = cwnd_limited;
        cc.max_packets_out = k.packets_out;
        t.cwnd_usage_seq = t.sndq.nxt();
      }
    }
    RecoveryCtx rc = rctx(t, now);
    t.recovery.on_burst_end(rc);
  }
  flush_ack(t, now);
  sync_timers(t, now);
}

}  // namespace utcp
