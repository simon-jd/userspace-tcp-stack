// The tcp_* socket API (DESIGN §3.5).
#include <algorithm>
#include <array>
#include <vector>

#include "core/stack_impl.hpp"
#include "core/tcp/tcp_engine.hpp"
#include "utcp/check.hpp"

namespace utcp {

namespace {

[[nodiscard]] bool valid_options(const TcpSocketOptions& o, CcAlgo fallback) {
  const auto cc = o.cc.value_or(fallback);
  if (cc != CcAlgo::newreno && cc != CcAlgo::cubic && cc != CcAlgo::bbr) {
    return false;
  }
  if (o.rcv_buf && *o.rcv_buf == 0) {
    return false;
  }
  if (o.snd_buf && *o.snd_buf == 0) {
    return false;
  }
  return !(o.mss_clamp && *o.mss_clamp == 0);
}

}  // namespace

std::expected<Handle, Error> TcpEngine::tcp_listen(Endpoint local, std::uint32_t backlog,
                                                   const TcpSocketOptions& opts) {
  if (local.port == 0 || !valid_options(opts, cfg_.cc)) {
    return std::unexpected(Error::invalid_argument);
  }
  if (local.addr.v != 0 && local.addr != core_.local_addr()) {
    return std::unexpected(Error::addr_not_available);
  }
  if (listener_for(local.port)) {
    return std::unexpected(Error::addr_in_use);
  }
  Tcb* p = alloc_tcb(resolve(opts));
  if (p == nullptr) {
    return std::unexpected(Error::no_buffers);
  }
  Tcb& t = *p;
  t.tuple = FourTuple{Endpoint{core_.local_addr(), local.port}, Endpoint{}};
  t.listen = ListenState{};
  t.listen->backlog = backlog;
  t.app_holds = true;
  listener_add(local.port, t.self.slot);
  set_state(t, TcpState::listen);
  return t.self;
}

std::expected<Handle, Error> TcpEngine::tcp_accept(Handle listener) {
  Tcb* l = find(listener);
  if (l == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (!l->listen) {
    return std::unexpected(Error::invalid_state);
  }
  ListenState& ls = *l->listen;
  if (ls.accept_q.empty()) {
    return std::unexpected(Error::would_block);
  }
  const std::uint32_t slot = ls.accept_q.front();
  ls.accept_q.pop_front();
  Tcb& c = at(slot);
  c.listener.reset();
  c.app_holds = true;
  return c.self;
}

std::expected<Handle, Error> TcpEngine::tcp_connect(Endpoint remote, const TcpSocketOptions& opts,
                                                    std::uint16_t local_port) {
  if (remote.addr.v == 0 || remote.port == 0 || !valid_options(opts, cfg_.cc)) {
    return std::unexpected(Error::invalid_argument);
  }
  std::uint16_t port = local_port;
  if (port == 0) {
    const auto p = core_.tcp_ephemeral_port(remote);
    if (!p) {
      return std::unexpected(p.error());
    }
    port = *p;
  }
  const FourTuple tuple{Endpoint{core_.local_addr(), port}, remote};
  if (tuple_in_use(tuple)) {
    return std::unexpected(Error::addr_in_use);
  }
  Tcb* p = alloc_tcb(resolve(opts));
  if (p == nullptr) {
    return std::unexpected(Error::no_buffers);
  }
  Tcb& t = *p;
  const Time now = core_.now();
  t.tuple = tuple;
  t.app_holds = true;
  t.pmtu = core_.pmtu(remote.addr);
  t.iss = cfg_.test_isn ? Seq32{*cfg_.test_isn} : core_.isn(tuple);
  t.ts_offset = core_.ts_offset(tuple);
  t.ip_id = core_.ip_id_start(tuple);
  t.syn_wnd = t.rwin.syn_window(t.adv_mss);
  // Until the peer's MSS is known (§4.13).
  t.peer_mss = cfg_.default_snd_mss;
  update_mss(t);
  const bool inserted = conns_.insert(tuple, t.self.slot);
  UTCP_CHECK(inserted);
  t.in_conn_table = true;
  set_state(t, TcpState::syn_sent);
  ++core_.stats().TcpActiveOpens;
  send_syn(t, now);
  core_.timers().arm(t.t_xmit, now + t.rtt.rto_backed_off(0));
  t.xmit_kind = XmitTimer::rto;
  trace_timer(t, TraceTimer::rto, TimerOp::armed);
  return t.self;
}

std::expected<std::size_t, Error> TcpEngine::tcp_send(Handle h, std::span<const std::byte> data) {
  Tcb* p = find(h);
  if (p == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  Tcb& t = *p;
  if (t.listen) {
    return std::unexpected(Error::not_connected);
  }
  if (t.error) {
    return std::unexpected(*t.error);
  }
  if (t.app_write_shut || t.fin_queued) {
    return std::unexpected(Error::shut_down);
  }
  switch (t.state) {
    case TcpState::syn_sent:
    case TcpState::syn_received:  // §3.5: queued, sent once ESTABLISHED
    case TcpState::established:
    case TcpState::close_wait:
      break;
    default:
      return std::unexpected(Error::shut_down);
  }
  if (data.empty()) {
    return 0;
  }
  const Time now = core_.now();
  const Counters& k = t.sndq.counters();
  if (t.syn_acked) {
    // §5.4: the application-limited marker (Linux tcp_sendmsg_locked).
    rate_check_app_limited(t.rate, t.sndq.end() - t.sndq.nxt(), t.mss_cache,
                           core_.queued_for(t.self.slot) > 0, packets_in_flight(k),
                           t.cc_conn.cwnd, k.lost_out, k.retrans_out);
    // RFC 5681 §4.1 (Linux tcp_slow_start_after_idle_check from tcp_skb_entail).
    if (k.packets_out == 0 && t.sndq.end() == t.sndq.nxt()) {
      refresh_cc(t, now);
      cwnd_restart(t.cc_conn, t.algo(), cfg_.idle_restart, now - t.lsndtime,
                   t.rtt.rto_backed_off(t.backoff), initial_window(t));
    }
  }
  const std::uint64_t space = t.sndq.free_space();
  const std::size_t n = t.sndq.write(data);
  if (n < data.size()) {
    t.send_blocked = true;  // sndbuf_limited is transmit's (tcp_cwnd_validate)
    if (n < space) {
      wait_for_chunks(t);  // the buffer had room, the ChunkPool did not
    }
  }
  if (n == 0) {
    return std::unexpected(Error::would_block);
  }
  transmit(t, now);
  return n;
}

std::expected<std::size_t, Error> TcpEngine::tcp_recv(Handle h, std::span<std::byte> out) {
  Tcb* p = find(h);
  if (p == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  Tcb& t = *p;
  if (t.listen) {
    return std::unexpected(Error::not_connected);
  }
  if (t.state == TcpState::syn_sent || t.state == TcpState::syn_received) {
    return std::unexpected(Error::would_block);
  }
  if (t.app_read_shut || out.empty()) {
    return 0;
  }
  const std::size_t n = t.rcvq.read(out);
  if (n > 0) {
    const Time now = core_.now();
    // Linux tcp_recvmsg: tcp_rcv_space_adjust, then tcp_cleanup_rbuf.
    if (const auto grown = t.rwin.on_read(now, t.rcvq.read_offset())) {
      t.rcvq.grow(*grown);
    }
    if (t.synchronized() && t.state != TcpState::time_wait) {
      t.ackp.on_read(t.rwin.ack_view(t.rcvq, t.ackp.rcv_mss()));
      if (t.rwin.update_after_read(t.rcvq, t.ackp.rcv_mss())) {
        t.ackp.ack_now();
      }
      flush_ack(t, now);
      sync_timers(t, now);
    }
    wake_chunk_waiters();
    return n;
  }
  if (t.fin_rcvd) {
    return 0;
  }
  if (t.error) {
    return std::unexpected(*t.error);
  }
  if (t.state == TcpState::closed || t.state == TcpState::time_wait) {
    return 0;
  }
  return std::unexpected(Error::would_block);
}

std::expected<void, Error> TcpEngine::tcp_shutdown(Handle h, Shutdown how) {
  Tcb* p = find(h);
  if (p == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  Tcb& t = *p;
  if (t.listen || t.state == TcpState::closed || t.state == TcpState::time_wait) {
    return std::unexpected(Error::not_connected);
  }
  const Time now = core_.now();
  if (how == Shutdown::read || how == Shutdown::both) {
    t.app_read_shut = true;
    t.rcvq.discard_readable();
    wake_chunk_waiters();
  }
  if ((how == Shutdown::write || how == Shutdown::both) && !t.app_write_shut) {
    t.app_write_shut = true;
    // RFC 9293 §3.10.4: FIN-WAIT-1 or LAST-ACK once the FIN is queued; in a
    // SYN state the FIN waits for ESTABLISHED (handshake_done).
    if (t.state == TcpState::established) {
      t.fin_queued = true;
      set_state(t, TcpState::fin_wait_1);
    } else if (t.state == TcpState::close_wait) {
      t.fin_queued = true;
      set_state(t, TcpState::last_ack);
    }
  }
  transmit(t, now);
  return {};
}

std::expected<void, Error> TcpEngine::tcp_close(Handle h) {
  Tcb* p = find(h);
  if (p == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  Tcb& t = *p;
  const Time now = core_.now();
  core_.drop_events(t.self);
  t.app_holds = false;
  if (t.listen) {
    // Linux inet_csk_listen_stop: children in SYN-RECEIVED go silently,
    // established ones not accepted are reset.
    const std::uint32_t ls = t.self.slot;
    for (std::uint32_t i = 0; i < slots_.size(); ++i) {
      if (!slots_[i].tcb || slots_[i].tcb->listener != ls) {
        continue;
      }
      Tcb& c = *slots_[i].tcb;
      if (c.state != TcpState::syn_received && c.synchronized()) {
        send_rst(c, now);
      }
      close_conn(c, CloseCause::listener_closed);
    }
    set_state(t, TcpState::closed, CloseCause::listener_closed);
    free_tcb(t);
    return {};
  }
  switch (t.state) {
    case TcpState::closed:
    case TcpState::time_wait:
      free_tcb(t);  // a zombie: the connection already ended
      return {};
    case TcpState::syn_sent:
      close_conn(t, CloseCause::aborted);
      return {};
    default:
      break;
  }
  t.orphan = true;
  // RFC 9293 §3.10.4, RFC 2525 §2.17 (Linux tcp_close): unread data resets.
  if (t.rcvq.readable() > 0 && !t.app_read_shut) {
    ++core_.stats().TcpExtTCPAbortOnClose;
    send_rst(t, now);
    close_conn(t, CloseCause::aborted);
    return {};
  }
  t.app_read_shut = true;
  t.app_write_shut = true;
  switch (t.state) {
    case TcpState::established:
      t.fin_queued = true;
      set_state(t, TcpState::fin_wait_1);
      break;
    case TcpState::close_wait:
      t.fin_queued = true;
      set_state(t, TcpState::last_ack);
      break;
    case TcpState::fin_wait_2:
      core_.timers().arm(t.t_fin_wait2, now + cfg_.orphan_fin_wait2_timeout);
      trace_timer(t, TraceTimer::fin_wait2, TimerOp::armed);
      break;
    default:
      break;  // SYN-RECEIVED: the FIN follows ESTABLISHED; FIN states: already sent
  }
  transmit(t, now);
  return {};
}

std::expected<void, Error> TcpEngine::tcp_abort(Handle h) {
  Tcb* p = find(h);
  if (p == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  Tcb& t = *p;
  if (t.listen) {
    return tcp_close(h);
  }
  const Time now = core_.now();
  core_.drop_events(t.self);
  t.app_holds = false;
  switch (t.state) {
    case TcpState::closed:
    case TcpState::time_wait:
      free_tcb(t);
      return {};
    // Linux tcp_need_reset.
    case TcpState::established:
    case TcpState::fin_wait_1:
    case TcpState::fin_wait_2:
    case TcpState::close_wait:
    case TcpState::syn_received:
      send_rst(t, now);
      break;
    default:
      break;
  }
  close_conn(t, CloseCause::aborted);
  return {};
}

Readiness TcpEngine::tcp_readiness(Handle h) const {
  Readiness r;
  const Tcb* p = find(h);
  if (p == nullptr) {
    return r;
  }
  const Tcb& t = *p;
  if (t.listen) {
    r.acceptable = !t.listen->accept_q.empty();
    return r;
  }
  const bool ended = t.state == TcpState::closed || t.state == TcpState::time_wait;
  r.has_error = t.error.has_value();
  r.read_closed = t.fin_rcvd || t.app_read_shut || ended;
  r.readable = t.rcvq.readable() > 0 || r.read_closed || r.has_error;
  r.write_closed = t.app_write_shut || t.fin_queued || ended;
  const std::uint64_t queued = t.sndq.held();
  const bool open = t.state == TcpState::established || t.state == TcpState::close_wait;
  // Not writable while the ChunkPool is exhausted, as tcp_send would refuse.
  const ChunkPool& pool = core_.chunks();
  r.writable = (open && !r.write_closed && t.sndq.free_space() > 0 &&
                t.sndq.free_space() >= queued / 2 && pool.in_use() < pool.limit()) ||
               r.write_closed || r.has_error;
  return r;
}

std::expected<TcpInfo, Error> TcpEngine::tcp_info(Handle h) const {
  const Tcb* p = find(h);
  if (p == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  const Tcb& t = *p;
  const Time now = core_.now();
  TcpInfo i;
  i.cc_name.fill('\0');
  i.set_cc_name(const_cast<Tcb&>(t).algo().name());  // NOLINT: name() is const
  i.state = t.state;
  i.ca_state = t.recovery.state();
  i.snd_wscale = t.snd_wscale;
  i.rcv_wscale = t.rcv_wscale;
  i.rto = t.rtt.rto_backed_off(t.backoff);
  i.ato = t.ackp.ato();
  i.srtt = t.rtt.srtt();
  i.rttvar = t.rtt.rttvar();
  i.min_rtt = t.rtt.min_rtt() == Duration::max() ? Duration::zero() : t.rtt.min_rtt();
  i.cwnd = t.cc_conn.cwnd;
  i.ssthresh = t.cc_conn.ssthresh;
  i.snd_mss = t.mss_cache;
  i.rcv_mss = t.ackp.rcv_mss();
  i.adv_mss = t.adv_mss;
  i.pmtu = t.pmtu;
  const Counters& k = t.sndq.counters();
  i.bytes_sent = k.bytes_sent;
  i.bytes_retrans = k.bytes_retrans;
  i.bytes_acked = k.bytes_acked;
  i.bytes_received = t.ctr.bytes_received;
  i.segs_out = t.ctr.segs_out;
  i.segs_in = t.ctr.segs_in;
  i.data_segs_out = t.ctr.data_segs_out;
  i.data_segs_in = t.ctr.data_segs_in;
  i.pacing_rate = t.cc_conn.pacing_rate;
  i.delivered = t.rate.delivered;
  // tcpi_delivery_rate and tcpi_delivery_rate_app_limited come from the
  // record tcp_rate_gen keeps (M2-DESIGN §2.6; tcp_get_info,
  // tcp_compute_delivery_rate), not from tp->app_limited.
  i.delivery_rate = rate_delivery_rate(t.rate, t.mss_cache);
  i.app_limited = t.rate.rate_app_limited;
  // Linux tcp_get_info_chrono_stats: the running interval counts too.
  std::array<Duration, 4> total = t.chrono.total;
  if (t.chrono.type != ChronoType::none) {
    total[static_cast<std::size_t>(t.chrono.type)] += now - t.chrono.start;
  }
  i.busy_time = total[1] + total[2] + total[3];
  i.rwnd_limited = total[2];
  i.sndbuf_limited = total[3];
  i.unacked = k.packets_out;
  i.sacked = k.sacked_out;
  i.lost = k.lost_out;
  i.retrans = k.retrans_out;
  i.total_retrans = static_cast<std::uint32_t>(t.ctr.total_retrans);
  i.dsack_dups = static_cast<std::uint32_t>(t.ctr.dsack_dups);
  // Adaptive reordering is recovery's (M2-DESIGN §1.9).
  i.reordering = t.recovery.reordering(cfg_);
  i.reord_seen = t.recovery.reord_seen();
  i.rcv_rtt = t.rwin.rcv_rtt();
  i.rcv_space = t.rwin.rcv_space();
  i.rcv_ssthresh = t.rwin.rcv_ssthresh();
  i.snd_wnd = t.snd_wnd;
  i.rcv_wnd = t.rcv_wnd;
  i.notsent_bytes = static_cast<std::uint32_t>(t.sndq.end() - t.sndq.nxt());
  i.last_data_sent = now - t.lsndtime;
  i.last_data_recv = now - t.last_data_recv;
  i.last_ack_recv = now - t.last_ack_recv;
  i.conn_id = t.conn_id;
  return i;
}

std::expected<void, Error> TcpEngine::tcp_set_options(Handle h, const TcpSocketOptions& opts) {
  Tcb* p = find(h);
  if (p == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  Tcb& t = *p;
  if (!valid_options(opts, t.opts.cc) || (opts.cc && *opts.cc != t.opts.cc)) {
    return std::unexpected(Error::invalid_argument);
  }
  if (opts.rcv_buf) {
    // RcvWindow needs rcv_buf >= min_rcv_buf(shift); the buffer is sized when
    // the socket is created, so later only a listener (for its children)
    // takes a new one.
    if (*opts.rcv_buf < min_rcv_buf(t.offered_wscale)) {
      return std::unexpected(Error::invalid_argument);
    }
    if (!t.listen) {
      return std::unexpected(Error::invalid_state);
    }
    t.opts.rcv_buf = opts.rcv_buf;
  }
  if (opts.snd_buf) {
    t.opts.snd_buf = opts.snd_buf;
    t.sndq.set_capacity(*opts.snd_buf);
  }
  if (opts.mss_clamp) {
    t.opts.mss_clamp = opts.mss_clamp;
  }
  if (opts.nodelay) {
    t.opts.nodelay = *opts.nodelay;
    if (t.opts.nodelay && !t.listen) {
      transmit(t, core_.now());  // Linux TCP_NODELAY pushes pending data
    }
  }
  return {};
}

std::optional<Error> TcpEngine::take_error(Handle h) {
  Tcb* p = find(h);
  if (p == nullptr) {
    return std::nullopt;
  }
  Tcb& t = *p;
  if (t.error) {
    const Error e = *t.error;
    t.error.reset();
    t.error_reported = true;
    return e;
  }
  if (t.soft_error) {
    const Error e = *t.soft_error;
    t.soft_error.reset();
    return e;
  }
  return std::nullopt;
}

}  // namespace utcp
