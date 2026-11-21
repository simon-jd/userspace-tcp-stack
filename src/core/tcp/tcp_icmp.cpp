// ICMP errors for TCP connections (DESIGN §4.7, §4.13; RFC 5927, RFC 1122
// §4.2.3.9, RFC 1191; Linux tcp_v4_err).
#include "core/stack_impl.hpp"
#include "core/tcp/tcp_engine.hpp"
#include "core/wire/icmp.hpp"

namespace utcp {

void TcpEngine::on_icmp_error(Time now, const TcpIcmpError& err) {
  const auto slot = conns_.find(err.tuple);
  if (!slot) {
    return;  // TIME-WAIT entries and unknown tuples ignore ICMP
  }
  Tcb& t = at(*slot);
  // RFC 5927 §4.1: the quoted sequence number must be in flight.
  if (before(err.seq, t.snd_una()) || !before(err.seq, t.snd_nxt())) {
    ++core_.stats().icmp_seq_invalid;
    return;
  }
  if (core_.tracing(TraceKind::icmp)) {
    TraceEvent e = trace_base(t, TraceKind::icmp);
    e.seq = err.seq.raw();
    e.len = err.new_pmtu;
    core_.trace(e);
  }
  if (err.type == wire::icmp_dest_unreach && err.code == wire::icmp_frag_needed) {
    if (err.new_pmtu == 0) {
      return;
    }
    // §4.13 (Linux tcp_v4_mtu_reduced, inet_csk_update_pmtu): the cache
    // takes the value after the sequence check (it only ever lowers); the
    // connection acts only on a reduction of its own PMTU and never raises
    // it (RFC 1191 §6.1).
    core_.pmtu_lower(t.tuple.remote.addr, err.new_pmtu);
    if (err.new_pmtu >= t.pmtu) {
      ++core_.stats().icmp_pmtu_not_reduced;
      return;
    }
    t.pmtu = err.new_pmtu;
    update_mss(t);
    if (t.stream && t.syn_acked && t.synchronized()) {
      observe_cc(t, TraceTrigger::pmtu, nullptr, [&](RecoveryTransition observe) {
        RecoveryCtx c = rctx(t, now);
        c.on_transition = observe;
        t.stream->recovery.on_pmtu_drop(c);
      });
      if (t.counters().lost_out > 0) {
        t.stream->pmtu_rexmit_end = t.stream->sndq.nxt();
      }
      transmit(t, now);
    }
    return;
  }
  Error e = Error::host_unreachable;
  bool hard = false;
  if (err.type == wire::icmp_dest_unreach) {
    switch (err.code) {
      case wire::icmp_net_unreach:
        e = Error::network_unreachable;
        break;
      case wire::icmp_proto_unreach:
      case wire::icmp_port_unreach:
        e = Error::connection_refused;
        hard = true;
        break;
      default:
        break;
    }
  }
  // RFC 1122 §4.2.3.9: hard errors abort only a connection being opened;
  // otherwise the error is soft (reported at a timeout or by take_error).
  if (hard && t.state == TcpState::syn_sent) {
    close_conn(t, CloseCause::refused, e);
    return;
  }
  t.soft_error = e;
}

}  // namespace utcp
