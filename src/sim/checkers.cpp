#include "utcp/sim/checkers.hpp"

#include <algorithm>
#include <array>
#include <cstdio>

#include "utcp/retry_model.hpp"
#include "utcp/sim/datagram.hpp"

namespace utcp::sim {

using namespace std::chrono_literals;

namespace {

constexpr std::array<std::string_view, verdict_count> verdict_names{
    "ok", "stream", "termination", "inflight", "progress",
    "leak", "stuck", "livelock", "workload", "planted", "pacing"};

std::string tuple_string(const FourTuple& t) {
  return to_string(t.local) + ">" + to_string(t.remote);
}

std::string conn_string(std::uint32_t node, std::uint32_t conn_id, const FourTuple& t) {
  return "node " + node_name(node) + " conn " + std::to_string(conn_id) + " (" + tuple_string(t) +
         ")";
}

// RFC 9293 §3.3.2: the states after the handshake (TIME-WAIT included).
bool synchronized(TcpState s) noexcept {
  return s >= TcpState::established;
}

std::string hex2(std::byte b) {
  std::array<char, 8> buf{};
  std::snprintf(buf.data(), buf.size(), "0x%02x", std::to_integer<unsigned>(b));
  return buf.data();
}

}  // namespace

std::string_view to_string(Verdict v) noexcept {
  const auto i = static_cast<std::size_t>(v);
  return i < verdict_names.size() ? verdict_names[i] : "?";
}

std::optional<Verdict> verdict_from_string(std::string_view s) noexcept {
  for (std::size_t i = 0; i < verdict_names.size(); ++i) {
    if (verdict_names[i] == s) {
      return static_cast<Verdict>(i);
    }
  }
  return std::nullopt;
}

// --- StreamChecker.

StreamChecker::StreamChecker(const Seed& master) : master_(master) {}

const Pattern& StreamChecker::pattern_(std::string_view kind, std::uint32_t flow,
                                       std::uint8_t dir) {
  const Key key{kind == "udp" ? (flow | 0x8000'0000u) : flow, dir};
  auto it = patterns_.find(key);
  if (it == patterns_.end()) {
    it = patterns_.try_emplace(key, master_, kind, flow, dir).first;
  }
  return it->second;
}

const Pattern& StreamChecker::tcp_pattern(std::uint32_t conn, std::uint8_t dir) {
  return pattern_("tcp", conn, dir);
}

const Pattern& StreamChecker::udp_pattern(std::uint32_t flow, std::uint8_t dir) {
  return pattern_("udp", flow, dir);
}

void StreamChecker::on_written(std::uint32_t conn, std::uint8_t dir, std::uint64_t total) {
  written_[Key{conn, dir}] = total;
}

std::optional<std::string> StreamChecker::on_read(std::uint32_t conn, std::uint8_t dir,
                                                  std::uint64_t offset,
                                                  std::span<const std::byte> data) {
  if (!enabled_) {
    return std::nullopt;
  }
  const Pattern& p = tcp_pattern(conn, dir);
  if (const auto bad = p.mismatch(offset, data)) {
    return "tcp conn " + std::to_string(conn) + (dir == 0 ? " c2s" : " s2c") + ": byte at offset " +
           std::to_string(*bad) + " is " + hex2(data[*bad - offset]) + ", expected " +
           hex2(p.at(*bad));
  }
  return std::nullopt;
}

std::optional<std::string> StreamChecker::on_eof(std::uint32_t conn, std::uint8_t dir,
                                                 std::uint64_t total) {
  if (!enabled_) {
    return std::nullopt;
  }
  const auto it = written_.find(Key{conn, dir});
  const std::uint64_t written = it == written_.end() ? 0 : it->second;
  if (total != written) {
    return "tcp conn " + std::to_string(conn) + (dir == 0 ? " c2s" : " s2c") +
           ": end of stream after " + std::to_string(total) + " bytes, the sender wrote " +
           std::to_string(written);
  }
  return std::nullopt;
}

void StreamChecker::udp_payload(std::uint32_t flow, std::uint8_t dir, std::uint32_t seq,
                                std::span<std::byte> out) {
  const std::array<std::byte, 4> s{static_cast<std::byte>(seq >> 24), static_cast<std::byte>(seq >> 16),
                                   static_cast<std::byte>(seq >> 8), static_cast<std::byte>(seq)};
  const std::size_t head = std::min<std::size_t>(out.size(), 4);
  std::copy_n(s.begin(), head, out.begin());
  if (out.size() > 4) {
    udp_pattern(flow, dir).fill((std::uint64_t{seq} << 16) + 4, out.subspan(4));
  }
}

std::optional<std::string> StreamChecker::on_datagram(std::uint32_t flow, std::uint8_t dir,
                                                      std::span<const std::byte> payload) {
  if (!enabled_ || payload.size() < 4) {
    return std::nullopt;
  }
  const std::uint32_t seq = (std::to_integer<std::uint32_t>(payload[0]) << 24) |
                            (std::to_integer<std::uint32_t>(payload[1]) << 16) |
                            (std::to_integer<std::uint32_t>(payload[2]) << 8) |
                            std::to_integer<std::uint32_t>(payload[3]);
  const Pattern& p = udp_pattern(flow, dir);
  const std::uint64_t base = (std::uint64_t{seq} << 16) + 4;
  if (const auto bad = p.mismatch(base, payload.subspan(4))) {
    return "udp flow " + std::to_string(flow) + " datagram " + std::to_string(seq) + ": byte " +
           std::to_string(*bad - base + 4) + " differs";
  }
  return std::nullopt;
}

// --- TerminationChecker.

void TerminationChecker::on_trace(std::uint32_t node, const TraceEvent& e) {
  if (e.kind == TraceKind::tx && e.tx == TxKind::rst) {
    // Kept apart from the connection record: the RST may come before or
    // after the state event to CLOSED.
    rst_sent_.insert(std::make_pair(node, e.conn_id));
    return;
  }
  if (e.kind != TraceKind::state) {
    return;
  }
  const auto key = std::make_pair(node, e.conn_id);
  auto it = by_id_.find(key);
  if (it == by_id_.end()) {
    Conn c;
    c.node = node;
    c.conn_id = e.conn_id;
    c.tuple = e.tuple;
    c.start = e.t;
    c.listener = e.state == TcpState::listen;
    c.passive = e.state == TcpState::syn_received;
    conns_.push_back(c);
    it = by_id_.emplace(key, conns_.size() - 1).first;
  }
  Conn& c = conns_[it->second];
  if (c.closed) {
    return;  // conn_ids are not reused; nothing follows CLOSED
  }
  if (e.state == TcpState::closed) {
    c.closed = true;
    c.before_close = c.state;
    c.cause = e.cause;
    c.end = e.t;
  } else {
    c.state = e.state;
    if (c.tuple.remote.port == 0 && e.tuple.remote.port != 0) {
      c.tuple = e.tuple;
    }
  }
}

void TerminationChecker::on_app_close(std::uint32_t node, std::uint32_t conn_id, Time t) {
  // A connection without state events yet cannot have sent anything; only
  // known connections matter.
  const auto it = by_id_.find(std::make_pair(node, conn_id));
  if (it == by_id_.end()) {
    return;
  }
  Conn& c = conns_[it->second];
  if (!c.app_close) {
    c.app_close = t;
  }
}

std::size_t TerminationChecker::open_connections() const noexcept {
  std::size_t n = 0;
  for (const Conn& c : conns_) {
    n += c.closed ? 0u : 1u;
  }
  return n;
}

const TerminationChecker::Conn* TerminationChecker::peer_of(const Conn& c) const {
  const Conn* best = nullptr;
  for (const Conn& p : conns_) {
    if (p.node == c.node || p.listener || p.tuple.local != c.tuple.remote ||
        p.tuple.remote != c.tuple.local || p.start > c.end) {
      continue;
    }
    if (best == nullptr || p.start >= best->start) {
      best = &p;
    }
  }
  return best;
}

std::optional<std::string> TerminationChecker::judge(const Conn& c) const {
  if (relaxed_) {
    return std::nullopt;
  }
  const Conn* peer = peer_of(c);
  const bool peer_ended = peer != nullptr && peer->closed && peer->end <= c.end;
  switch (c.cause) {
    case CloseCause::last_ack:
    case CloseCause::time_wait_expired:
    case CloseCause::time_wait_reused:
    case CloseCause::synack_timed_out:
      return std::nullopt;
    case CloseCause::timed_out:
      // §4.7, §4.8: retry exhaustion in a synchronized state sends RST.
      if (synchronized(c.before_close) && !rst_sent_.contains(std::make_pair(c.node, c.conn_id))) {
        return "timed_out in a synchronized state without sending RST";
      }
      return std::nullopt;
    case CloseCause::fin_wait2_timeout:
      if (c.before_close != TcpState::fin_wait_2) {
        return "fin_wait2_timeout outside FIN-WAIT-2";
      }
      // §4.12: only an orphan (closed by its application) times out there.
      if (!c.app_close || *c.app_close > c.end) {
        return "fin_wait2_timeout of a connection its application had not closed";
      }
      return std::nullopt;
    case CloseCause::aborted:
      if (c.app_close && *c.app_close <= c.end) {
        return std::nullopt;
      }
      return "RST sent without an application close or abort";
    case CloseCause::listener_closed: {
      if (c.listener && c.app_close) {
        return std::nullopt;
      }
      for (const Conn& l : conns_) {
        if (l.node == c.node && l.listener && l.tuple.local.port == c.tuple.local.port &&
            l.app_close && *l.app_close <= c.end) {
          return std::nullopt;
        }
      }
      return "listener_closed without a closed listener";
    }
    case CloseCause::rst_received: {
      if (!peer_ended) {
        return "RST received while the peer's connection was still open";
      }
      switch (peer->cause) {
        case CloseCause::aborted:
        case CloseCause::timed_out:
        case CloseCause::synack_timed_out:
        case CloseCause::listener_closed:
        case CloseCause::child_reset:
        case CloseCause::refused:
        case CloseCause::time_wait_rst:
          return std::nullopt;
        default:
          break;
      }
      switch (c.before_close) {
        case TcpState::fin_wait_1:
        case TcpState::fin_wait_2:
        case TcpState::closing:
        case TcpState::last_ack:
          return std::nullopt;
        case TcpState::close_wait:
          // We acked the peer's FIN, so it was in FIN-WAIT-2; as an orphan it
          // timed out there and answers our data or FIN with RST (§4.12;
          // Linux tcp_fin_timeout, after which no socket matches).
          if (peer->cause == CloseCause::fin_wait2_timeout) {
            return std::nullopt;
          }
          break;
        default:
          break;
      }
      return "RST received in " + std::string(to_string(c.before_close)) +
             " after the peer ended with " + std::string(to_string(peer->cause));
    }
    case CloseCause::refused: {
      const auto mode = design_ ? design_(c.node, c.tuple) : std::nullopt;
      if (mode == CloseMode::refused || peer_ended) {
        return std::nullopt;
      }
      return "connection refused although a listener was designed";
    }
    case CloseCause::child_reset:
    case CloseCause::time_wait_rst:
      if (peer_ended) {
        return std::nullopt;
      }
      return "RST received while the peer's connection was still open";
    case CloseCause::none:
      break;
  }
  return "CLOSED without a cause";
}

std::vector<Violation> TerminationChecker::finish(Time now) const {
  std::vector<Violation> out;
  for (const Conn& c : conns_) {
    if (!c.closed) {
      out.push_back(Violation{Verdict::termination, now,
                              conn_string(c.node, c.conn_id, c.tuple) + " still in state " +
                                  std::string(to_string(c.state))});
    } else if (auto why = judge(c)) {
      out.push_back(Violation{Verdict::termination, c.end,
                              conn_string(c.node, c.conn_id, c.tuple) + " closed with cause " +
                                  std::string(to_string(c.cause)) + " from " +
                                  std::string(to_string(c.before_close)) + ": " + *why});
    }
  }
  return out;
}

// --- InFlightChecker.

std::uint8_t InFlightChecker::peer_shift(const Dir& d) const noexcept {
  // RFC 7323 §2.2: scaling is in effect only if both SYNs carried the
  // option; shifts above 14 are treated as 14 (§2.3).
  if (!d.own_ws || !d.peer_ws) {
    return 0;
  }
  return std::min<std::uint8_t>(*d.peer_ws, max_wscale);
}

void InFlightChecker::add_sack(Dir& d, Seq32 begin, Seq32 end) {
  if (!d.high_ack || !after(end, begin)) {
    return;
  }
  const Seq32 base = *d.high_ack;
  if (!after(end, base)) {
    return;
  }
  if (before(begin, base)) {
    begin = base;
  }
  d.sacked.emplace_back(begin, end);
  // Sort by distance from the cumulative ACK and merge.
  std::sort(d.sacked.begin(), d.sacked.end(), [&](const auto& x, const auto& y) {
    return (x.first - base) < (y.first - base);
  });
  std::vector<std::pair<Seq32, Seq32>> merged;
  for (const auto& r : d.sacked) {
    if (!merged.empty() && !after(r.first, merged.back().second)) {
      if (after(r.second, merged.back().second)) {
        merged.back().second = r.second;
      }
    } else {
      merged.push_back(r);
    }
  }
  d.sacked = std::move(merged);
}

std::uint32_t InFlightChecker::sacked_bytes(const Dir& d) noexcept {
  std::uint32_t n = 0;
  for (const auto& r : d.sacked) {
    n += r.second - r.first;
  }
  return n;
}

std::optional<Seq32> InFlightChecker::right_edge(const FourTuple& sender) const {
  const auto it = dirs_.find(sender);
  if (it == dirs_.end()) {
    return std::nullopt;
  }
  return it->second.edge;
}

std::optional<std::string> InFlightChecker::on_egress(std::uint32_t node,
                                                      std::span<const std::byte> datagram) {
  const auto p = parse_tcp_packet(datagram);
  if (!p || (p->tcp.h.flags & wire::tcp_rst) != 0) {
    return std::nullopt;
  }
  const FourTuple key{{p->ip.src, p->tcp.h.sport}, {p->ip.dst, p->tcp.h.dport}};
  Dir& d = dirs_[key];
  if ((p->tcp.h.flags & wire::tcp_syn) != 0) {
    if (!d.own_syn || d.iss != p->tcp.h.seq) {
      // A new incarnation from this sender: forget its old sequence state;
      // the peer's SYN options are kept (a passive side hears them first).
      d.own_syn = true;
      d.iss = p->tcp.h.seq;
      d.own_ws = p->tcp.opt.wscale;
      d.own_sack = p->tcp.opt.sack_permitted;
      d.probe.reset();
      d.sent_end = d.iss + 1;
      d.accepted.reset();
      d.pending.reset();
      d.max_window = 0;
      d.edge.reset();
      d.high_sent.reset();
      d.high_ack.reset();
      d.sacked.clear();
    }
    return std::nullopt;
  }
  const auto len = static_cast<std::uint32_t>(p->tcp.payload.size());
  const bool fin = (p->tcp.h.flags & wire::tcp_fin) != 0;
  if (d.own_syn && (len || fin)) {
    const Seq32 wire_end = p->tcp.h.seq + len + static_cast<std::uint32_t>(fin);
    if (!d.sent_end || after(wire_end, *d.sent_end)) d.sent_end = wire_end;
  }
  if (len == 0 || !d.own_syn) {
    return std::nullopt;
  }
  const Seq32 end = p->tcp.h.seq + len;
  if (d.high_sent && !after(end, *d.high_sent)) {
    return std::nullopt;  // retransmission: exempt
  }
  std::optional<std::string> v;
  if (d.edge && after(end, *d.edge)) {
    v = "node " + node_name(node) + " (" + tuple_string(key) + ") sent new data ending at " +
        std::to_string(end.raw()) + ", " + std::to_string(end - *d.edge) +
        " bytes beyond the peer's right edge " + std::to_string(d.edge->raw()) +
        " (peer window scale " + std::to_string(peer_shift(d)) + ")";
  }
  d.high_sent = end;
  return v;
}

void InFlightChecker::on_ingress(std::uint32_t node, std::span<const std::byte> datagram) {
  static_cast<void>(node);
  const auto p = parse_tcp_packet(datagram);
  if (!p) {
    return;
  }
  const std::uint16_t flags = p->tcp.h.flags;
  if ((flags & wire::tcp_rst) != 0) {
    return;
  }
  // The receiver X of this datagram, as a sender, and the peer Y.
  const FourTuple xkey{{p->ip.dst, p->tcp.h.dport}, {p->ip.src, p->tcp.h.sport}};
  const FourTuple ykey{{p->ip.src, p->tcp.h.sport}, {p->ip.dst, p->tcp.h.dport}};
  const Seq32 ack = p->tcp.h.ack;
  if ((flags & wire::tcp_syn) != 0) {
    // Only the SYN its sender really sent counts (not a corrupted copy).
    const auto yit = dirs_.find(ykey);
    if (yit == dirs_.end() || !yit->second.own_syn || yit->second.iss != p->tcp.h.seq) {
      return;
    }
    Dir& x = dirs_[xkey];
    const bool has_ack = (flags & wire::tcp_ack) != 0;
    if (has_ack && (!x.own_syn || ack != x.iss + 1)) {
      return;  // not an acceptable SYN-ACK for X's SYN
    }
    if (!x.peer_syn || x.peer_isn != p->tcp.h.seq) {
      x.peer_syn = true;
      x.peer_isn = p->tcp.h.seq;
      x.peer_ws = p->tcp.opt.wscale;
      x.peer_sack = p->tcp.opt.sack_permitted;
    }
    if (has_ack) {
      if (!x.accepted) {
        x.accepted = Dir::Ack{p->tcp.h.seq, ack, p->tcp.h.window};
        x.max_window = p->tcp.h.window;
      }
      // RFC 7323 §2.2: the window of a SYN is never scaled.
      const Seq32 cand = ack + p->tcp.h.window;
      if (!x.edge || after(cand, *x.edge)) {
        x.edge = cand;
      }
      if (!x.high_ack || after(ack, *x.high_ack)) {
        x.high_ack = ack;
      }
    }
    return;
  }
  if ((flags & wire::tcp_ack) == 0) {
    return;
  }
  const auto xit = dirs_.find(xkey);
  if (xit == dirs_.end() || !xit->second.own_syn) {
    return;
  }
  Dir& x = xit->second;
  // Ingress is observed before TCP validation. Only the matching ACK trace
  // commits this packet's window and probe evidence.
  const auto window = std::uint32_t{p->tcp.h.window} << peer_shift(x);
  x.pending = Dir::Ack{p->tcp.h.seq, ack, window};
  x.pending_pure = flags == wire::tcp_ack && p->tcp.payload.empty() && p->tcp.opt.sack_count == 0;
  x.pending_dsack.reset();
  if (x.probe && p->tcp.opt.sack_count > 0) {
    const auto [begin, end] = p->tcp.opt.sack[0];
    const auto second = p->tcp.opt.sack[1];
    // RFC 2883 §4: below the cumulative ACK or nested in the next block.
    if (before(begin, end) && (before_eq(end, ack) || (p->tcp.opt.sack_count > 1 &&
        before_eq(second.first, begin) && before_eq(end, second.second)))) {
      x.pending_dsack = {begin, end};
    }
  }
  const Seq32 cand = ack + window;
  if (!x.edge || after(cand, *x.edge)) {
    x.edge = cand;
  }
  if (!x.high_ack || after(ack, *x.high_ack)) {
    x.high_ack = ack;
    // Drop SACKed ranges now below the cumulative ACK.
    std::vector<std::pair<Seq32, Seq32>> kept;
    for (auto r : x.sacked) {
      if (after(r.second, ack)) {
        if (before(r.first, ack)) {
          r.first = ack;
        }
        kept.push_back(r);
      }
    }
    x.sacked = std::move(kept);
  }
  for (std::size_t i = 0; i < p->tcp.opt.sack_count; ++i) {
    add_sack(x, p->tcp.opt.sack[i].first, p->tcp.opt.sack[i].second);
  }
}

void InFlightChecker::Dir::accept_ack(const TraceEvent& e) {
  if (!pending || pending->seq != Seq32(e.seq) || pending->number != Seq32(e.ack)) return;
  const Ack a = *pending;
  pending.reset();
  if (accepted && before(a.number, accepted->number)) return;
  const bool advances = !accepted || after(a.number, accepted->number);
  const bool update = advances || after_eq(a.seq, accepted->seq);
  const bool pure_duplicate = !advances && pending_pure && (!update || a.window == accepted->window);
  if (update) {
    accepted = a;
    max_window = std::max(max_window, a.window);
  }
  // RFC 8985 §7.4.2, Linux tcp_process_tlp_ack: equality alone is
  // sufficient for new data. A retransmission at equality needs evidence
  // that both copies arrived. tcp_dsack_seen tags a block ending at the
  // marker that covers at most one MSS and fits the advertised window.
  if (!probe || before(a.number, probe->high)) return;
  const bool matches_dsack = pending_dsack && pending_dsack->second == probe->high &&
      pending_dsack->second - pending_dsack->first <= std::min<std::uint32_t>(e.mss, max_window);
  if (!probe->retrans || after(a.number, probe->high) || pure_duplicate || matches_dsack) {
    probe.reset();
  }
}

std::optional<std::string> InFlightChecker::on_trace(std::uint32_t node, const TraceEvent& e) {
  const auto conn = std::make_pair(node, e.conn_id);
  auto& dir = dirs_[e.tuple];
  if (e.kind == TraceKind::state && e.state == TcpState::closed) dir.probe.reset();
  if (e.ca == CaState::loss || e.ca == CaState::recovery) {
    dir.probe.reset();
  }
  if (e.kind == TraceKind::ack) dir.accept_ack(e);
  if (e.kind == TraceKind::rto ||
      (e.kind == TraceKind::timer && e.timer == TraceTimer::rto && e.timer_op == TimerOp::fired)) {
    dir.probe.reset();
    rto_pending_.insert(conn);
    return std::nullopt;
  }
  if (e.kind != TraceKind::tx) {
    return std::nullopt;
  }
  const bool fin = (e.flags & wire::tcp_fin) != 0;
  const Seq32 end = Seq32(e.seq) + e.len + static_cast<std::uint32_t>(fin);
  const bool new_sequence = !dir.sent_end || after(end, *dir.sent_end);
  if (e.tx != TxKind::zwp && (e.len || fin) && new_sequence) dir.sent_end = end;
  const auto conf = configs_.find(node);
  switch (e.tx) {
    case TxKind::tlp: {
      const std::string who = conn_string(node, e.conn_id, e.tuple);
      if (conf != configs_.end() && !conf->second.rack_tlp) return who + " TLP with RACK-TLP disabled";
      if (!dir.own_sack || !dir.peer_sack) return who + " TLP without negotiated SACK";
      if (e.ca == CaState::recovery || e.ca == CaState::loss) return who + " TLP in Recovery/Loss";
      if (dir.probe) return who + " second TLP in open probe episode";
      if (std::uint64_t{e.in_flight} > std::uint64_t{e.cwnd} + 1) return who + " TLP exceeds cwnd+1";
      dir.probe = Dir::Probe{dir.sent_end.value_or(end), !new_sequence};
      return std::nullopt;
    }
    case TxKind::fast_rexmit:
      if (!strict_ || (conf != configs_.end() && conf->second.recovery_reduction == RecoveryReduction::rfc6675)) {
        return std::nullopt;
      }
      break;
    case TxKind::data:
    case TxKind::fin:
    case TxKind::rexmit:
    case TxKind::pmtu_rexmit:
      break;
    case TxKind::rto_rexmit:
      // Only the head retransmission of an RTO expiry skips the cwnd gate
      // (§4.9, Linux tcp_retransmit_timer); a further rto_rexmit is checked
      // like rexmit.
      if (rto_pending_.erase(conn) != 0) {
        return std::nullopt;
      }
      break;
    case TxKind::syn:
    case TxKind::synack:
      rto_pending_.erase(conn);  // the expiry retransmitted the SYN or SYN-ACK
      return std::nullopt;
    default:
      // Pure control segments do not consume congestion-window space.
      return std::nullopt;
  }
  if (e.len == 0) {
    return std::nullopt;
  }
  if (e.in_flight > e.cwnd) {
    return "node " + node_name(node) + " (" + tuple_string(e.tuple) + ") " +
           std::string(to_string(e.tx)) + " of " + std::to_string(e.len) +
           " bytes left packets_in_flight " + std::to_string(e.in_flight) + " > cwnd " +
           std::to_string(e.cwnd);
  }
  if (e.ca != CaState::open || e.lost_out != 0) {
    return std::nullopt;
  }
  const auto it = dirs_.find(e.tuple);
  if (it == dirs_.end() || !it->second.high_ack) {
    return std::nullopt;
  }
  const Dir& d = it->second;
  Seq32 high = Seq32(e.seq) + e.len;
  if (d.high_sent && after(*d.high_sent, high)) {
    high = *d.high_sent;
  }
  if (!after(high, *d.high_ack)) {
    return std::nullopt;
  }
  const std::uint64_t outstanding = high - *d.high_ack;
  const std::uint64_t sacked = sacked_bytes(d);
  const std::uint64_t wire_in_flight = outstanding > sacked ? outstanding - sacked : 0;
  if (wire_in_flight > std::uint64_t{e.cwnd} * e.mss) {
    return "node " + node_name(node) + " (" + tuple_string(e.tuple) + ") in Open with no loss " +
           "marks has " + std::to_string(wire_in_flight) + " bytes in flight on the wire > cwnd " +
           std::to_string(e.cwnd) + " * mss " + std::to_string(e.mss);
  }
  return std::nullopt;
}

// --- PacingChecker (§7.3). A burst is charged once its last segment is known.
void PacingChecker::Sender::finish_burst() {
  if (bytes == 0) return;
  const Time base = std::max(edt, sent);
  if (segments >= 10) {
    __extension__ using Wide = unsigned __int128;
    const Wide interval = Wide{bytes} * 1'000'000'000 / rate;
    const auto late = static_cast<std::uint64_t>(std::max((sent - edt).count(), std::int64_t{0}));
    const Wide charge = interval - std::min<Wide>(interval / 2, late);
    edt = base + Duration{static_cast<std::int64_t>(std::min<Wide>(charge, Duration::max().count()))};
  } else {
    edt = base;
  }
  bytes = 0;
}

std::optional<std::string> PacingChecker::on_trace(std::uint32_t node, const TraceEvent& e) {
  const auto key = std::pair{node, e.conn_id};
  if (e.kind == TraceKind::state && e.state == TcpState::closed) {
    senders_.erase(key);
    return std::nullopt;
  }
  if (e.kind == TraceKind::rto ||
      (e.kind == TraceKind::timer && e.timer == TraceTimer::rto && e.timer_op == TimerOp::fired)) {
    senders_[key].rto_head = true;
  }
  if (e.kind != TraceKind::tx) return std::nullopt;
  Sender& s = senders_[key];
  const bool head = e.tx == TxKind::rto_rexmit && s.rto_head;
  if (e.tx == TxKind::syn || e.tx == TxKind::synack || e.tx == TxKind::rto_rexmit) s.rto_head = false;
  const bool repeat_probe = e.tx == TxKind::tlp && e.snd_nxt_off <= s.nxt;
  s.nxt = std::max(s.nxt, e.snd_nxt_off);
  if (e.len == 0) return std::nullopt;
  const bool exempt = head || repeat_probe;
  if (e.burst_start || exempt || !e.gate_rate) s.finish_burst();
  if (e.tx == TxKind::zwp) return std::nullopt;  // persist probes do not consume a data segment
  const bool startup = s.segments < 10;
  s.segments = std::min(10u, s.segments + 1);
  const auto who = [&] { return conn_string(node, e.conn_id, e.tuple); };
  const auto conf = configs_.find(node);
  const bool configured = conf != configs_.end();
  const bool paced = configured ? (conf->second.test_fixed_pacing_rate ||
      conf->second.pacing == Pacing::always ||
      (conf->second.pacing == Pacing::cc_requested && conf->second.cc == CcAlgo::bbr))
      : s.rate != 0;
  const auto rate = configured ? conf->second.test_fixed_pacing_rate.value_or(e.pacing_rate)
                               : e.pacing_rate;
  if (e.gate_rate && ((configured && (!paced || rate != e.gate_rate)) ||
                       (!configured && rate && rate != e.gate_rate))) {
    return who() + " gate rate disagrees with sender pacing rate";
  }
  if (exempt) {
    // Timer sends bypass the gate but charge EDT at the active sender rate.
    s.rate = configured ? (paced ? rate : 0) : (e.gate_rate ? e.gate_rate : s.rate);
    if (s.rate && s.segments >= 10) {
      s.sent = e.t;
      s.bytes = e.len;
      s.finish_burst();
    }
    return std::nullopt;
  }
  if (!e.gate_rate) {
    // Legacy transmit() chose whether to pace once on entry. Its untagged
    // startup call can send several segments across ten at the same time.
    if (startup && s.segments == 10) s.legacy_startup = e.t;
    if (e.t + 1us < s.edt) return who() + " untagged payload before EDT";
    if (!startup && s.legacy_startup != e.t && paced && (rate || !configured)) {
      return who() + " ordinary paced payload missing gate rate";
    }
    return std::nullopt;
  }
  s.legacy_startup.reset();
  if (e.burst_start) {
    if (e.t + 1us < s.edt) return who() + " paced burst before EDT " + std::to_string(s.edt.ns);
    s.rate = e.gate_rate;
    s.sent = e.t;
  } else if (!s.bytes || s.sent != e.t || s.rate != e.gate_rate) {
    return who() + " paced segment without matching burst start";
  }
  s.bytes += e.len;
  return std::nullopt;
}

// --- ProgressChecker, QuiescenceChecker.

Duration progress_bound(const TcpConfig& c) noexcept {
  return retry_abort_time(c.data_retries, c.rto_min, c.rto_max) + c.time_wait + 120s;
}

bool usage_settled(const StackUsage& u) noexcept {
  return u.conn_timers_armed == 0 && u.tx_queued == 0 && u.blocked_conns == 0;
}

std::optional<std::string> usage_leaks(const StackUsage& u) {
  std::string s;
  const auto add = [&](std::string_view what, std::uint64_t n) {
    if (n != 0) {
      if (!s.empty()) {
        s += ", ";
      }
      s += what;
      s += ' ';
      s += std::to_string(n);
    }
  };
  add("tcp_slots", u.tcp_slots);
  add("udp_slots", u.udp_slots);
  add("time_wait_entries", u.time_wait_entries);
  add("tx_queued", u.tx_queued);
  add("events_queued", u.events_queued);
  add("echo_replies_queued", u.echo_replies_queued);
  add("blocked_conns", u.blocked_conns);
  add("conn_timers_armed", u.conn_timers_armed);
  add("pool_buffers_in_use", u.pool_buffers - u.pool_buffers_free);
  add("chunks_in_use", u.chunks - u.chunks_free);
  if (s.empty()) {
    return std::nullopt;
  }
  return s;
}

}  // namespace utcp::sim
