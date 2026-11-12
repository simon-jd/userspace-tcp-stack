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
    "leak", "stuck", "livelock", "workload", "planted"};

std::string tuple_string(const FourTuple& t) {
  return to_string(t.local) + ">" + to_string(t.remote);
}

std::string conn_string(std::uint32_t node, std::uint32_t conn_id, const FourTuple& t) {
  return "node " + node_name(node) + " conn " + std::to_string(conn_id) + " (" + tuple_string(t) +
         ")";
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
    case CloseCause::timed_out:
    case CloseCause::synack_timed_out:
      return std::nullopt;
    case CloseCause::fin_wait2_timeout:
      if (c.before_close == TcpState::fin_wait_2) {
        return std::nullopt;
      }
      return "fin_wait2_timeout outside FIN-WAIT-2";
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
        default:
          return "RST received in " + std::string(to_string(c.before_close)) +
                 " after the peer ended with " + std::string(to_string(peer->cause));
      }
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
      d.edge.reset();
      d.high_sent.reset();
      d.high_ack.reset();
      d.sacked.clear();
    }
    return std::nullopt;
  }
  const auto len = static_cast<std::uint32_t>(p->tcp.payload.size());
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
    }
    if (has_ack) {
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
  const Seq32 cand = ack + (std::uint32_t{p->tcp.h.window} << peer_shift(x));
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

std::optional<std::string> InFlightChecker::on_trace(std::uint32_t node, const TraceEvent& e) {
  if (e.kind != TraceKind::tx || e.len == 0) {
    return std::nullopt;
  }
  switch (e.tx) {
    case TxKind::data:
    case TxKind::fin:
    case TxKind::rexmit:
    case TxKind::pmtu_rexmit:
      break;
    default:
      // fast_rexmit, rto_rexmit and tlp are exempt (RFC 6675 §5 (4.3), RFC
      // 8985 §7.3); the other kinds carry no data.
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
