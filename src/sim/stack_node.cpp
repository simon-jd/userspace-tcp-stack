#include "utcp/sim/stack_node.hpp"

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "utcp/sim/checkers.hpp"
#include "utcp/sim/datagram.hpp"

namespace utcp::sim {

using namespace std::chrono_literals;

StackConfig stack_config(const Scenario& s, std::uint32_t index) {
  const NodeSpec& n = s.node.at(index);
  StackConfig c;
  c.local_addr = node_addr(index);
  c.mtu = 1500;
  c.seed = Rng::derive_seed(Seed::from_u64(s.seed), "node/" + node_name(index) + "/stack");
  c.tcp = tcp_config(n.profile);
  if (s.gen_version >= 4) {
    c.tcp.cc = n.cc;
    c.tcp.hystart = n.hystart;
    c.tcp.recovery_reduction = n.recovery_reduction;
    c.tcp.rack_tlp = n.rack_tlp;
    c.tcp.pacing = n.pacing;
  }
  c.tcp.sack = n.sack;
  c.tcp.timestamps = n.timestamps;
  c.tcp.window_scaling = n.window_scaling;
  c.tcp.nodelay = n.nodelay;
  c.tcp.test_isn = n.test_isn;
  c.tcp.test_renege_ppm = n.renege_ppm;
  c.tcp.test_fault = n.test_fault;
  c.pool_buffers = n.pool_buffers;
  c.chunk_limit = n.chunk_limit;
  c.tx_queue_packets = n.tx_queue_packets;
  c.trace_mask = trace_mask_all;
  c.assert_time_monotonic = true;
  return c;
}

namespace {

constexpr std::size_t io_chunk = 65536;
// UDP and ping clients stop waiting for replies this long after their last send.
constexpr Duration reply_grace = 5s;

// Errors that end a connection under the application: tolerated, the
// TerminationChecker judges how the connection ended.
bool connection_error(Error e) {
  switch (e) {
    case Error::connection_refused:
    case Error::connection_reset:
    case Error::connection_aborted:
    case Error::timed_out:
    case Error::host_unreachable:
    case Error::network_unreachable:
    case Error::not_connected:
      return true;
    default:
      return false;
  }
}

}  // namespace

class StackNode::Impl final : public TraceSink {
public:
  Impl(const Scenario& s, std::uint32_t index)
      : s_(s), index_(index), stack_(stack_config(s, index)), buf_(io_chunk) {
    const NodeSpec& ns = s_.node.at(index);
    if (ns.nodelay) {
      opts_.nodelay = true;
    }
    if (ns.snd_buf != 0) {
      opts_.snd_buf = ns.snd_buf;
    }
    if (ns.rcv_buf != 0) {
      opts_.rcv_buf = ns.rcv_buf;
    }
    plan();
  }

  void on_event(const TraceEvent& e) override {
    ++activity_;
    if (shared_listener_ && e.kind == TraceKind::state && e.tuple.remote.port != 0) {
      remote_port_.try_emplace(e.conn_id, e.tuple.remote.port);
    }
    if (ctx_ != nullptr) {
      ctx_->on_trace(index_, e);
    }
  }

  void attach(SimContext& ctx) {
    ctx_ = &ctx;
    stack_.set_trace_sink(this);
  }

  // --- Workload state.
  enum class Phase : std::uint8_t { waiting, connecting, open, done };

  struct TcpEnd {
    std::uint32_t conn = 0;
    bool client = false;
    bool passive = false;  // accepted from a listener
    CloseMode mode = CloseMode::close;
    std::uint8_t send_dir = 0, recv_dir = 1;
    Phase phase = Phase::waiting;
    Time start_at = Time::never();  // connect time (active ends)
    Endpoint remote;
    std::uint16_t local_port = 0;
    Handle h;
    std::uint32_t conn_id = 0;
    std::uint64_t to_send = 0, sent = 0, received = 0;
    std::uint32_t write_max = 1;
    std::uint64_t pause_every = 0, next_pause = 0;
    Duration pause{};
    Time paused_until{}, next_write{};
    bool eof = false, shut_wr = false;
    Time abort_at = Time::never();
    Time last_activity{};
    Rng writes{Seed{}};
  };

  // One per server port: the passive ends of every ConnSpec on that port
  // (several when they share the listener, ConnSpec).
  struct Listener {
    std::uint32_t conn = 0;  // the first ConnSpec
    std::uint16_t port = 0;
    std::uint32_t backlog = 1;
    std::vector<std::size_t> ends;  // the passive TcpEnds
    bool open = false, done = false;
    Handle h;
    std::uint32_t conn_id = 0;
    Time give_up = Time::never();  // clients not connected by then: close
  };

  struct UdpEnd {
    std::uint32_t flow = 0;
    bool client = false;
    Endpoint local, remote;
    bool open = false, done = false;
    Handle h;
    Time open_at = Time::never();
    Time close_at = Time::never();
    std::uint32_t count = 0, next_seq = 0, replies = 0;
    Duration interval{};
    std::uint32_t size_min = 0, size_max = 0;
    Rng sizes{Seed{}};
  };

  struct PingEnd {
    std::uint32_t idx = 0;
    std::uint16_t id = 1;
    Ipv4Addr dst;
    std::uint32_t count = 0, next_seq = 0, replies = 0, size = 0;
    Duration interval{};
    Time start_at = Time::never();
    Time close_at = Time::never();
    bool done = false;
  };

  void plan() {
    const Seed master = Seed::from_u64(s_.seed);
    for (std::uint32_t i = 0; i < s_.conn.size(); ++i) {
      const ConnSpec& c = s_.conn[i];
      const std::uint32_t server = 1 - c.client;
      if (index_ != c.client && index_ != server) {
        continue;
      }
      const bool client = index_ == c.client;
      if (c.mode == CloseMode::refused && !client) {
        continue;
      }
      TcpEnd e;
      e.conn = i;
      e.client = client;
      e.mode = c.mode;
      e.send_dir = client ? 0 : 1;
      e.recv_dir = client ? 1 : 0;
      e.to_send = client ? c.bytes_c2s : c.bytes_s2c;
      e.write_max = std::max<std::uint32_t>(1, client ? c.write_max_c : c.write_max_s);
      e.pause_every = client ? c.pause_every_c : c.pause_every_s;
      e.next_pause = e.pause_every;
      e.pause = client ? c.pause_c : c.pause_s;
      e.writes = Rng::derive(master, "wl/conn" + std::to_string(i) + (client ? "/c" : "/s") +
                                         "/writes");
      const Ipv4Addr peer = node_addr(client ? server : c.client);
      if (client) {
        e.start_at = s_.start + c.start;
        e.remote = Endpoint{peer, c.server_port};
        e.local_port = c.client_port;
      } else if (c.mode == CloseMode::simultaneous) {
        e.start_at = s_.start + c.start;
        e.remote = Endpoint{peer, c.client_port};
        e.local_port = c.server_port;
      } else {
        e.passive = true;
        const auto same_port = [&](const Listener& x) { return x.port == c.server_port; };
        auto it = std::ranges::find_if(listeners_, same_port);
        if (it == listeners_.end()) {
          Listener l;
          l.conn = i;
          l.port = c.server_port;
          l.backlog = c.backlog;
          l.give_up = s_.start + c.start + s_.app_idle_timeout;
          listeners_.push_back(l);
          it = listeners_.end() - 1;
        } else {
          shared_listener_ = true;
          it->give_up = std::max(it->give_up, s_.start + c.start + s_.app_idle_timeout);
        }
        it->ends.push_back(ends_.size());
      }
      ends_.push_back(std::move(e));
    }
    for (std::uint32_t i = 0; i < s_.udp.size(); ++i) {
      const UdpSpec& u = s_.udp[i];
      const std::uint32_t server = 1 - u.client;
      if (index_ != u.client && index_ != server) {
        continue;
      }
      const bool client = index_ == u.client;
      if (!client && !u.server_bound) {
        continue;
      }
      UdpEnd e;
      e.flow = i;
      e.client = client;
      e.local = Endpoint{node_addr(index_), client ? u.client_port : u.server_port};
      e.remote = Endpoint{node_addr(client ? server : u.client), u.server_port};
      e.open_at = client ? s_.start + u.start : s_.start;
      const Duration span = u.interval * (u.count == 0 ? 0 : u.count - 1);
      e.close_at = s_.start + u.start + span + reply_grace;
      e.count = client ? u.count : 0;
      e.interval = u.interval;
      e.size_min = u.size_min;
      e.size_max = std::max(u.size_min, u.size_max);
      e.sizes = Rng::derive(master, "wl/udp" + std::to_string(i) + "/sizes");
      udp_.push_back(e);
    }
    for (std::uint32_t i = 0; i < s_.ping.size(); ++i) {
      const PingSpec& p = s_.ping[i];
      if (index_ != p.client) {
        continue;
      }
      PingEnd e;
      e.idx = i;
      e.id = p.id;
      e.dst = node_addr(1 - p.client);
      e.count = p.count;
      e.size = p.size;
      e.interval = p.interval;
      e.start_at = s_.start + p.start;
      e.close_at = e.start_at + p.interval * (p.count == 0 ? 0 : p.count - 1) + reply_grace;
      pings_.push_back(e);
    }
  }

  // --- Helpers.

  Time now() const { return stack_.now(); }

  void fail(std::string_view call, Error e) {
    failed_ = true;
    ctx_->violation(Verdict::workload, "node " + node_name(index_) + ": " + std::string(call) +
                                           " failed with " + std::string(to_string(e)));
  }

  void tolerate(std::string_view what, Error e) {
    ctx_->note_error(index_, std::string(what) + ": " + std::string(to_string(e)));
  }

  std::uint32_t conn_id_of(Handle h) const {
    const auto info = stack_.tcp_info(h);
    return info ? info->conn_id : 0;
  }

  void touch(TcpEnd& e) { e.last_activity = now(); }

  void end_close(TcpEnd& e, bool abort) {
    ctx_->on_app_close(index_, e.conn_id);
    const auto r = abort ? stack_.tcp_abort(e.h) : stack_.tcp_close(e.h);
    tcp_handles_.erase(e.h);
    e.phase = Phase::done;
    if (!r) {
      fail(abort ? "tcp_abort" : "tcp_close", r.error());
    }
  }

  // A connection error ended the connection: close the handle.
  void end_error(TcpEnd& e, std::string_view call, Error err) {
    ++counts_.tcp_errors;
    tolerate(call, err);
    end_close(e, false);
  }

  void listener_close(Listener& l) {
    ctx_->on_app_close(index_, l.conn_id);
    const auto r = stack_.tcp_close(l.h);
    listener_handles_.erase(l.h);
    l.open = false;
    l.done = true;
    if (!r) {
      fail("tcp_close(listener)", r.error());
    }
  }

  // --- Setup and timers.

  void setup() {
    setup_done_ = true;
    for (Listener& l : listeners_) {
      auto h = stack_.tcp_listen(Endpoint{node_addr(index_), l.port}, l.backlog, opts_);
      if (!h) {
        fail("tcp_listen", h.error());
        return;
      }
      l.h = *h;
      l.open = true;
      l.conn_id = conn_id_of(l.h);
      listener_handles_.emplace(l.h, static_cast<std::size_t>(&l - listeners_.data()));
    }
  }

  void run_timers() {
    const Time t = now();
    for (TcpEnd& e : ends_) {
      if (failed_) {
        return;
      }
      if (e.phase == Phase::waiting && !e.passive && e.start_at <= t) {
        auto h = stack_.tcp_connect(e.remote, opts_, e.local_port);
        if (!h) {
          if (e.mode == CloseMode::refused && connection_error(h.error())) {
            tolerate("tcp_connect", h.error());
            e.phase = Phase::done;
            continue;
          }
          fail("tcp_connect", h.error());
          return;
        }
        e.h = *h;
        e.conn_id = conn_id_of(e.h);
        e.phase = Phase::connecting;
        touch(e);
        tcp_handles_.emplace(e.h, static_cast<std::size_t>(&e - ends_.data()));
      }
      if ((e.phase == Phase::open || e.phase == Phase::connecting) &&
          e.last_activity + s_.app_idle_timeout <= t) {
        tolerate("idle timeout", Error::timed_out);
        end_close(e, false);
        continue;
      }
      if (e.phase == Phase::open && e.abort_at <= t) {
        end_close(e, true);
      }
    }
    for (Listener& l : listeners_) {
      if (l.open && l.give_up <= t) {
        listener_close(l);
        for (const std::size_t i : l.ends) {
          if (ends_[i].phase == Phase::waiting) {
            ends_[i].phase = Phase::done;  // its client never connected
          }
        }
      }
    }
    for (UdpEnd& u : udp_) {
      run_udp_timers(u, t);
    }
    for (PingEnd& p : pings_) {
      run_ping(p, t);
    }
  }

  // --- TCP.

  // The waiting passive end of `l` that the accepted connection `conn_id`
  // belongs to: the only end, or with a shared listener the end whose
  // client port is the connection's remote port (from its trace events).
  std::optional<std::size_t> match(const Listener& l, std::uint32_t conn_id) {
    if (l.ends.size() == 1) {
      const std::size_t i = l.ends[0];
      return ends_[i].phase == Phase::waiting ? std::optional{i} : std::nullopt;
    }
    const auto it = remote_port_.find(conn_id);
    if (it == remote_port_.end()) {
      return std::nullopt;
    }
    const std::uint16_t port = it->second;
    remote_port_.erase(it);
    for (const std::size_t i : l.ends) {
      if (ends_[i].phase == Phase::waiting && s_.conn[ends_[i].conn].client_port == port) {
        return i;
      }
    }
    return std::nullopt;
  }

  void accept_all(Listener& l) {
    for (;;) {
      auto c = stack_.tcp_accept(l.h);
      if (!c) {
        if (c.error() != Error::would_block) {
          fail("tcp_accept", c.error());
        }
        return;
      }
      const std::uint32_t id = conn_id_of(*c);
      const auto i = match(l, id);
      if (!i) {
        // Not a designed client (cannot happen without garbage): close it.
        ctx_->on_app_close(index_, id);
        if (auto r = stack_.tcp_close(*c); !r) {
          fail("tcp_close", r.error());
        }
        continue;
      }
      TcpEnd& e = ends_[*i];
      e.h = *c;
      e.conn_id = id;
      e.phase = Phase::open;
      touch(e);
      tcp_handles_.emplace(e.h, *i);
      ctx_->on_progress();
      const bool all = std::ranges::none_of(
          l.ends, [&](std::size_t k) { return ends_[k].phase == Phase::waiting; });
      if (all) {
        listener_close(l);  // every designed client is in
        return;
      }
    }
  }

  void pump(TcpEnd& e) {
    if (e.phase != Phase::open) {
      return;
    }
    const Time t = now();
    if (!e.eof && t >= e.paused_until) {
      if (!read(e)) {
        return;
      }
    }
    const bool may_send = !(e.mode == CloseMode::half_close && !e.client) || e.eof;
    if (may_send && e.sent < e.to_send && e.next_write <= t) {
      if (!write(e)) {
        return;
      }
    }
    if (may_send && e.sent == e.to_send && !e.shut_wr) {
      const auto r = stack_.tcp_shutdown(e.h, Shutdown::write);
      if (!r) {
        if (connection_error(r.error())) {
          end_error(e, "tcp_shutdown", r.error());
        } else {
          fail("tcp_shutdown", r.error());
        }
        return;
      }
      e.shut_wr = true;
    }
    if (e.eof && e.shut_wr) {
      ctx_->on_progress();
      end_close(e, false);
    }
  }

  // False if the connection ended.
  bool read(TcpEnd& e) {
    for (;;) {
      std::size_t want = buf_.size();
      if (e.pause_every != 0) {
        want = static_cast<std::size_t>(std::min<std::uint64_t>(want, e.next_pause - e.received));
      }
      const auto r = stack_.tcp_recv(e.h, std::span<std::byte>(buf_).first(want));
      if (!r) {
        if (r.error() == Error::would_block) {
          return true;
        }
        if (connection_error(r.error())) {
          end_error(e, "tcp_recv", r.error());
        } else {
          fail("tcp_recv", r.error());
        }
        return false;
      }
      if (*r == 0) {
        e.eof = true;
        touch(e);
        ctx_->on_progress();
        if (auto v = ctx_->stream().on_eof(e.conn, e.recv_dir, e.received)) {
          ctx_->violation(Verdict::stream, std::move(*v));
          return false;
        }
        return true;
      }
      const auto data = std::span<const std::byte>(buf_).first(*r);
      if (auto v = ctx_->stream().on_read(e.conn, e.recv_dir, e.received, data)) {
        ctx_->violation(Verdict::stream, std::move(*v));
        return false;
      }
      e.received += *r;
      counts_.tcp_bytes_received += *r;
      touch(e);
      ctx_->on_progress();
      if (e.pause_every != 0 && e.received >= e.next_pause) {
        e.next_pause += e.pause_every;
        e.paused_until = now() + e.pause;
        return true;
      }
    }
  }

  bool write(TcpEnd& e) {
    const Pattern& p = ctx_->stream().tcp_pattern(e.conn, e.send_dir);
    while (e.sent < e.to_send) {
      const std::uint64_t left = e.to_send - e.sent;
      const std::size_t n = static_cast<std::size_t>(
          std::min<std::uint64_t>({left, std::uint64_t{1} + e.writes.below(e.write_max), buf_.size()}));
      const auto chunk = std::span<std::byte>(buf_).first(n);
      p.fill(e.sent, chunk);
      const auto r = stack_.tcp_send(e.h, chunk);
      if (!r) {
        if (r.error() == Error::would_block) {
          return true;
        }
        if (connection_error(r.error()) || r.error() == Error::shut_down) {
          end_error(e, "tcp_send", r.error());
        } else {
          fail("tcp_send", r.error());
        }
        return false;
      }
      if (*r == 0) {
        return true;
      }
      e.sent += *r;
      counts_.tcp_bytes_sent += *r;
      ctx_->stream().on_written(e.conn, e.send_dir, e.sent);
      touch(e);
      const auto gap = s_.conn[e.conn].write_interval;
      if (gap > Duration::zero()) {
        e.next_write = now() + gap;
        break;
      }
    }
    return true;
  }

  void on_tcp_event(TcpEnd& e, std::uint16_t ev) {
    if (e.phase == Phase::connecting && (ev & ev_connected) != 0) {
      e.phase = Phase::open;
      touch(e);
      ctx_->on_progress();
      if (e.mode == CloseMode::abort && e.client) {
        e.abort_at = now() + s_.conn[e.conn].abort_after;
      }
    }
    if ((ev & ev_error) != 0 && (e.phase == Phase::connecting || e.phase == Phase::open)) {
      if (const auto err = stack_.take_error(e.h)) {
        if (connection_error(*err)) {
          end_error(e, "connection", *err);
        } else {
          fail("connection", *err);
        }
      }
    }
  }

  // --- UDP and ICMP.

  void run_udp_timers(UdpEnd& u, Time t) {
    if (u.done) {
      return;
    }
    if (!u.open && u.open_at <= t) {
      auto h = stack_.udp_open(u.local);
      if (!h) {
        fail("udp_open", h.error());
        u.done = true;
        return;
      }
      u.h = *h;
      u.open = true;
      udp_handles_.emplace(u.h, static_cast<std::size_t>(&u - udp_.data()));
    }
    if (u.open && u.client) {
      while (u.next_seq < u.count && u.open_at + u.interval * u.next_seq <= t) {
        const std::uint32_t size =
            u.size_min + u.sizes.below(u.size_max - u.size_min + 1);
        const auto payload = std::span<std::byte>(buf_).first(std::min<std::size_t>(size, buf_.size()));
        ctx_->stream().udp_payload(u.flow, 0, u.next_seq, payload);
        const auto r = stack_.udp_send_to(u.h, u.remote, payload);
        if (!r) {
          if (r.error() == Error::no_buffers) {
            return;  // retried at the next call, after the host drained
          }
          if (r.error() == Error::message_too_big || connection_error(r.error())) {
            tolerate("udp_send_to", r.error());
          } else {
            fail("udp_send_to", r.error());
            return;
          }
        } else {
          ++counts_.udp_sent;
        }
        ++u.next_seq;
      }
    }
    if (u.open && (u.close_at <= t || (u.client && u.replies == u.count && u.next_seq == u.count))) {
      udp_close(u);
    }
  }

  void udp_close(UdpEnd& u) {
    const auto r = stack_.udp_close(u.h);
    udp_handles_.erase(u.h);
    u.open = false;
    u.done = true;
    ctx_->on_progress();
    if (!r) {
      fail("udp_close", r.error());
    }
  }

  void udp_readable(UdpEnd& u) {
    for (;;) {
      const auto r = stack_.udp_recv_from(u.h, buf_);
      if (!r) {
        if (r.error() != Error::would_block) {
          if (connection_error(r.error())) {
            tolerate("udp_recv_from", r.error());
            continue;
          }
          fail("udp_recv_from", r.error());
        }
        return;
      }
      const auto data = std::span<const std::byte>(buf_).first(std::min(r->len, buf_.size()));
      if (auto v = ctx_->stream().on_datagram(u.flow, 0, data)) {
        ctx_->violation(Verdict::stream, std::move(*v));
        return;
      }
      ctx_->on_progress();
      if (u.client) {
        ++u.replies;
        ++counts_.udp_replies;
      } else {
        const auto e = stack_.udp_send_to(u.h, r->from, data);
        if (e) {
          ++counts_.udp_echoed;
        } else if (e.error() == Error::no_buffers || e.error() == Error::message_too_big) {
          tolerate("udp echo", e.error());
        } else {
          fail("udp_send_to", e.error());
          return;
        }
      }
    }
  }

  void run_ping(PingEnd& p, Time t) {
    if (p.done) {
      return;
    }
    while (p.next_seq < p.count && p.start_at + p.interval * p.next_seq <= t) {
      const auto payload = std::span<std::byte>(buf_).first(std::min<std::size_t>(p.size, buf_.size()));
      ctx_->stream().udp_payload(1'000'000 + p.idx, 0, p.next_seq, payload);
      const auto r = stack_.icmp_echo(p.dst, p.id, static_cast<std::uint16_t>(p.next_seq), payload);
      if (!r) {
        if (r.error() == Error::no_buffers) {
          return;
        }
        fail("icmp_echo", r.error());
        p.done = true;
        return;
      }
      ++counts_.pings_sent;
      ++p.next_seq;
    }
    if (p.close_at <= t || (p.next_seq == p.count && p.replies == p.count)) {
      p.done = true;
      ctx_->on_progress();
    }
  }

  void poll_echo() {
    while (const auto r = stack_.poll_echo_reply()) {
      ++activity_;
      for (PingEnd& p : pings_) {
        if (p.id == r->id && !p.done) {
          ++p.replies;
          ++counts_.ping_replies;
          ctx_->on_progress();
          break;
        }
      }
    }
  }

  // --- Node interface.

  void run_apps() {
    if (failed_) {
      return;  // the run ends at the World's next check
    }
    if (!setup_done_) {
      setup();
    }
    run_timers();
    while (const auto ev = stack_.poll_event()) {
      ++activity_;
      ctx_->on_socket_event(index_, *ev);
      if (ev->h.proto == Proto::udp) {
        if (const auto it = udp_handles_.find(ev->h); it != udp_handles_.end()) {
          if ((ev->events & ev_readable) != 0) {
            udp_readable(udp_[it->second]);
          }
        }
        continue;
      }
      if (const auto it = listener_handles_.find(ev->h); it != listener_handles_.end()) {
        if ((ev->events & ev_acceptable) != 0) {
          accept_all(listeners_[it->second]);
        }
        continue;
      }
      if (const auto it = tcp_handles_.find(ev->h); it != tcp_handles_.end()) {
        on_tcp_event(ends_[it->second], ev->events);
      }
    }
    poll_echo();
    for (TcpEnd& e : ends_) {
      pump(e);
    }
    for (UdpEnd& u : udp_) {
      if (!u.done) {
        run_udp_timers(u, now());
      }
    }
  }

  Time next_app_deadline() const {
    if (!setup_done_) {
      return s_.start;
    }
    Time t = Time::never();
    const Time n = now();
    for (const TcpEnd& e : ends_) {
      switch (e.phase) {
        case Phase::waiting:
          if (!e.passive) {
            t = std::min(t, e.start_at);
          }
          break;
        case Phase::connecting:
          t = std::min(t, e.last_activity + s_.app_idle_timeout);
          break;
        case Phase::open:
          t = std::min(t, e.last_activity + s_.app_idle_timeout);
          t = std::min(t, e.abort_at);
          if (e.sent < e.to_send && e.next_write > n) t = std::min(t, e.next_write);
          if (!e.eof && e.paused_until > n) {
            t = std::min(t, e.paused_until);
          }
          break;
        case Phase::done:
          break;
      }
    }
    for (const Listener& l : listeners_) {
      if (l.open) {
        t = std::min(t, l.give_up);
      }
    }
    for (const UdpEnd& u : udp_) {
      if (u.done) {
        continue;
      }
      if (!u.open) {
        t = std::min(t, u.open_at);
        continue;
      }
      if (u.client && u.next_seq < u.count) {
        t = std::min(t, u.open_at + u.interval * u.next_seq);
      }
      t = std::min(t, u.close_at);
    }
    for (const PingEnd& p : pings_) {
      if (p.done) {
        continue;
      }
      if (p.next_seq < p.count) {
        t = std::min(t, p.start_at + p.interval * p.next_seq);
      }
      t = std::min(t, p.close_at);
    }
    return t;
  }

  bool finished() const {
    if (!setup_done_) {
      return false;
    }
    return std::ranges::all_of(ends_, [](const TcpEnd& e) { return e.phase == Phase::done; }) &&
           std::ranges::all_of(listeners_, [](const Listener& l) { return !l.open; }) &&
           std::ranges::all_of(udp_, [](const UdpEnd& u) { return u.done; }) &&
           std::ranges::all_of(pings_, [](const PingEnd& p) { return p.done; });
  }

  Scenario s_;
  std::uint32_t index_;
  Stack stack_;
  SimContext* ctx_ = nullptr;
  TcpSocketOptions opts_;
  std::vector<std::byte> buf_;
  bool setup_done_ = false;
  bool failed_ = false;
  std::vector<TcpEnd> ends_;
  std::vector<Listener> listeners_;
  std::vector<UdpEnd> udp_;
  std::vector<PingEnd> pings_;
  std::map<Handle, std::size_t> tcp_handles_, listener_handles_, udp_handles_;
  bool shared_listener_ = false;  // some listener has several ends
  std::map<std::uint32_t, std::uint16_t> remote_port_;  // conn_id -> remote port (shared listeners)
  std::uint64_t activity_ = 0;
  Counts counts_;
};

StackNode::StackNode(const Scenario& s, std::uint32_t index)
    : impl_(std::make_unique<Impl>(s, index)) {}

StackNode::~StackNode() = default;

void StackNode::receive(Time now, std::span<const std::byte> datagram) {
  impl_->stack_.receive(now, datagram);
}

void StackNode::advance(Time now) { impl_->stack_.advance(now); }

std::optional<TxPacket> StackNode::pop_transmit() {
  auto p = impl_->stack_.pop_transmit();
  if (p) {
    ++impl_->activity_;
  }
  return p;
}

Time StackNode::next_deadline() const { return impl_->stack_.next_deadline(); }

void StackNode::attach(SimContext& ctx, std::uint32_t index) {
  static_cast<void>(index);
  impl_->attach(ctx);
}

Time StackNode::next_app_deadline() const { return impl_->next_app_deadline(); }

void StackNode::run_apps(Time now) {
  static_cast<void>(now);  // socket calls use the stack's now(), set by the World's last call
  impl_->run_apps();
}

bool StackNode::finished() const { return impl_->finished(); }

void StackNode::debug_check() const { impl_->stack_.debug_check(); }

std::optional<StackUsage> StackNode::debug_usage() const { return impl_->stack_.debug_usage(); }

std::uint64_t StackNode::activity() const { return impl_->activity_; }

Stack& StackNode::stack() noexcept { return impl_->stack_; }

const Stack& StackNode::stack() const noexcept { return impl_->stack_; }

const StackNode::Counts& StackNode::counts() const noexcept { return impl_->counts_; }

}  // namespace utcp::sim
