#include "common/fake_transport.hpp"

#include <algorithm>
#include <utility>

#include "utcp/check.hpp"

namespace utcp::app {

namespace {

// Largest UDP payload in one IPv4 datagram (65535 - 20 - 8).
constexpr std::size_t max_udp_payload = 65507;

bool addr_matches(Ipv4Addr bound, Ipv4Addr dst) { return bound.v == 0 || bound == dst; }

}  // namespace

FakeTransport::FakeTransport(const FakeTransportOptions& options)
    : opt_(options), now_(options.start), next_port_(options.first_ephemeral_port) {
  UTCP_CHECK(opt_.rcv_buf > 0);
  UTCP_CHECK(opt_.first_ephemeral_port > 0);
}

FakeTransport::Sock* FakeTransport::find(ConnId id, Kind kind) {
  const auto it = socks_.find(id);
  if (it == socks_.end() || it->second.kind != kind) {
    return nullptr;
  }
  return &it->second;
}

ConnId FakeTransport::add(Sock s) {
  const ConnId id = next_id_++;
  socks_.emplace(id, std::move(s));
  return id;
}

std::uint16_t FakeTransport::ephemeral_port() {
  for (std::uint32_t tries = 0; tries <= 0xffff; ++tries) {
    const std::uint16_t port = next_port_;
    next_port_ = next_port_ == 0xffff ? opt_.first_ephemeral_port
                                      : static_cast<std::uint16_t>(next_port_ + 1);
    const bool used = std::ranges::any_of(
        socks_, [port](const auto& kv) { return kv.second.local.port == port; });
    if (!used) {
      return port;
    }
  }
  return 0;
}

void FakeTransport::queue(Event e) { events_.push_back(e); }

void FakeTransport::queue_readable(ConnId id) {
  auto it = socks_.find(id);
  if (it != socks_.end() && !it->second.readable_queued) {
    it->second.readable_queued = true;
    queue({EvType::readable, id});
  }
}

void FakeTransport::queue_writable(ConnId id) {
  auto it = socks_.find(id);
  if (it != socks_.end() && !it->second.writable_queued) {
    it->second.writable_queued = true;
    queue({EvType::writable, id});
  }
}

void FakeTransport::maybe_closed(ConnId id) {
  Sock* s = find(id, Kind::tcp);
  if (s != nullptr && s->fin_sent && s->peer_fin && !s->closed_queued && !s->error) {
    s->closed_queued = true;
    queue({EvType::closed, id});
  }
}

// --- TCP.

std::expected<ConnId, Error> FakeTransport::connect(Endpoint remote, const TcpSocketOptions& opts) {
  if (remote.port == 0) {
    return std::unexpected(Error::invalid_argument);
  }
  const std::uint16_t port = ephemeral_port();
  if (port == 0) {
    return std::unexpected(Error::addr_not_available);
  }
  Sock client{.kind = Kind::tcp, .local = {opt_.local_addr, port}, .remote = remote, .opts = opts};

  ConnId listener = no_conn;
  for (const auto& [id, s] : socks_) {
    if (s.kind == Kind::listener && s.local.port == remote.port &&
        addr_matches(s.local.addr, remote.addr)) {
      listener = id;
      break;
    }
  }
  if (listener == no_conn) {
    client.error = Error::connection_refused;
    const ConnId c = add(std::move(client));
    queue({.type = EvType::error, .id = c, .err = Error::connection_refused});
    return c;
  }

  const Endpoint client_local = client.local;
  const ConnId c = add(std::move(client));
  Sock server{.kind = Kind::tcp,
              .local = {remote.addr.v == 0 ? opt_.local_addr : remote.addr, remote.port},
              .remote = client_local,
              .opts = socks_.at(listener).opts,
              .peer = c};
  const ConnId srv = add(std::move(server));
  socks_.at(c).peer = srv;
  queue({EvType::connected, c});
  queue({.type = EvType::accept, .id = listener, .conn = srv});
  return c;
}

std::expected<ConnId, Error> FakeTransport::listen(Endpoint local, std::uint32_t /*backlog*/,
                                                   const TcpSocketOptions& opts) {
  if (local.port == 0) {
    local.port = ephemeral_port();
    if (local.port == 0) {
      return std::unexpected(Error::addr_not_available);
    }
  }
  for (const auto& kv : socks_) {
    if (kv.second.kind == Kind::listener && kv.second.local.port == local.port) {
      return std::unexpected(Error::addr_in_use);
    }
  }
  return add(Sock{.kind = Kind::listener, .local = local, .opts = opts});
}

std::expected<std::size_t, Error> FakeTransport::send(ConnId id, std::span<const std::byte> data) {
  Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (s->error) {
    return std::unexpected(*s->error);
  }
  if (s->fin_sent) {
    return std::unexpected(Error::shut_down);
  }
  if (s->peer == no_conn) {
    return std::unexpected(Error::connection_reset);
  }
  Sock& p = socks_.at(s->peer);
  const std::size_t space = opt_.rcv_buf - std::min<std::size_t>(p.rx.size(), opt_.rcv_buf);
  const std::size_t n = std::min(space, data.size());
  if (n < data.size()) {
    s->want_writable = true;
  }
  if (n == 0) {
    return data.empty() ? std::expected<std::size_t, Error>(0)
                        : std::unexpected(Error::would_block);
  }
  p.rx.insert(p.rx.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(n));
  s->bytes_sent += n;
  ++s->segs_out;
  p.bytes_received += n;
  ++p.segs_in;
  queue_readable(s->peer);
  return n;
}

std::expected<std::size_t, Error> FakeTransport::recv(ConnId id, std::span<std::byte> out) {
  Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (s->rx.empty()) {
    if (s->error) {
      return std::unexpected(*s->error);
    }
    if (s->peer_fin) {
      return 0;
    }
    return std::unexpected(Error::would_block);
  }
  const std::size_t n = std::min(out.size(), s->rx.size());
  std::copy_n(s->rx.begin(), n, out.begin());
  s->rx.erase(s->rx.begin(), s->rx.begin() + static_cast<std::ptrdiff_t>(n));
  // The sender may write again once half the buffer is free.
  if (s->peer != no_conn) {
    Sock& p = socks_.at(s->peer);
    if (p.want_writable && opt_.rcv_buf - s->rx.size() >= opt_.rcv_buf / 2) {
      p.want_writable = false;
      queue_writable(s->peer);
    }
  }
  return n;
}

void FakeTransport::shutdown_write(ConnId id) {
  Sock* s = find(id, Kind::tcp);
  if (s == nullptr || s->fin_sent || s->error) {
    return;
  }
  s->fin_sent = true;
  const ConnId peer = s->peer;
  if (peer != no_conn) {
    socks_.at(peer).peer_fin = true;
    queue_readable(peer);
    maybe_closed(peer);
  }
  maybe_closed(id);
}

void FakeTransport::close(ConnId id) {
  const auto it = socks_.find(id);
  if (it == socks_.end()) {
    return;
  }
  // Pending events of `id` are skipped by dispatch (ids are never reused).
  const Sock s = std::move(it->second);
  socks_.erase(it);
  if (s.kind != Kind::tcp || s.peer == no_conn) {
    return;
  }
  Sock& p = socks_.at(s.peer);
  p.peer = no_conn;
  if (!s.rx.empty()) {
    // Unread data: RST instead of FIN (RFC 2525 §2.17, Linux tcp_close).
    reset(s.peer);
    return;
  }
  if (!s.fin_sent) {
    p.peer_fin = true;
    queue_readable(s.peer);
  }
  maybe_closed(s.peer);
}

void FakeTransport::reset(ConnId id) {
  Sock* s = find(id, Kind::tcp);
  if (s == nullptr || s->error) {
    return;
  }
  s->peer = no_conn;
  s->error = Error::connection_reset;
  queue({.type = EvType::error, .id = id, .err = Error::connection_reset});
}

ConnSample FakeTransport::sample(ConnId id) {
  ConnSample out;
  const Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return out;
  }
  out.set_cc_name("fake");
  if (s->error || (s->fin_sent && s->peer_fin)) {
    out.state = TcpState::closed;
  } else if (s->fin_sent) {
    out.state = TcpState::fin_wait_2;
  } else if (s->peer_fin) {
    out.state = TcpState::close_wait;
  } else {
    out.state = TcpState::established;
  }
  out.bytes_sent = s->bytes_sent;
  out.bytes_acked = s->bytes_sent;  // delivered at once
  out.bytes_received = s->bytes_received;
  out.segs_out = s->segs_out;
  out.segs_in = s->segs_in;
  out.data_segs_out = s->segs_out;
  out.data_segs_in = s->segs_in;
  out.rcv_wnd = static_cast<std::uint32_t>(opt_.rcv_buf - s->rx.size());
  if (s->peer != no_conn) {
    const Sock& p = socks_.at(s->peer);
    out.snd_wnd = static_cast<std::uint32_t>(opt_.rcv_buf - p.rx.size());
  }
  return out;
}

// --- UDP.

std::expected<ConnId, Error> FakeTransport::udp_open(Endpoint local) {
  if (local.port == 0) {
    local.port = ephemeral_port();
    if (local.port == 0) {
      return std::unexpected(Error::addr_not_available);
    }
  }
  for (const auto& kv : socks_) {
    if (kv.second.kind == Kind::udp && kv.second.local.port == local.port) {
      return std::unexpected(Error::addr_in_use);
    }
  }
  return add(Sock{.kind = Kind::udp, .local = local});
}

std::expected<void, Error> FakeTransport::send_to(ConnId id, Endpoint remote,
                                                  std::span<const std::byte> data) {
  const Sock* s = find(id, Kind::udp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (remote.port == 0) {
    return std::unexpected(Error::invalid_argument);
  }
  if (data.size() > max_udp_payload) {
    return std::unexpected(Error::message_too_big);
  }
  const Endpoint from{s->local.addr.v == 0 ? opt_.local_addr : s->local.addr, s->local.port};
  for (auto& [dst_id, d] : socks_) {
    if (d.kind == Kind::udp && d.local.port == remote.port &&
        addr_matches(d.local.addr, remote.addr)) {
      d.dgrams.push_back({from, std::vector<std::byte>(data.begin(), data.end())});
      queue_readable(dst_id);
      return {};
    }
  }
  ++udp_dropped_;  // no socket: the datagram is lost, as on a network
  return {};
}

std::expected<UdpRecv, Error> FakeTransport::recv_from(ConnId id, std::span<std::byte> out) {
  Sock* s = find(id, Kind::udp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (s->dgrams.empty()) {
    return std::unexpected(Error::would_block);
  }
  const Datagram d = std::move(s->dgrams.front());
  s->dgrams.pop_front();
  const std::size_t n = std::min(out.size(), d.bytes.size());
  std::copy_n(d.bytes.begin(), n, out.begin());
  return UdpRecv{.len = d.bytes.size(), .from = d.from, .truncated = n < d.bytes.size()};
}

// --- Timers and running.

TimerToken FakeTransport::add_timer(Duration period, std::function<void()> cb) {
  UTCP_CHECK(period > Duration::zero());
  const TimerToken t = next_timer_++;
  timers_.emplace(t, Timer{now_ + period, period, std::move(cb)});
  return t;
}

TimerToken FakeTransport::add_oneshot(Duration delay, std::function<void()> cb) {
  const TimerToken t = next_timer_++;
  timers_.emplace(t, Timer{now_ + std::max(delay, Duration::zero()), Duration::zero(),
                           std::move(cb)});
  return t;
}

void FakeTransport::cancel_timer(TimerToken t) { timers_.erase(t); }

void FakeTransport::inject_error(ConnId id, Error e) {
  Sock* s = find(id, Kind::tcp);
  if (s == nullptr || s->error) {
    return;
  }
  s->error = e;
  queue({.type = EvType::error, .id = id, .err = e});
}

void FakeTransport::dispatch(const Event& e, Handler& h) {
  const auto it = socks_.find(e.id);
  if (it == socks_.end()) {
    if (e.type == EvType::accept) {
      // The listener was closed first: the connection is reset, as Linux
      // inet_csk_listen_stop does with the accept queue.
      if (const Sock* c = find(e.conn, Kind::tcp); c != nullptr) {
        const ConnId peer = c->peer;
        socks_.erase(e.conn);
        reset(peer);
      }
    }
    return;
  }
  switch (e.type) {
    case EvType::accept: h.on_accept(e.id, e.conn); break;
    case EvType::connected: h.on_connected(e.id); break;
    case EvType::readable:
      it->second.readable_queued = false;
      h.on_readable(e.id);
      break;
    case EvType::writable:
      it->second.writable_queued = false;
      h.on_writable(e.id);
      break;
    case EvType::closed: h.on_closed(e.id); break;
    case EvType::error: h.on_error(e.id, e.err); break;
  }
}

void FakeTransport::run(Handler& h) {
  stopped_ = false;
  while (!stopped_) {
    if (!events_.empty()) {
      const Event e = events_.front();
      events_.pop_front();
      dispatch(e, h);
      continue;
    }
    if (timers_.empty()) {
      return;
    }
    auto next = timers_.begin();
    for (auto it = timers_.begin(); it != timers_.end(); ++it) {
      if (it->second.deadline < next->second.deadline) {
        next = it;  // ties keep the lower (older) token
      }
    }
    now_ = std::max(now_, next->second.deadline);
    // The callback may cancel or add timers, its own included.
    std::function<void()> cb;
    if (next->second.period > Duration::zero()) {
      next->second.deadline = next->second.deadline + next->second.period;
      cb = next->second.cb;
    } else {
      cb = std::move(next->second.cb);
      timers_.erase(next);
    }
    cb();
  }
}

}  // namespace utcp::app
