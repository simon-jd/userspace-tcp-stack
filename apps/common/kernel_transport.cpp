#include "common/kernel_transport.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "common/utcp_transport.hpp"
#include "utcp/check.hpp"
#include "utcp/config.hpp"
#include "utcp/trace.hpp"

namespace utcp::app {

namespace {

constexpr std::uint32_t conn_events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;

sockaddr_in to_sockaddr(Endpoint e) {
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(e.port);
  sa.sin_addr.s_addr = htonl(e.addr.v);
  return sa;
}

Endpoint from_sockaddr(const sockaddr_in& sa) {
  return Endpoint{Ipv4Addr{ntohl(sa.sin_addr.s_addr)}, ntohs(sa.sin_port)};
}

const sockaddr* as_sockaddr(const sockaddr_in& sa) { return reinterpret_cast<const sockaddr*>(&sa); }
sockaddr* as_sockaddr(sockaddr_in& sa) { return reinterpret_cast<sockaddr*>(&sa); }

int so_error(int fd) {
  int err = 0;
  socklen_t len = sizeof err;
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
    return errno;
  }
  return err;
}

Duration us(std::uint64_t v) { return Duration{static_cast<std::int64_t>(v) * 1000}; }
Duration ms(std::uint64_t v) { return Duration{static_cast<std::int64_t>(v) * 1'000'000}; }

// Linux include/net/tcp_states.h (not in the UAPI headers).
TcpState state_of(std::uint8_t s) {
  switch (s) {
    case 1: return TcpState::established;
    case 2: return TcpState::syn_sent;
    case 3: return TcpState::syn_received;
    case 4: return TcpState::fin_wait_1;
    case 5: return TcpState::fin_wait_2;
    case 6: return TcpState::time_wait;
    case 8: return TcpState::close_wait;
    case 9: return TcpState::last_ack;
    case 10: return TcpState::listen;
    case 11: return TcpState::closing;
    default: return TcpState::closed;  // 7 = TCP_CLOSE
  }
}

CaState ca_state_of(std::uint8_t s) {
  switch (s) {
    case TCP_CA_Disorder: return CaState::disorder;
    case TCP_CA_CWR: return CaState::cwr;
    case TCP_CA_Recovery: return CaState::recovery;
    case TCP_CA_Loss: return CaState::loss;
    default: return CaState::open;
  }
}

}  // namespace

Error error_from_errno(int err) noexcept {
  switch (err) {
    case EAGAIN: return Error::would_block;
    case EBADF: return Error::bad_handle;
    case EINVAL: return Error::invalid_argument;
    case EADDRINUSE: return Error::addr_in_use;
    case EADDRNOTAVAIL: return Error::addr_not_available;
    case ENOTCONN: return Error::not_connected;
    case EISCONN: return Error::already_connected;
    case ECONNREFUSED: return Error::connection_refused;
    case ECONNRESET: return Error::connection_reset;
    case ECONNABORTED: return Error::connection_aborted;
    case ETIMEDOUT: return Error::timed_out;
    case EHOSTUNREACH: return Error::host_unreachable;
    case ENETUNREACH: return Error::network_unreachable;
    case EMSGSIZE: return Error::message_too_big;
    case ENOBUFS:
    case ENOMEM: return Error::no_buffers;
    case EPIPE: return Error::shut_down;
    default: return Error::invalid_state;
  }
}

std::string_view kernel_cc_name(CcAlgo cc) noexcept {
  switch (cc) {
    case CcAlgo::newreno: return "reno";  // Linux tcp_cong.c: "reno" is NewReno (RFC 6582)
    case CcAlgo::cubic: return "cubic";
    case CcAlgo::bbr: return "bbr";
  }
  return "reno";
}

std::expected<CcAlgo, std::string> parse_cc(std::string_view s) {
  if (s == "newreno" || s == "reno") return CcAlgo::newreno;
  if (s == "cubic") return CcAlgo::cubic;
  if (s == "bbr") return CcAlgo::bbr;
  return std::unexpected("unknown congestion control '" + std::string(s) +
                         "' (newreno, reno, cubic, bbr)");
}

std::string describe(Error e) {
  return std::string(to_string(e)) + " (" + std::strerror(to_errno(e)) + ")";
}

// --- KernelTransport.

KernelTransport::KernelTransport(const EventLoopOptions& loop_options) : loop_(loop_options) {
  event_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (event_fd_ < 0) {
    std::fprintf(stderr, "KernelTransport: eventfd: %s\n", std::strerror(errno));
    std::abort();
  }
  loop_.watch(event_fd_, EPOLLIN, [this](std::uint32_t) { on_pending(); });
  loop_.set_deadline_source([this] { return next_deadline(); });
  loop_.set_deadline_handler([this](Time now) { on_deadline(now); });
}

KernelTransport::~KernelTransport() {
  for (auto& [id, s] : socks_) {
    ::close(s.fd);
  }
  loop_.unwatch(event_fd_);
  ::close(event_fd_);
}

KernelTransport::Sock* KernelTransport::find(ConnId id, Kind kind) {
  const auto it = socks_.find(id);
  return it == socks_.end() || it->second.kind != kind ? nullptr : &it->second;
}

const KernelTransport::Sock* KernelTransport::find_any(ConnId id) const {
  const auto it = socks_.find(id);
  return it == socks_.end() ? nullptr : &it->second;
}

ConnId KernelTransport::add(Sock s) {
  const ConnId id = next_id_++;
  socks_.emplace(id, s);
  return id;
}

Error KernelTransport::fail(const char* what, int err) {
  detail_ = std::string(what) + ": " + std::strerror(err);
  return error_from_errno(err);
}

std::expected<void, Error> KernelTransport::apply_options(int fd, const TcpSocketOptions& o) {
  const auto set_int = [&](int level, int name, int v, const char* what) -> bool {
    if (setsockopt(fd, level, name, &v, sizeof v) != 0) {
      fail(what, errno);
      return false;
    }
    return true;
  };
  if (o.nodelay && !set_int(IPPROTO_TCP, TCP_NODELAY, *o.nodelay ? 1 : 0, "setsockopt(TCP_NODELAY)")) {
    return std::unexpected(Error::invalid_argument);
  }
  if (o.snd_buf &&
      !set_int(SOL_SOCKET, SO_SNDBUF, static_cast<int>(*o.snd_buf), "setsockopt(SO_SNDBUF)")) {
    return std::unexpected(Error::invalid_argument);
  }
  if (o.rcv_buf &&
      !set_int(SOL_SOCKET, SO_RCVBUF, static_cast<int>(*o.rcv_buf), "setsockopt(SO_RCVBUF)")) {
    return std::unexpected(Error::invalid_argument);
  }
  if (o.mss_clamp && !set_int(IPPROTO_TCP, TCP_MAXSEG, *o.mss_clamp, "setsockopt(TCP_MAXSEG)")) {
    return std::unexpected(Error::invalid_argument);
  }
  if (o.cc) {
    const std::string_view name = kernel_cc_name(*o.cc);
    if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name.data(),
                   static_cast<socklen_t>(name.size())) != 0) {
      fail(("setsockopt(TCP_CONGESTION, " + std::string(name) + ")").c_str(), errno);
      return std::unexpected(Error::invalid_argument);
    }
  }
  return {};
}

void KernelTransport::watch(ConnId id, int fd) {
  loop_.watch(fd, conn_events, [this, id](std::uint32_t ev) { on_io(id, ev); });
}

void KernelTransport::queue(Pending p) {
  pending_.push_back(p);
  const std::uint64_t one = 1;
  [[maybe_unused]] const ssize_t n = ::write(event_fd_, &one, sizeof one);
}

std::expected<ConnId, Error> KernelTransport::connect(Endpoint remote, const TcpSocketOptions& opts) {
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return std::unexpected(fail("socket", errno));
  }
  if (auto r = apply_options(fd, opts); !r) {
    ::close(fd);
    return std::unexpected(r.error());
  }
  const sockaddr_in sa = to_sockaddr(remote);
  bool in_progress = false;
  if (::connect(fd, as_sockaddr(sa), sizeof sa) != 0) {
    if (errno != EINPROGRESS) {
      const Error e = fail("connect", errno);
      ::close(fd);
      return std::unexpected(e);
    }
    in_progress = true;
  }
  const ConnId id = add(Sock{.kind = Kind::tcp, .fd = fd, .opts = opts, .connecting = in_progress});
  watch(id, fd);
  if (!in_progress) {
    queue({EvType::connected, id});
  }
  return id;
}

std::expected<ConnId, Error> KernelTransport::listen(Endpoint local, std::uint32_t backlog,
                                                     const TcpSocketOptions& opts) {
  const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return std::unexpected(fail("socket", errno));
  }
  const int one = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
    const Error e = fail("setsockopt(SO_REUSEADDR)", errno);
    ::close(fd);
    return std::unexpected(e);
  }
  if (auto r = apply_options(fd, opts); !r) {
    ::close(fd);
    return std::unexpected(r.error());
  }
  const sockaddr_in sa = to_sockaddr(local);
  if (::bind(fd, as_sockaddr(sa), sizeof sa) != 0) {
    const Error e = fail("bind", errno);
    ::close(fd);
    return std::unexpected(e);
  }
  const int bl = static_cast<int>(std::min<std::uint32_t>(backlog, 65535));
  if (::listen(fd, bl) != 0) {
    const Error e = fail("listen", errno);
    ::close(fd);
    return std::unexpected(e);
  }
  const ConnId id = add(Sock{.kind = Kind::listener, .fd = fd, .opts = opts});
  loop_.watch(fd, EPOLLIN | EPOLLET, [this, id](std::uint32_t) { on_listener(id); });
  return id;
}

std::expected<std::size_t, Error> KernelTransport::send(ConnId id, std::span<const std::byte> data) {
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
  if (s->connecting) {
    s->want_writable = true;
    return std::unexpected(Error::would_block);
  }
  if (data.empty()) {
    return 0;
  }
  const ssize_t n = ::send(s->fd, data.data(), data.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      s->want_writable = true;
      return std::unexpected(Error::would_block);
    }
    // EPIPE without our shutdown: the connection was reset or closed by an
    // error whose SO_ERROR was already read.
    const Error e = errno == EPIPE ? Error::connection_reset : fail("send", errno);
    s->error = e;
    return std::unexpected(e);
  }
  if (static_cast<std::size_t>(n) < data.size()) {
    s->want_writable = true;
  }
  return static_cast<std::size_t>(n);
}

std::expected<std::size_t, Error> KernelTransport::recv(ConnId id, std::span<std::byte> out) {
  Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (s->connecting) {
    return std::unexpected(Error::would_block);
  }
  if (out.empty()) {
    return 0;
  }
  const ssize_t n = ::recv(s->fd, out.data(), out.size(), MSG_DONTWAIT);
  if (n > 0) {
    return static_cast<std::size_t>(n);
  }
  if (n == 0) {
    // After an error whose SO_ERROR was read, Linux reports the end of stream.
    if (s->error) {
      return std::unexpected(*s->error);
    }
    return 0;
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK) {
    if (s->error) {
      return std::unexpected(*s->error);
    }
    return std::unexpected(Error::would_block);
  }
  const Error e = fail("recv", errno);
  s->error = e;
  return std::unexpected(e);
}

void KernelTransport::shutdown_write(ConnId id) {
  Sock* s = find(id, Kind::tcp);
  if (s == nullptr || s->fin_sent || s->error) {
    return;
  }
  s->fin_sent = true;
  if (s->connecting) {
    s->shutdown_pending = true;  // on_io shuts down once the connect succeeds
    return;
  }
  // Wakes the socket: EPOLLHUP follows if the peer's FIN is already in.
  ::shutdown(s->fd, SHUT_WR);
}

void KernelTransport::close(ConnId id) {
  const auto it = socks_.find(id);
  if (it == socks_.end()) {
    return;
  }
  loop_.unwatch(it->second.fd);
  // Linux tcp_close: FIN, or RST if unread data remains (RFC 2525 §2.17).
  ::close(it->second.fd);
  socks_.erase(it);
}

ConnSample KernelTransport::sample(ConnId id) {
  ConnSample out;
  const Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return out;
  }
  tcp_info ti{};
  socklen_t len = sizeof ti;
  if (getsockopt(s->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) != 0) {
    return out;
  }
  std::array<char, 16> cc{};
  socklen_t cc_len = sizeof cc;
  std::string_view cc_name;
  if (getsockopt(s->fd, IPPROTO_TCP, TCP_CONGESTION, cc.data(), &cc_len) == 0) {
    cc_name = std::string_view(cc.data(), strnlen(cc.data(), cc_len));
  }
  return sample_from_tcp_info(ti, cc_name);
}

ConnSample sample_from_tcp_info(const tcp_info& ti, std::string_view cc) {
  ConnSample out;
  // Linux names NewReno (RFC 6582) "reno"; TcpInfo says "newreno" (stats.hpp).
  out.set_cc_name(cc == "reno" ? std::string_view("newreno") : cc);
  // DESIGN §10.1, field by field.
  out.state = state_of(ti.tcpi_state);
  out.ca_state = ca_state_of(ti.tcpi_ca_state);
  out.snd_wscale = ti.tcpi_snd_wscale;
  out.rcv_wscale = ti.tcpi_rcv_wscale;
  out.rto = us(ti.tcpi_rto);
  out.ato = us(ti.tcpi_ato);
  out.srtt = us(ti.tcpi_rtt);
  out.rttvar = us(ti.tcpi_rttvar);
  out.min_rtt = us(ti.tcpi_min_rtt);
  out.cwnd = ti.tcpi_snd_cwnd;
  out.ssthresh = ti.tcpi_snd_ssthresh;
  out.snd_mss = ti.tcpi_snd_mss;
  out.rcv_mss = ti.tcpi_rcv_mss;
  out.adv_mss = ti.tcpi_advmss;
  out.pmtu = ti.tcpi_pmtu;
  out.bytes_sent = ti.tcpi_bytes_sent;
  out.bytes_retrans = ti.tcpi_bytes_retrans;
  out.bytes_acked = ti.tcpi_bytes_acked;
  out.bytes_received = ti.tcpi_bytes_received;
  out.segs_out = ti.tcpi_segs_out;
  out.segs_in = ti.tcpi_segs_in;
  out.data_segs_out = ti.tcpi_data_segs_out;
  out.data_segs_in = ti.tcpi_data_segs_in;
  out.pacing_rate = ti.tcpi_pacing_rate;  // ~0 = no pacing limit
  out.delivery_rate = ti.tcpi_delivery_rate;
  out.delivered = ti.tcpi_delivered;
  out.app_limited = ti.tcpi_delivery_rate_app_limited != 0;
  out.busy_time = us(ti.tcpi_busy_time);
  out.rwnd_limited = us(ti.tcpi_rwnd_limited);
  out.sndbuf_limited = us(ti.tcpi_sndbuf_limited);
  out.unacked = ti.tcpi_unacked;
  out.sacked = ti.tcpi_sacked;
  out.lost = ti.tcpi_lost;
  out.retrans = ti.tcpi_retrans;
  out.total_retrans = ti.tcpi_total_retrans;
  out.dsack_dups = ti.tcpi_dsack_dups;
  out.reordering = ti.tcpi_reordering;
  out.reord_seen = ti.tcpi_reord_seen;
  out.rcv_rtt = us(ti.tcpi_rcv_rtt);
  out.rcv_space = ti.tcpi_rcv_space;
  out.rcv_ssthresh = ti.tcpi_rcv_ssthresh;
  out.snd_wnd = ti.tcpi_snd_wnd;
  out.rcv_wnd = ti.tcpi_rcv_wnd;
  out.notsent_bytes = ti.tcpi_notsent_bytes;
  out.last_data_sent = ms(ti.tcpi_last_data_sent);
  out.last_data_recv = ms(ti.tcpi_last_data_recv);
  out.last_ack_recv = ms(ti.tcpi_last_ack_recv);
  return out;
}

// --- UDP.

std::expected<ConnId, Error> KernelTransport::udp_open(Endpoint local) {
  const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return std::unexpected(fail("socket", errno));
  }
  const sockaddr_in sa = to_sockaddr(local);
  if (::bind(fd, as_sockaddr(sa), sizeof sa) != 0) {
    const Error e = fail("bind", errno);
    ::close(fd);
    return std::unexpected(e);
  }
  const ConnId id = add(Sock{.kind = Kind::udp, .fd = fd});
  loop_.watch(fd, EPOLLIN | EPOLLOUT | EPOLLET, [this, id](std::uint32_t ev) { on_io(id, ev); });
  return id;
}

std::expected<void, Error> KernelTransport::send_to(ConnId id, Endpoint remote,
                                                    std::span<const std::byte> data) {
  Sock* s = find(id, Kind::udp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (remote.port == 0) {
    return std::unexpected(Error::invalid_argument);
  }
  const sockaddr_in sa = to_sockaddr(remote);
  if (::sendto(s->fd, data.data(), data.size(), MSG_DONTWAIT | MSG_NOSIGNAL, as_sockaddr(sa),
               sizeof sa) < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      s->want_writable = true;
      return std::unexpected(Error::would_block);
    }
    return std::unexpected(fail("sendto", errno));
  }
  return {};
}

std::expected<UdpRecv, Error> KernelTransport::recv_from(ConnId id, std::span<std::byte> out) {
  Sock* s = find(id, Kind::udp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  sockaddr_in sa{};
  socklen_t sa_len = sizeof sa;
  // MSG_TRUNC: the result is the datagram's real length.
  const ssize_t n = ::recvfrom(s->fd, out.data(), out.size(), MSG_DONTWAIT | MSG_TRUNC,
                               as_sockaddr(sa), &sa_len);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return std::unexpected(Error::would_block);
    }
    return std::unexpected(fail("recvfrom", errno));
  }
  const auto len = static_cast<std::size_t>(n);
  return UdpRecv{.len = len, .from = from_sockaddr(sa), .truncated = len > out.size()};
}

std::expected<Endpoint, Error> KernelTransport::local_endpoint(ConnId id) const {
  const Sock* s = find_any(id);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  sockaddr_in sa{};
  socklen_t len = sizeof sa;
  if (getsockname(s->fd, as_sockaddr(sa), &len) != 0) {
    return std::unexpected(error_from_errno(errno));
  }
  return from_sockaddr(sa);
}

std::expected<Endpoint, Error> KernelTransport::remote_endpoint(ConnId id) const {
  const Sock* s = find_any(id);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  sockaddr_in sa{};
  socklen_t len = sizeof sa;
  if (getpeername(s->fd, as_sockaddr(sa), &len) != 0) {
    return std::unexpected(error_from_errno(errno));
  }
  return from_sockaddr(sa);
}

// --- Events.

void KernelTransport::on_listener(ConnId id) {
  // Edge-triggered: accept until EAGAIN. Whenever we stop before EAGAIN, the
  // queued connections get no new edge, so a timer comes back for them.
  while (true) {
    Sock* l = find(id, Kind::listener);
    if (l == nullptr) {
      return;
    }
    if (stopped_) {
      retry_accept(id, Duration::zero());  // runs at the next run()
      return;
    }
    const int fd = ::accept4(l->fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) {
      const int err = errno;
      switch (err) {
        case EAGAIN:
#if EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
          l->accept_failing = false;
          return;
        // accept(2) "Error handling": pending network errors of the new
        // connection; retry like EAGAIN.
        case EINTR:
        case ECONNABORTED:
        case ENETDOWN:
        case EPROTO:
        case ENOPROTOOPT:
        case EHOSTDOWN:
        case ENONET:
        case EHOSTUNREACH:
        case EOPNOTSUPP:
        case ENETUNREACH:
          continue;
        default:
          // EMFILE, ENFILE, ENOBUFS, ENOMEM: try again shortly; the
          // connections stay queued (or the peer gives up).
          if (!l->accept_failing) {
            std::fprintf(stderr, "KernelTransport: accept4: %s (retrying every 10 ms)\n",
                         std::strerror(err));
            l->accept_failing = true;
          }
          retry_accept(id, std::chrono::milliseconds(10));
          return;
      }
    }
    l->accept_failing = false;
    const ConnId c = add(Sock{.kind = Kind::tcp, .fd = fd, .opts = l->opts});
    watch(c, fd);
    if (handler_ != nullptr) {
      handler_->on_accept(id, c);
    }
  }
}

void KernelTransport::retry_accept(ConnId id, Duration delay) {
  Sock* l = find(id, Kind::listener);
  if (l == nullptr || l->accept_retry) {
    return;
  }
  l->accept_retry = true;
  add_oneshot(delay, [this, id] {
    if (Sock* s = find(id, Kind::listener)) {
      s->accept_retry = false;
      on_listener(id);
    }
  });
}

void KernelTransport::on_io(ConnId id, std::uint32_t ev) {
  const auto it = socks_.find(id);
  if (it == socks_.end() || handler_ == nullptr) {
    return;
  }
  Sock* s = &it->second;
  if (s->kind == Kind::udp) {
    if ((ev & EPOLLIN) != 0) {
      handler_->on_readable(id);
    }
    s = find(id, Kind::udp);
    if (s != nullptr && (ev & EPOLLOUT) != 0 && s->want_writable) {
      s->want_writable = false;
      handler_->on_writable(id);
    }
    return;
  }
  if (s->connecting) {
    if ((ev & (EPOLLOUT | EPOLLERR | EPOLLHUP)) == 0) {
      return;
    }
    s->connecting = false;
    const int err = so_error(s->fd);
    if (err != 0) {
      s->error = fail("connect", err);
      handler_->on_error(id, *s->error);
      return;
    }
    if (s->shutdown_pending) {
      s->shutdown_pending = false;
      ::shutdown(s->fd, SHUT_WR);
    }
    handler_->on_connected(id);
    s = find(id, Kind::tcp);
    if (s == nullptr) {
      return;
    }
  }
  if ((ev & EPOLLERR) != 0 && !s->error) {
    const int err = so_error(s->fd);
    if (err != 0) {
      s->error = fail("socket error", err);
      handler_->on_error(id, *s->error);
      return;  // data received before the error stays readable (recv)
    }
  }
  if ((ev & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) != 0) {
    handler_->on_readable(id);
    s = find(id, Kind::tcp);
    if (s == nullptr) {
      return;
    }
  }
  if ((ev & EPOLLOUT) != 0 && s->want_writable && !s->error) {
    s->want_writable = false;
    handler_->on_writable(id);
    s = find(id, Kind::tcp);
    if (s == nullptr) {
      return;
    }
  }
  // Linux tcp_poll: EPOLLHUP when both directions are shut down (or CLOSE).
  if ((ev & EPOLLHUP) != 0 && s->fin_sent && !s->error && !s->closed_delivered) {
    s->closed_delivered = true;
    handler_->on_closed(id);
  }
}

void KernelTransport::on_pending() {
  std::uint64_t v = 0;
  [[maybe_unused]] const ssize_t n = ::read(event_fd_, &v, sizeof v);
  std::deque<Pending> batch;
  batch.swap(pending_);
  for (const Pending& p : batch) {
    if (handler_ == nullptr || find(p.id, Kind::tcp) == nullptr) {
      continue;  // closed in the meantime
    }
    if (p.type == EvType::connected) {
      handler_->on_connected(p.id);
    } else {
      handler_->on_error(p.id, p.err);
    }
  }
}

// --- Timers.

TimerToken KernelTransport::add_timer_(Time deadline, Duration period, std::function<void()> cb) {
  const TimerToken t = next_timer_++;
  const std::uint64_t seq = next_timer_seq_++;
  timers_.emplace(t, Timer{deadline, seq, period, std::make_shared<std::function<void()>>(std::move(cb))});
  timer_order_.emplace(std::pair{deadline, seq}, t);
  return t;
}

TimerToken KernelTransport::add_timer(Duration period, std::function<void()> cb) {
  UTCP_CHECK(period > Duration::zero());
  return add_timer_(now() + period, period, std::move(cb));
}

TimerToken KernelTransport::add_oneshot(Duration delay, std::function<void()> cb) {
  return add_timer_(now() + std::max(delay, Duration::zero()), Duration::zero(), std::move(cb));
}

void KernelTransport::cancel_timer(TimerToken t) {
  const auto it = timers_.find(t);
  if (it == timers_.end()) {
    return;
  }
  timer_order_.erase(std::pair{it->second.deadline, it->second.seq});
  timers_.erase(it);
}

Time KernelTransport::next_deadline() const {
  return timer_order_.empty() ? Time::never() : timer_order_.begin()->first.first;
}

void KernelTransport::on_deadline(Time now) {
  // Timers armed during this call wait for the next iteration.
  const std::uint64_t seq_limit = next_timer_seq_;
  while (!timer_order_.empty() && !stopped_) {
    const auto first = timer_order_.begin();
    if (first->first.first > now || first->first.second >= seq_limit) {
      break;
    }
    const TimerToken t = first->second;
    timer_order_.erase(first);
    Timer& tm = timers_.at(t);
    const std::shared_ptr<std::function<void()>> cb = tm.cb;
    if (tm.period > Duration::zero()) {
      // Keep the phase; after a long stall, skip the missed periods.
      Time next = tm.deadline + tm.period;
      if (next <= now) {
        next = now + tm.period;
      }
      tm.deadline = next;
      tm.seq = next_timer_seq_++;
      timer_order_.emplace(std::pair{tm.deadline, tm.seq}, t);
    } else {
      timers_.erase(t);
    }
    (*cb)();
  }
}

// --- Running.

void KernelTransport::run(Handler& h) {
  handler_ = &h;
  stopped_ = false;
  while (!stopped_ && !loop_.stopped()) {
    loop_.run_once();
  }
  handler_ = nullptr;
}

void KernelTransport::stop() { stopped_ = true; }

// --- Backend selection.

void add_backend_options(CliParser& p) {
  p.option("backend", "kernel|utcp", "transport: Linux sockets or the userspace stack", "utcp")
      .option("profile", "rfc|linux", "TCP profile of the utcp backend", "linux")
      .option("tun", "IFNAME", "utcp backend: TUN interface", "utcp0")
      .option("addr", "IP", "utcp backend: the stack's address", "198.18.0.2")
      .option("mtu", "N", "utcp backend: the TUN interface's MTU", "1500")
      .option("pcap", "FILE", "utcp backend: record the datagrams that cross the TUN")
      .option("stats", "FILE",
              "utcp backend: write the stack's counters (StackStats) and the device counters "
              "as one JSON line to FILE when the program ends")
      .option("spin-us", "US", "utcp backend: busy-poll the last US microseconds before a deadline",
              "0")
      .option("seed", "N", "utcp backend: stack seed (default: getrandom)")
      .option("set", "FIELD=VALUE",
              "utcp backend: set a TcpConfig field of the profile (repeatable; e.g. "
              "snd_buf_max=64Mi, test_fixed_pacing_rate=50Mbit)")
      .option("trace", "FILE",
              "utcp backend: keep the stack's trace events in memory and write them to FILE as "
              "JSON lines when the program ends")
      .option("trace-kinds", "LIST",
              "utcp backend: trace kinds, comma-separated (state, tx, rx, ack, rtt, rto, cwnd, "
              "recovery, timer, icmp, drop; rexmit = tx events of retransmissions only)",
              std::string(default_trace_kinds));
}

namespace {

// --trace-kinds: the trace mask and whether tx events are limited to
// retransmissions.
std::expected<std::pair<std::uint32_t, bool>, std::string> parse_trace_kinds(std::string_view list) {
  std::uint32_t mask = 0;
  bool rexmit = false, all_tx = false;
  while (!list.empty()) {
    const auto comma = list.find(',');
    const std::string_view name = list.substr(0, comma);
    list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
    if (name == "rexmit") {
      rexmit = true;
      mask |= trace_bit(TraceKind::tx);
      continue;
    }
    bool found = false;
    for (int k = 0; k < trace_kind_count; ++k) {
      if (to_string(static_cast<TraceKind>(k)) == name) {
        mask |= trace_bit(static_cast<TraceKind>(k));
        all_tx = all_tx || static_cast<TraceKind>(k) == TraceKind::tx;
        found = true;
      }
    }
    if (!found) {
      return std::unexpected("--trace-kinds: unknown kind '" + std::string(name) + "'");
    }
  }
  if (mask == 0) {
    return std::unexpected(std::string("--trace-kinds: no kind given"));
  }
  return std::pair{mask, rexmit && !all_tx};
}

}  // namespace

std::expected<BackendSelection, std::string> parse_backend_options(const CliArgs& a) {
  BackendSelection b;
  const std::string backend = a.get("backend").value_or("utcp");
  if (backend == "kernel") {
    b.kernel = true;
  } else if (backend != "utcp") {
    return std::unexpected("--backend must be kernel or utcp, not '" + backend + "'");
  }
  UtcpTransportOptions& u = b.utcp;
  const std::string profile = a.get("profile").value_or("linux");
  if (profile == "rfc") {
    u.stack.tcp = tcp_config(ProfileId::rfc);
  } else if (profile == "linux") {
    u.stack.tcp = tcp_config(ProfileId::linux_compat);
  } else {
    return std::unexpected("--profile must be rfc or linux, not '" + profile + "'");
  }
  u.tun = a.get("tun").value_or("utcp0");
  const auto addr = parse_ipv4(a.get("addr").value_or("198.18.0.2"));
  if (!addr) {
    return std::unexpected("--addr: " + addr.error());
  }
  u.stack.local_addr = *addr;
  const auto mtu = parse_u64(a.get("mtu").value_or("1500"));
  if (!mtu || *mtu < 576 || *mtu > 65535) {
    return std::unexpected(std::string("--mtu must be 576..65535"));
  }
  u.stack.mtu = static_cast<std::uint16_t>(*mtu);
  u.pcap_file = a.get("pcap").value_or("");
  u.stats_file = a.get("stats").value_or("");
  const auto spin = parse_u64(a.get("spin-us").value_or("0"));
  if (!spin || *spin > 1'000'000) {
    return std::unexpected(std::string("--spin-us must be 0..1000000"));
  }
  u.spin_us = static_cast<std::uint32_t>(*spin);
  if (const auto seed = a.get("seed")) {
    const auto v = parse_u64(*seed);
    if (!v) {
      return std::unexpected("--seed: " + v.error());
    }
    u.stack.seed = Seed::from_u64(*v);
    u.seed_from_getrandom = false;
  }
  for (const std::string& s : a.all("set")) {
    const auto eq = s.find('=');
    if (eq == std::string::npos || eq == 0) {
      return std::unexpected("--set: FIELD=VALUE, not '" + s + "'");
    }
    const std::string name = s.substr(0, eq), value = s.substr(eq + 1);
    if (auto r = set_config_field(u.stack.tcp, name, value); !r) {
      return std::unexpected("--set " + s + ": " + r.error());
    }
    b.sets.emplace_back(name, value);
  }
  if (const auto bad = check_tcp_config(u.stack.tcp)) {
    return std::unexpected("--set: " + *bad);
  }
  if (const auto t = a.get("trace")) {
    if (t->empty()) {
      return std::unexpected(std::string("--trace: a file name"));
    }
    const auto kinds = parse_trace_kinds(a.get("trace-kinds").value_or(std::string(default_trace_kinds)));
    if (!kinds) {
      return std::unexpected(kinds.error());
    }
    b.trace_file = *t;
    u.stack.trace_mask = kinds->first;
    b.trace_rexmit_only = kinds->second;
  } else if (a.given("trace-kinds")) {
    return std::unexpected(std::string("--trace-kinds needs --trace"));
  }
  if (b.kernel) {
    for (const char* name : {"set", "trace"}) {
      if (a.given(name)) {
        return std::unexpected(std::string("--") + name + " is for the utcp backend");
      }
    }
  }
  return b;
}

std::expected<std::unique_ptr<Transport>, std::string> make_transport(const BackendSelection& b) {
  if (b.kernel) {
    return std::make_unique<KernelTransport>();
  }
  auto t = UtcpTransport::open(b.utcp);
  if (!t) {
    return std::unexpected(std::move(t.error()));
  }
  if (!b.trace_file.empty()) {
    (*t)->enable_trace(b.trace_file, b.trace_rexmit_only);
  }
  return std::unique_ptr<Transport>(std::move(*t));
}

}  // namespace utcp::app
