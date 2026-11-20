// Adapter for the IPv4, nonblocking subset used by the accompanying tests.
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <packetdrill.h>
#include <sys/eventfd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "utcp/stack.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Endpoint;
using utcp::Handle;
using utcp::Time;

constexpr auto outbound_wait = 500ms;

[[noreturn]] void fail(const char* message) {
  std::fprintf(stderr, "utcp-packetdrill: %s\n", message);
  std::exit(EXIT_FAILURE);
}

int failure(int error) {
  errno = error;
  return -1;
}

struct Socket {
  bool nonblocking = false;
  std::optional<Endpoint> bound;
  std::optional<Handle> handle;
};

struct Datagram {
  Time sent;
  std::vector<std::byte> bytes;
};

utcp::StackConfig make_config(utcp::Ipv4Addr addr) {
  utcp::StackConfig config{};
  config.local_addr = addr;
  config.seed = utcp::Seed::from_u64(1);
  config.tcp = utcp::tcp_config(utcp::ProfileId::rfc);
  // The handshake tests exercise only MSS negotiation (RFC 9293 §3.7.1).
  config.tcp.sack = false;
  config.tcp.timestamps = false;
  config.tcp.window_scaling = false;
  config.max_connections = 64;
  config.pool_buffers = 128;
  config.tx_queue_packets = 64;
  config.assert_time_monotonic = true;
  config.trace_mask = (1u << static_cast<unsigned>(utcp::TraceKind::state)) |
                      (1u << static_cast<unsigned>(utcp::TraceKind::timer));
  return config;
}

long long to_usecs(Time t) {
  return std::chrono::duration_cast<std::chrono::microseconds>(utcp::Duration{t.ns}).count();
}

class Adapter final : public utcp::TraceSink {
 public:
  explicit Adapter(utcp::Ipv4Addr addr) : stack(make_config(addr)) { stack.set_trace_sink(this); }

  void on_event(const utcp::TraceEvent& event) override {
    if (event.kind == utcp::TraceKind::state) {
      if (event.state == utcp::TcpState::syn_received) {
        peers.emplace(event.conn_id, event.tuple.remote);
      } else if (event.state == utcp::TcpState::closed) {
        peers.erase(event.conn_id);
      }
      const auto state = utcp::to_string(event.state);
      std::fprintf(stderr, "utcp-packetdrill state=%.*s conn=%u virtual_us=%lld\n",
                   static_cast<int>(state.size()), state.data(), event.conn_id, to_usecs(event.t));
    } else if (event.timer_op == utcp::TimerOp::fired) {
      const auto timer = utcp::to_string(event.timer);
      std::fprintf(stderr, "utcp-packetdrill timer=%.*s conn=%u virtual_us=%lld\n",
                   static_cast<int>(timer.size()), timer.data(), event.conn_id, to_usecs(event.t));
    }
  }

  Socket* find(int fd) {
    const auto entry = sockets.find(fd);
    if (entry == sockets.end()) {
      errno = EBADF;
      return nullptr;
    }
    return &entry->second;
  }

  int open(Socket socket) {
    // Upstream closes any overlooked descriptors with plain close(2).
    const int fd = eventfd(0, EFD_CLOEXEC);
    if (fd >= 0) {
      sockets.emplace(fd, socket);
    }
    return fd;
  }

  void drain() {
    while (auto tx = stack.pop_transmit()) {
      if (outbound.size() >= 64) {
        fail("outbound queue exceeded 64 packets");
      }
      if (tx->gso_size || tx->csum_partial) {
        fail("packetdrill requires complete datagrams");
      }
      const auto bytes = tx->buf.bytes();
      outbound.push_back({stack.now(), {bytes.begin(), bytes.end()}});
    }
    while (stack.poll_event()) {
    }
    stack.debug_check();
  }

  void advance_to(Time target, bool stop_on_packet = false) {
    unsigned steps = 0;
    for (auto next = stack.next_deadline(); next <= target; next = stack.next_deadline()) {
      if (++steps > 128) {
        fail("Stack did not clear deadlines within 128 steps");
      }
      stack.advance(next);
      drain();
      if (stop_on_packet && !outbound.empty()) {
        return;
      }
    }
    stack.advance(target);
    drain();
  }

  utcp::Stack stack;
  std::map<int, Socket> sockets;
  std::map<std::uint32_t, Endpoint> peers;
  std::deque<Datagram> outbound;
  unsigned clock_reads = 0;
  unsigned sleeps = 0;
  unsigned packets_returned = 0;
};

Adapter& adapter(void* userdata) { return *static_cast<Adapter*>(userdata); }

std::optional<Endpoint> ipv4_endpoint(const sockaddr* address, socklen_t length) {
  if (!address || length < sizeof(sockaddr_in)) {
    errno = EINVAL;
    return std::nullopt;
  }
  sockaddr_in ipv4{};
  std::memcpy(&ipv4, address, sizeof(ipv4));
  if (ipv4.sin_family != AF_INET) {
    errno = EAFNOSUPPORT;
    return std::nullopt;
  }
  return Endpoint{{ntohl(ipv4.sin_addr.s_addr)}, ntohs(ipv4.sin_port)};
}

std::optional<Handle> nonblocking_handle(Adapter& a, int fd) {
  const Socket* socket = a.find(fd);
  if (!socket) {
    return std::nullopt;
  }
  if (!socket->nonblocking) {
    errno = EOPNOTSUPP;
    return std::nullopt;
  }
  if (!socket->handle) {
    errno = ENOTCONN;
  }
  return socket->handle;
}

int pd_socket(void* userdata, int domain, int type, int protocol) {
  if (domain != AF_INET || (type & ~SOCK_NONBLOCK) != SOCK_STREAM || protocol != IPPROTO_TCP) {
    return failure(EOPNOTSUPP);
  }
  Socket socket;
  socket.nonblocking = (type & SOCK_NONBLOCK) != 0;
  return adapter(userdata).open(socket);
}

int pd_bind(void* userdata, int fd, const sockaddr* address, socklen_t length) {
  Adapter& a = adapter(userdata);
  Socket* socket = a.find(fd);
  if (!socket) {
    return -1;
  }
  if (socket->bound || socket->handle) {
    return failure(EINVAL);
  }
  const auto local = ipv4_endpoint(address, length);
  if (!local) {
    return -1;
  }
  if (local->addr.v != INADDR_ANY && local->addr != a.stack.config().local_addr) {
    return failure(EADDRNOTAVAIL);
  }
  socket->bound = local;
  return 0;
}

int pd_listen(void* userdata, int fd, int backlog) {
  Adapter& a = adapter(userdata);
  Socket* socket = a.find(fd);
  if (!socket) {
    return -1;
  }
  if (!socket->bound || socket->handle || backlog <= 0) {
    return failure(EINVAL);
  }
  const auto handle = a.stack.tcp_listen(*socket->bound, static_cast<std::uint32_t>(backlog));
  if (!handle) {
    return failure(utcp::to_errno(handle.error()));
  }
  socket->handle = *handle;
  a.drain();
  return 0;
}

int pd_accept(void* userdata, int fd, sockaddr* address, socklen_t* length) {
  Adapter& a = adapter(userdata);
  const auto listener = nonblocking_handle(a, fd);
  if (!listener) {
    return -1;
  }
  if (!address || !length || *length < sizeof(sockaddr_in)) {
    return failure(EINVAL);
  }
  const auto accepted = a.stack.tcp_accept(*listener);
  if (!accepted) {
    return failure(utcp::to_errno(accepted.error()));
  }
  const auto info = a.stack.tcp_info(*accepted);
  if (!info || !a.peers.contains(info->conn_id)) {
    fail("missing Stack trace tuple for accepted connection");
  }
  const auto peer = a.peers.at(info->conn_id);
  a.peers.erase(info->conn_id);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(peer.addr.v);
  addr.sin_port = htons(peer.port);
  std::memcpy(address, &addr, sizeof(addr));
  *length = sizeof(addr);
  Socket child;
  child.handle = *accepted;
  const int child_fd = a.open(child);
  if (child_fd < 0) {
    const int saved_errno = errno;
    if (!a.stack.tcp_close(*accepted)) {
      fail("could not close accepted handle after eventfd failed");
    }
    a.drain();
    return failure(saved_errno);
  }
  a.drain();
  return child_fd;
}

int pd_connect(void* userdata, int fd, const sockaddr* address, socklen_t length) {
  Adapter& a = adapter(userdata);
  Socket* socket = a.find(fd);
  if (!socket) {
    return -1;
  }
  if (!socket->nonblocking || socket->handle) {
    return failure(EOPNOTSUPP);
  }
  const auto peer = ipv4_endpoint(address, length);
  if (!peer) {
    return -1;
  }
  const auto local_port = socket->bound ? socket->bound->port : std::uint16_t{0};
  const auto handle = a.stack.tcp_connect(*peer, {}, local_port);
  if (!handle) {
    return failure(utcp::to_errno(handle.error()));
  }
  socket->handle = *handle;
  a.drain();
  return failure(EINPROGRESS);
}

ssize_t pd_read(void* userdata, int fd, void* buffer, size_t count) {
  Adapter& a = adapter(userdata);
  const auto handle = nonblocking_handle(a, fd);
  if (!handle) {
    return -1;
  }
  if (!count) {
    return 0;
  }
  if (!buffer) {
    return failure(EFAULT);
  }
  const std::span out{static_cast<std::byte*>(buffer), count};
  const auto result = a.stack.tcp_recv(*handle, out);
  if (!result) {
    return failure(utcp::to_errno(result.error()));
  }
  const auto received = out.first(*result);
  const auto nonzero = std::count_if(received.begin(), received.end(),
                                     [](std::byte byte) { return byte != std::byte{}; });
  std::fprintf(stderr, "utcp-packetdrill read=%zu nonzero=%td\n", *result, nonzero);
  a.drain();
  return static_cast<ssize_t>(*result);
}

ssize_t pd_write(void* userdata, int fd, const void* buffer, size_t count) {
  Adapter& a = adapter(userdata);
  const auto handle = nonblocking_handle(a, fd);
  if (!handle) {
    return -1;
  }
  if (!count) {
    return 0;
  }
  if (!buffer) {
    return failure(EFAULT);
  }
  const auto result = a.stack.tcp_send(*handle, {static_cast<const std::byte*>(buffer), count});
  if (!result) {
    return failure(utcp::to_errno(result.error()));
  }
  std::fprintf(stderr, "utcp-packetdrill write=%zu\n", *result);
  a.drain();
  return static_cast<ssize_t>(*result);
}

int pd_fcntl(void* userdata, int fd, int command, ...) {
  Socket* socket = adapter(userdata).find(fd);
  if (!socket) {
    return -1;
  }
  if (command == F_GETFL) {
    return O_RDWR | (socket->nonblocking ? O_NONBLOCK : 0);
  }
  if (command != F_SETFL) {
    return failure(EOPNOTSUPP);
  }
  va_list args;
  va_start(args, command);
  const int flags = va_arg(args, int);
  va_end(args);
  if ((flags & ~O_NONBLOCK) != 0) {
    return failure(EOPNOTSUPP);
  }
  socket->nonblocking = (flags & O_NONBLOCK) != 0;
  return 0;
}

int pd_close(void* userdata, int fd) {
  Adapter& a = adapter(userdata);
  const Socket* socket = a.find(fd);
  if (!socket) {
    return -1;
  }
  if (socket->handle) {
    const auto closed = a.stack.tcp_close(*socket->handle);
    if (!closed) {
      return failure(utcp::to_errno(closed.error()));
    }
    a.drain();
  }
  a.sockets.erase(fd);
  return ::close(fd);
}

int pd_getsockopt(void* userdata, int fd, int level, int option, void* value, socklen_t* length) {
  Adapter& a = adapter(userdata);
  const Socket* socket = a.find(fd);
  if (!socket) {
    return -1;
  }
  if (level != SOL_SOCKET || option != SO_ERROR) {
    return failure(ENOPROTOOPT);
  }
  if (!value || !length || *length < sizeof(int)) {
    return failure(EINVAL);
  }
  const auto error = socket->handle ? a.stack.take_error(*socket->handle) : std::nullopt;
  const int result = error ? utcp::to_errno(*error) : 0;
  std::memcpy(value, &result, sizeof(result));
  *length = sizeof(result);
  return 0;
}

int inject(void* userdata, const void* buffer, size_t count) {
  Adapter& a = adapter(userdata);
  a.stack.receive(a.stack.now(), {static_cast<const std::byte*>(buffer), count});
  a.drain();
  return 0;
}

int sniff(void* userdata, void* buffer, size_t* count, long long* received_at) {
  Adapter& a = adapter(userdata);
  if (a.outbound.empty()) {
    a.advance_to(a.stack.now() + outbound_wait, true);
  }
  if (a.outbound.empty() || a.outbound.front().bytes.size() > *count) {
    // At the pinned revision a -1 status makes so_testing.c retry forever.
    // A zero-length read makes the checked packet expectation fail promptly.
    std::fputs("utcp-packetdrill: no fitting datagram within transmit wait\n", stderr);
    *count = 0;
    *received_at = to_usecs(a.stack.now());
    return 0;
  }
  const Datagram& datagram = a.outbound.front();
  *count = datagram.bytes.size();
  *received_at = to_usecs(datagram.sent);
  std::memcpy(buffer, datagram.bytes.data(), *count);
  a.outbound.pop_front();
  ++a.packets_returned;
  return 0;
}

int sleep_us(void* userdata, useconds_t usecs) {
  Adapter& a = adapter(userdata);
  ++a.sleeps;
  a.advance_to(a.stack.now() + std::chrono::microseconds(usecs));
  return 0;
}

int clock_us(void* userdata, timeval* tv, struct timezone*) {
  Adapter& a = adapter(userdata);
  ++a.clock_reads;
  // The interpreter busy-spins for its last 20 us, so reads must advance time.
  a.advance_to(a.stack.now() + 1us);
  const auto now = to_usecs(a.stack.now());
  tv->tv_sec = now / 1'000'000;
  tv->tv_usec = now % 1'000'000;
  return 0;
}

template <class Result, class... Args>
Result unsupported(void*, Args...) {
  return failure(ENOSYS);
}

int unsupported_ioctl(void*, int, unsigned long, ...) { return failure(ENOSYS); }

void destroy(void* userdata) {
  const Adapter& a = adapter(userdata);
  const auto usage = a.stack.debug_usage();
  std::fprintf(stderr,
               "utcp-packetdrill rx=%llu tx=%u sleeps=%u clock_reads=%u regressions=%llu "
               "fds=%zu tcp_slots=%u time_wait=%u queued=%zu\n",
               static_cast<unsigned long long>(a.stack.stats().IpInDelivers), a.packets_returned,
               a.sleeps, a.clock_reads,
               static_cast<unsigned long long>(a.stack.stats().time_regressions), a.sockets.size(),
               usage.tcp_slots, usage.time_wait_entries, a.outbound.size());
  delete &a;
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void packetdrill_interface_init(
    const char* argument, packetdrill_interface* interface) {
  const auto local =
      utcp::ipv4_from_string(argument ? std::string_view{argument} : std::string_view{});
  if (!local || local->v == INADDR_ANY) {
    fail("--so_flags must contain the configured local IPv4 address");
  }
  *interface = {
      .userdata = new Adapter(*local),
      .free = destroy,
      .socket = pd_socket,
      .bind = pd_bind,
      .listen = pd_listen,
      .accept = pd_accept,
      .connect = pd_connect,
      .read = pd_read,
      .readv = unsupported,
      .recv = unsupported,
      .recvfrom = unsupported,
      .recvmsg = unsupported,
      .write = pd_write,
      .writev = unsupported,
      .send = unsupported,
      .sendto = unsupported,
      .sendmsg = unsupported,
      .fcntl = pd_fcntl,
      .ioctl = unsupported_ioctl,
      .close = pd_close,
      .shutdown = unsupported,
      .getsockopt = pd_getsockopt,
      .setsockopt = unsupported,
      .poll = unsupported,
      .netdev_send = inject,
      .netdev_receive = sniff,
      .usleep = sleep_us,
      .gettimeofday = clock_us,
      .epoll_create = unsupported,
      .epoll_ctl = unsupported,
      .epoll_wait = unsupported,
      .pipe = unsupported,
      .splice = unsupported,
  };
  std::fputs("utcp-packetdrill initialized\n", stderr);
}
