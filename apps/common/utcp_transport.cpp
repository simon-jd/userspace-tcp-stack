// UtcpTransport: Stack + TUN + EventLoop (DESIGN §8, §9). See
// common/utcp_transport.hpp for the iteration and the event mapping.
#include "common/utcp_transport.hpp"

#include <fcntl.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <format>
#include <utility>

#include "utcp/check.hpp"
#include "utcp/pcap.hpp"
#include "utcp/tun_device.hpp"

namespace utcp::app {
namespace {

constexpr std::size_t max_datagram = 65535;   // largest IPv4 datagram
constexpr int rx_batch = 64;                  // datagrams per readable callback (§8.2)
constexpr std::uint32_t pcap_snaplen = 65535;
constexpr std::size_t pcap_buffer = 1 << 20;

std::string errno_text(std::string_view what, int err) {
  return std::format("{}: {}", what, std::strerror(err));
}

EventLoopOptions loop_options(const UtcpTransportOptions& o) {
  EventLoopOptions e;
  e.spin_us = o.spin_us;
  return e;
}

Time realtime_now() {
  timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);
  return Time{static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec};
}

std::expected<int, std::string> interface_mtu(const std::string& name) {
  const int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) {
    return std::unexpected(errno_text("socket", errno));
  }
  ifreq ifr{};
  std::memcpy(ifr.ifr_name, name.data(), std::min(name.size(), sizeof ifr.ifr_name - 1));
  const int rc = ::ioctl(s, SIOCGIFMTU, &ifr);
  const int err = errno;
  ::close(s);
  if (rc < 0) {
    return std::unexpected(errno_text("SIOCGIFMTU " + name, err));
  }
  return ifr.ifr_mtu;
}

}  // namespace

// --pcap FILE: LINKTYPE_RAW, nanosecond timestamps (utcp/pcap.hpp).
struct UtcpTransport::PcapWriter {
  std::FILE* f = nullptr;
  std::unique_ptr<char[]> buf;
  bool dirty = false;  // records written to the buffer since the last flush

  PcapWriter() = default;
  PcapWriter(const PcapWriter&) = delete;
  PcapWriter& operator=(const PcapWriter&) = delete;
  ~PcapWriter() { close(); }

  std::expected<void, std::string> open(const std::string& path) {
    f = std::fopen(path.c_str(), "wb");
    if (f == nullptr) {
      return std::unexpected(errno_text("cannot open pcap file " + path, errno));
    }
    buf = std::make_unique<char[]>(pcap_buffer);
    std::setvbuf(f, buf.get(), _IOFBF, pcap_buffer);
    std::array<std::byte, pcap_file_header_size> hdr{};
    write_pcap_file_header(hdr, pcap_snaplen);
    // The file header goes out at once: a run that ends without a flush
    // (abort, SIGKILL) still leaves a readable file.
    if (std::fwrite(hdr.data(), 1, hdr.size(), f) != hdr.size() || std::fflush(f) != 0) {
      return std::unexpected(errno_text("cannot write pcap file " + path, errno));
    }
    return {};
  }
  bool write(std::span<const std::byte> datagram) {
    std::array<std::byte, pcap_record_header_size> hdr{};
    const auto len = static_cast<std::uint32_t>(datagram.size());
    write_pcap_record_header(hdr, realtime_now(), len, pcap_snaplen);
    const std::size_t cap = std::min<std::size_t>(len, pcap_snaplen);
    dirty = true;
    return std::fwrite(hdr.data(), 1, hdr.size(), f) == hdr.size() &&
           std::fwrite(datagram.data(), 1, cap, f) == cap;
  }
  // Writes the buffered records to the file; false if that failed.
  bool flush() {
    if (f == nullptr || !dirty) {
      return true;
    }
    dirty = false;
    return std::fflush(f) == 0;
  }
  void close() {
    if (f != nullptr) {
      std::fclose(f);
      f = nullptr;
    }
  }
};

// --- Construction.

std::expected<std::unique_ptr<UtcpTransport>, std::string> UtcpTransport::open(
    const UtcpTransportOptions& opts) {
  // TUNSETIFF on a name that does not exist creates a new interface, down and
  // without an address, that goes away with the fd: it never comes up. The
  // testbed creates and configures the interface (§8.1).
  if (opts.tun.empty() || opts.tun.size() >= IFNAMSIZ || opts.tun == "." || opts.tun == ".." ||
      opts.tun.find('/') != std::string::npos) {
    return std::unexpected(std::format("invalid TUN interface name \"{}\"", opts.tun));
  }
  if (const std::string sys = "/sys/class/net/" + opts.tun; ::access(sys.c_str(), F_OK) != 0) {
    if (errno == ENOENT) {
      return std::unexpected(std::format(
          "interface {} does not exist (testbed/m1/up.sh creates it)", opts.tun));
    }
    return std::unexpected(errno_text("cannot check " + sys, errno));
  }
  auto tun = TunDevice::open(opts.tun, /*nonblocking=*/true);
  if (!tun) {
    return std::unexpected(
        std::format("cannot open TUN interface {}: {}", opts.tun, tun.error().message()));
  }
  const auto mtu = interface_mtu(tun->name());
  if (!mtu) {
    return std::unexpected(mtu.error());
  }
  // §8.1: StackConfig::mtu must equal the TUN MTU.
  if (*mtu != opts.stack.mtu) {
    return std::unexpected(std::format("stack MTU {} differs from the MTU {} of {}",
                                       opts.stack.mtu, *mtu, tun->name()));
  }
  // Until the kernel has re-enabled the interface's qdisc after the attach,
  // it drops what it sends to the stack (TunDevice::wait_running).
  if (!tun->wait_running(std::chrono::seconds{1})) {
    return std::unexpected(std::format("interface {} is not running (operstate \"{}\"); "
                                       "is it up?",
                                       tun->name(), tun->operstate()));
  }
  return attach(tun->release(), opts);
}

std::expected<std::unique_ptr<UtcpTransport>, std::string> UtcpTransport::attach(
    int fd, const UtcpTransportOptions& opts) {
  if (fd < 0) {
    return std::unexpected(std::string("attach: invalid file descriptor"));
  }
  const auto fail = [fd](std::string msg) {
    ::close(fd);
    return std::unexpected(std::move(msg));
  };
  const int fl = ::fcntl(fd, F_GETFL);
  if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
    return fail(errno_text("fcntl(O_NONBLOCK)", errno));
  }
  if (opts.stack.local_addr.v == 0) {
    return fail("the stack address (StackConfig::local_addr) is not set");
  }
  UtcpTransportOptions o = opts;
  if (o.seed_from_getrandom) {
    // §3.8: the backend seeds the stack from getrandom(2).
    std::array<std::byte, sizeof o.stack.seed.w> bytes{};
    std::size_t got = 0;
    while (got < bytes.size()) {
      const ssize_t n = ::getrandom(bytes.data() + got, bytes.size() - got, 0);
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        return fail(errno_text("getrandom", errno));
      }
      got += static_cast<std::size_t>(n);
    }
    std::memcpy(o.stack.seed.w.data(), bytes.data(), bytes.size());
  }
  std::unique_ptr<UtcpTransport> t(new UtcpTransport(fd, o));  // owns fd from here
  if (!o.pcap_file.empty()) {
    t->pcap_ = std::make_unique<PcapWriter>();
    if (auto r = t->pcap_->open(o.pcap_file); !r) {
      return std::unexpected(r.error());
    }
  }
  return t;
}

UtcpTransport::UtcpTransport(int fd, const UtcpTransportOptions& opts)
    : opt_(opts), fd_(fd), loop_(loop_options(opts)), stack_(opts.stack), rxbuf_(max_datagram) {
  loop_.watch(fd_, EPOLLIN, [this](std::uint32_t ev) { on_device(ev); });
  watched_ = true;
  // §3.4: next_deadline() == now() means that blocked connections can
  // resume. That is work to do at once, not a timer the loop waited for, so
  // it reaches the loop as pending work and adds no lateness sample (§8.3);
  // only timer deadlines do. (A stack timer that falls due while the stack
  // stays resumable fires in a pending iteration, also without a sample:
  // next_deadline() hides it then.)
  loop_.set_deadline_source([this] {
    const Time s = stack_.next_deadline();
    return std::min(s <= stack_.now() ? Time::never() : s, timer_deadline());
  });
  loop_.set_pending_source([this] { return stack_.next_deadline() <= stack_.now(); });
  loop_.set_deadline_handler([this](Time now) {
    stack_.advance(now);
    fire_timers(now);
  });
  stack_.advance(mono_now());
}

UtcpTransport::~UtcpTransport() {
  pending_tx_.reset();  // every TxPacket goes back before the Stack (stack.hpp)
  if (pcap_) {
    pcap_->close();
  }
  if (watched_) {
    loop_.unwatch(fd_);
  }
  ::close(fd_);
}

// --- Device.

void UtcpTransport::on_device(std::uint32_t events) {
  if ((events & EPOLLOUT) != 0) {
    drain_tx();
  }
  if ((events & EPOLLIN) != 0) {
    read_batch();
  }
  // TUN: EPOLLERR once the interface is gone; socketpair: EPOLLHUP when the
  // peer closed. Level-triggered, so stop watching.
  if (watched_ && (events & (EPOLLERR | EPOLLHUP)) != 0 && (events & EPOLLIN) == 0) {
    device_failed();
  }
}

void UtcpTransport::device_failed() {
  dev_.device_failed = true;
  stop_requested_ = true;
  if (watched_) {
    loop_.unwatch(fd_);
    watched_ = false;
    watching_out_ = false;
  }
}

void UtcpTransport::read_batch() {
  ++dev_.rx_batches;
  // §8.2: the iteration starts with advance(clock()): timers due before these
  // datagrams arrived fire first.
  stack_.advance(mono_now());
  int n_read = 0;
  while (n_read < rx_batch) {
    const ssize_t n = ::read(fd_, rxbuf_.data(), rxbuf_.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        ++dev_.rx_errors;
        // A TUN fd whose interface was deleted reads EBADFD forever.
        if (errno == EBADFD || errno == EIO) {
          device_failed();
        }
      }
      return;
    }
    if (n == 0) {
      // TUN never reads 0; a SOCK_SEQPACKET socketpair does once the peer closed.
      device_failed();
      return;
    }
    ++n_read;
    const std::span<const std::byte> d(rxbuf_.data(), static_cast<std::size_t>(n));
    record_pcap(d);
    ++dev_.rx_datagrams;
    dev_.rx_bytes += d.size();
    stack_.receive(mono_now(), d);  // per packet, for RTT precision (§8.2)
  }
  ++dev_.rx_batch_limit;  // more may be waiting: epoll is level-triggered
}

void UtcpTransport::drain_tx() {
  for (;;) {
    if (!pending_tx_) {
      pending_tx_ = stack_.pop_transmit();
      if (!pending_tx_) {
        break;
      }
    }
    const std::span<const std::byte> b = std::as_const(pending_tx_->buf).bytes();
    const ssize_t n = ::write(fd_, b.data(), b.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // §8.2: keep the packet and wait for EPOLLOUT.
        ++dev_.tx_eagain;
        if (watched_ && !watching_out_) {
          loop_.modify(fd_, EPOLLIN | EPOLLOUT);
          watching_out_ = true;
        }
        return;
      }
      ++dev_.tx_errors;  // EIO (interface down), EINVAL, ...: dropped, as a full link would
      dev_.last_tx_errno = errno;
    } else {
      record_pcap(b);
      ++dev_.tx_datagrams;
      dev_.tx_bytes += b.size();
    }
    pending_tx_.reset();
  }
  if (watching_out_) {
    loop_.modify(fd_, EPOLLIN);
    watching_out_ = false;
  }
}

void UtcpTransport::record_pcap(std::span<const std::byte> datagram) {
  if (!pcap_ || pcap_->f == nullptr) {
    return;
  }
  if (pcap_->write(datagram)) {
    ++dev_.pcap_records;
  } else {
    dev_.pcap_failed = true;
    pcap_->close();
  }
}

void UtcpTransport::flush_pcap() {
  if (pcap_ && !pcap_->flush()) {
    dev_.pcap_failed = true;
    pcap_->close();
  }
}

// --- Running.

void UtcpTransport::run(Handler& h) {
  UTCP_CHECK(!in_run_);  // not reentrant
  handler_ = &h;
  in_run_ = true;
  stop_requested_ = dev_.device_failed;
  stack_.advance(mono_now());
  for (;;) {
    deliver_events();
    drain_tx();  // host contract 1: drained before every wait
    // Everything recorded up to this wait reaches the file, so a run that
    // aborts (UTCP_CHECK, §13.2) or is killed keeps its capture; records of
    // one iteration are still written together.
    flush_pcap();
    if (stop_requested_ || loop_.stopped()) {
      break;
    }
    loop_.run_once();
  }
  in_run_ = false;
  handler_ = nullptr;
}

Time UtcpTransport::now() const { return mono_now(); }

void UtcpTransport::outside_run_enter() {
  if (!in_run_) {
    stack_.advance(mono_now());
  }
}

void UtcpTransport::outside_run_leave() {
  if (!in_run_) {
    drain_tx();
    flush_pcap();
  }
}

// A Transport call made outside run() advances the stack first; whatever it
// or the timers of that advance queued is written out when the call returns,
// on every path (an early error return included). Inside run() it does
// nothing: the iteration advances and drains.
class UtcpTransport::OutsideRun {
public:
  explicit OutsideRun(UtcpTransport& t) : t_(t) { t_.outside_run_enter(); }
  ~OutsideRun() { t_.outside_run_leave(); }
  OutsideRun(const OutsideRun&) = delete;
  OutsideRun& operator=(const OutsideRun&) = delete;

private:
  UtcpTransport& t_;
};

void UtcpTransport::deliver_events() {
  while (!stop_requested_) {
    const auto e = stack_.poll_event();
    if (!e) {
      return;
    }
    const auto it = by_handle_.find(e->h);
    if (it == by_handle_.end()) {
      continue;  // closed by the app, or a child not accepted yet (accept_all checks it)
    }
    deliver(it->second, e->events);
  }
}

// One socket's event mask, in the order of utcp_transport.hpp. The id is
// looked up again after every callback: the callback may have closed it.
void UtcpTransport::deliver(ConnId id, std::uint16_t ev) {
  Sock* s = find(id);
  if (s == nullptr) {
    return;
  }
  if (s->kind == Kind::udp) {
    if ((ev & ev_readable) != 0) {
      handler_->on_readable(id);
    }
    return;
  }
  if (s->kind == Kind::listener) {
    if ((ev & ev_acceptable) != 0) {
      accept_all(id);
    }
    return;
  }
  if ((ev & ev_connected) != 0) {
    handler_->on_connected(id);
    if ((s = find(id)) == nullptr) {
      return;
    }
  }
  if ((ev & (ev_readable | ev_read_closed)) != 0) {
    handler_->on_readable(id);
    if ((s = find(id)) == nullptr) {
      return;
    }
  }
  if ((ev & ev_writable) != 0) {
    handler_->on_writable(id);
    if ((s = find(id)) == nullptr) {
      return;
    }
  }
  if ((ev & ev_error) != 0) {
    if (const auto err = stack_.take_error(s->h)) {
      s->errored = true;
      handler_->on_error(id, *err);
      if ((s = find(id)) == nullptr) {
        return;
      }
    }
  }
  if ((ev & ev_closed) != 0 && !s->errored) {
    handler_->on_closed(id);
  }
}

void UtcpTransport::accept_all(ConnId listener) {
  for (;;) {
    const Sock* l = find(listener, Kind::listener);
    if (l == nullptr) {
      return;
    }
    const auto child = stack_.tcp_accept(l->h);
    if (!child) {
      return;  // would_block: the queue is empty
    }
    const ConnId cid = add_sock(Kind::tcp, *child);
    handler_->on_accept(listener, cid);
    // Events the child raised before it had an id were skipped by
    // deliver_events; report its level state once.
    Sock* c = find(cid);
    if (c == nullptr) {
      continue;
    }
    const Readiness r = stack_.tcp_readiness(c->h);
    if (r.readable || r.read_closed) {
      handler_->on_readable(cid);
      if ((c = find(cid)) == nullptr) {
        continue;
      }
    }
    if (r.has_error) {
      if (const auto err = stack_.take_error(c->h)) {
        c->errored = true;
        handler_->on_error(cid, *err);
      }
    }
  }
}

// --- Ids.

ConnId UtcpTransport::add_sock(Kind kind, Handle h) {
  const ConnId id = next_id_++;
  socks_.emplace(id, Sock{.kind = kind, .h = h});
  by_handle_[h] = id;
  return id;
}

UtcpTransport::Sock* UtcpTransport::find(ConnId id) {
  const auto it = socks_.find(id);
  return it == socks_.end() ? nullptr : &it->second;
}

UtcpTransport::Sock* UtcpTransport::find(ConnId id, Kind kind) {
  Sock* s = find(id);
  return s != nullptr && s->kind == kind ? s : nullptr;
}

// --- TCP.

std::expected<ConnId, Error> UtcpTransport::connect(Endpoint remote,
                                                    const TcpSocketOptions& opts) {
  const OutsideRun scope(*this);
  const auto h = stack_.tcp_connect(remote, opts);
  if (!h) {
    return std::unexpected(h.error());
  }
  return add_sock(Kind::tcp, *h);
}

std::expected<ConnId, Error> UtcpTransport::listen(Endpoint local, std::uint32_t backlog,
                                                   const TcpSocketOptions& opts) {
  const OutsideRun scope(*this);
  const auto h = stack_.tcp_listen(local, backlog, opts);
  if (!h) {
    return std::unexpected(h.error());
  }
  return add_sock(Kind::listener, *h);
}

std::expected<std::size_t, Error> UtcpTransport::send(ConnId id, std::span<const std::byte> data) {
  const Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  const OutsideRun scope(*this);
  return stack_.tcp_send(s->h, data);
}

std::expected<std::size_t, Error> UtcpTransport::recv(ConnId id, std::span<std::byte> out) {
  const Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  const OutsideRun scope(*this);
  return stack_.tcp_recv(s->h, out);  // may open the window: a window update
}

void UtcpTransport::shutdown_write(ConnId id) {
  const Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return;
  }
  const OutsideRun scope(*this);
  (void)stack_.tcp_shutdown(s->h, Shutdown::write);
}

void UtcpTransport::close(ConnId id) {
  const auto it = socks_.find(id);
  if (it == socks_.end()) {
    return;
  }
  const Sock s = it->second;
  socks_.erase(it);
  by_handle_.erase(s.h);
  const OutsideRun scope(*this);
  if (s.kind == Kind::udp) {
    (void)stack_.udp_close(s.h);
  } else {
    (void)stack_.tcp_close(s.h);  // FIN, or RST with unread data (§3.5)
  }
}

ConnSample UtcpTransport::sample(ConnId id) {
  const Sock* s = find(id, Kind::tcp);
  if (s == nullptr) {
    return ConnSample{};
  }
  return stack_.tcp_info(s->h).value_or(ConnSample{});
}

// --- UDP.

std::expected<ConnId, Error> UtcpTransport::udp_open(Endpoint local) {
  const OutsideRun scope(*this);
  const auto h = stack_.udp_open(local);
  if (!h) {
    return std::unexpected(h.error());
  }
  return add_sock(Kind::udp, *h);
}

std::expected<void, Error> UtcpTransport::send_to(ConnId id, Endpoint remote,
                                                  std::span<const std::byte> data) {
  const Sock* s = find(id, Kind::udp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  const OutsideRun scope(*this);
  auto r = stack_.udp_send_to(s->h, remote, data);
  if (!r && r.error() == Error::no_buffers) {
    // The transmit queue or pool is full (§3.6): write it out and retry once.
    drain_tx();
    r = stack_.udp_send_to(s->h, remote, data);
  }
  return r;
}

std::expected<UdpRecv, Error> UtcpTransport::recv_from(ConnId id, std::span<std::byte> out) {
  const Sock* s = find(id, Kind::udp);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  return stack_.udp_recv_from(s->h, out);
}

// --- Timers.

TimerToken UtcpTransport::add_timer(Duration period, std::function<void()> cb) {
  UTCP_CHECK(period > Duration::zero());
  const TimerToken t = next_timer_++;
  timers_.emplace(t, Timer{mono_now() + period, period,
                           std::make_shared<std::function<void()>>(std::move(cb))});
  return t;
}

TimerToken UtcpTransport::add_oneshot(Duration delay, std::function<void()> cb) {
  const TimerToken t = next_timer_++;
  timers_.emplace(t, Timer{mono_now() + std::max(delay, Duration::zero()), Duration::zero(),
                           std::make_shared<std::function<void()>>(std::move(cb))});
  return t;
}

void UtcpTransport::cancel_timer(TimerToken t) { timers_.erase(t); }

Time UtcpTransport::timer_deadline() const {
  Time d = Time::never();
  for (const auto& kv : timers_) {
    d = std::min(d, kv.second.deadline);
  }
  return d;
}

// Timers due at `now`, earliest first, ties in creation order. Callbacks may
// add or cancel timers, their own included.
void UtcpTransport::fire_timers(Time now) {
  while (!stop_requested_) {
    auto due = timers_.end();
    for (auto it = timers_.begin(); it != timers_.end(); ++it) {
      if (it->second.deadline <= now &&
          (due == timers_.end() || it->second.deadline < due->second.deadline)) {
        due = it;
      }
    }
    if (due == timers_.end()) {
      return;
    }
    const std::shared_ptr<std::function<void()>> cb = due->second.cb;
    if (due->second.period > Duration::zero()) {
      Timer& t = due->second;
      t.deadline = t.deadline + t.period;  // drift-free
      if (t.deadline <= now) {
        t.deadline = now + t.period;  // fell behind: no catch-up burst
      }
    } else {
      timers_.erase(due);
    }
    (*cb)();
  }
}

std::expected<std::unique_ptr<Transport>, std::string> make_utcp_transport(
    const UtcpTransportOptions& opts) {
  auto t = UtcpTransport::open(opts);
  if (!t) {
    return std::unexpected(std::move(t.error()));
  }
  return std::unique_ptr<Transport>(std::move(*t));
}

}  // namespace utcp::app
