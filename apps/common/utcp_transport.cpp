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

#include "common/jsonl.hpp"
#include "utcp/check.hpp"
#include "utcp/pcap.hpp"
#include "utcp/stats.hpp"
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

// --- TraceRecorder.

TraceRecorder::TraceRecorder(bool tx_retransmissions_only) : rexmit_only_(tx_retransmissions_only) {
  blocks_.emplace_back().reserve(block_events);
}

bool TraceRecorder::is_retransmission(TxKind k) noexcept {
  switch (k) {
    case TxKind::fast_rexmit:
    case TxKind::rexmit:
    case TxKind::rto_rexmit:
    case TxKind::pmtu_rexmit:
    case TxKind::tlp:
      return true;
    default:
      return false;
  }
}

void TraceRecorder::on_event(const TraceEvent& e) {
  if (rexmit_only_ && e.kind == TraceKind::tx && !is_retransmission(e.tx)) {
    return;
  }
  if (blocks_.back().size() == block_events) {
    blocks_.emplace_back().reserve(block_events);  // no copy of what is kept
  }
  blocks_.back().push_back(e);
  ++events_;
}

std::expected<void, std::string> TraceRecorder::write(const std::string& path) const {
  std::FILE* f = std::fopen(path.c_str(), "w");
  if (f == nullptr) {
    return std::unexpected(errno_text("cannot open trace file " + path, errno));
  }
  bool ok = true;
  JsonLine line;
  for (const auto& b : blocks_) {
    for (const TraceEvent& e : b) {
      line.clear();
      add_fields(line, e);
      std::string text = line.str();
      text += '\n';
      ok = ok && std::fwrite(text.data(), 1, text.size(), f) == text.size();
    }
  }
  if (std::fclose(f) != 0 || !ok) {
    return std::unexpected(errno_text("cannot write trace file " + path, errno));
  }
  return {};
}

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
  const std::size_t count = opts.tun_queues.value_or(1);
  if (count == 0 || count > tun_max_queues) {
    return std::unexpected(std::format("TUN queue count must be 1..{}", tun_max_queues));
  }
  const unsigned ifindex = ::if_nametoindex(opts.tun.c_str());
  if (ifindex == 0) {
    return std::unexpected(errno_text("if_nametoindex " + opts.tun, errno));
  }
  const bool multi_queue = opts.tun_queues.has_value();
  const auto open_queue = [&]() -> std::expected<TunDevice, std::string> {
    auto tun = TunDevice::open(opts.tun, /*nonblocking=*/true, opts.tun_offload, multi_queue);
    if (!tun) {
      return std::unexpected(
          std::format("cannot open TUN interface {} in {} mode: {}", opts.tun,
                      to_string(opts.tun_offload), tun.error().message()));
    }
    if (tun->name() != opts.tun || ::if_nametoindex(tun->name().c_str()) != ifindex) {
      return std::unexpected("TUN interface changed while attaching " + opts.tun);
    }
    return std::move(*tun);
  };
  auto tun = open_queue();
  if (!tun) {
    return std::unexpected(tun.error());
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
  std::vector<DeviceQueue> queues(count);
  const auto header_size = tun->vnet_header_size();
  queues[0].fd = tun->release();
  for (std::size_t i = 1; i < count; ++i) {
    auto next = open_queue();
    if (!next) {
      return std::unexpected(std::format("TUN queue {}: {}", i, next.error()));
    }
    if (next->vnet_header_size() != header_size) {
      return std::unexpected("inconsistent TUN queue framing");
    }
    queues[i].fd = next->release();
  }
  return attach_configured(std::move(queues), opts, ifindex, header_size);
}

UtcpTransport::DeviceQueue::~DeviceQueue() {
  if (fd >= 0) {
    ::close(fd);
  }
}

std::expected<std::unique_ptr<UtcpTransport>, std::string> UtcpTransport::attach(
    int fd, const UtcpTransportOptions& opts) {
  return attach_queues({fd}, opts);
}

std::expected<std::unique_ptr<UtcpTransport>, std::string> UtcpTransport::attach_queues(
    const std::vector<int>& fds, const UtcpTransportOptions& opts) {
  std::vector<DeviceQueue> queues(fds.size());
  bool valid = !fds.empty() && fds.size() <= tun_max_queues;
  auto first = fds.begin();
  // Take ownership of each distinct fd once, including on invalid input.
  for (std::size_t i = 0; i < fds.size(); ++i, ++first) {
    if (fds[i] < 0 || std::find(fds.begin(), first, fds[i]) != first) {
      valid = false;
    } else {
      queues[i].fd = fds[i];
    }
  }
  if (!valid) {
    return std::unexpected("attach: expected one or more distinct, valid file descriptors");
  }
  if (opts.tun_offload != TunOffload::legacy || opts.tun_queues) {
    return std::unexpected("TUN offloads and --tun-queues require UtcpTransport::open");
  }
  return attach_configured(std::move(queues), opts, 0, 0);
}

std::expected<std::unique_ptr<UtcpTransport>, std::string> UtcpTransport::attach_configured(
    std::vector<DeviceQueue> queues, const UtcpTransportOptions& opts,
    unsigned ifindex, std::size_t vnet_header_size) {
  for (const auto& queue : queues) {
    const int fl = ::fcntl(queue.fd, F_GETFL);
    if (fl < 0 || ::fcntl(queue.fd, F_SETFL, fl | O_NONBLOCK) < 0) {
      return std::unexpected(errno_text("fcntl(O_NONBLOCK)", errno));
    }
  }
  if (opts.stack.local_addr.v == 0) {
    return std::unexpected("the stack address (StackConfig::local_addr) is not set");
  }
  UtcpTransportOptions o = opts;
  o.stack.tcp_checksum_offload = vnet_header_size != 0;
  o.stack.tcp_gso_buffers = o.tun_offload == TunOffload::tcpv4 ? 16 : 0;
  if (vnet_header_size != 0) {
    // LINKTYPE_RAW cannot describe partial checksums or TCP super-segments.
    if (!o.pcap_file.empty()) {
      return std::unexpected("--pcap requires legacy TUN mode; capture on the peer for offload modes");
    }
    o.stack.tx_headroom = std::max(o.stack.tx_headroom,
                                   static_cast<std::uint16_t>(vnet_header_size));
  }
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
        return std::unexpected(errno_text("getrandom", errno));
      }
      got += static_cast<std::size_t>(n);
    }
    std::memcpy(o.stack.seed.w.data(), bytes.data(), bytes.size());
  }
  auto t = std::unique_ptr<UtcpTransport>(
      new UtcpTransport(std::move(queues), o, ifindex, vnet_header_size));
  if (!o.pcap_file.empty()) {
    t->pcap_ = std::make_unique<PcapWriter>();
    if (auto r = t->pcap_->open(o.pcap_file); !r) {
      return std::unexpected(r.error());
    }
  }
  return t;
}

UtcpTransport::UtcpTransport(std::vector<DeviceQueue> queues, const UtcpTransportOptions& opts,
                             unsigned ifindex, std::size_t vnet_header_size)
    : opt_(opts), queues_(std::move(queues)), ifindex_(ifindex), vnet_header_size_(vnet_header_size),
      loop_(loop_options(opts)), stack_(opts.stack),
      rxbuf_(max_datagram + vnet_header_size + (vnet_header_size != 0)) {
  for (std::size_t i = 0; i < queues_.size(); ++i) {
    loop_.watch(queues_[i].fd, EPOLLIN, [this, i](std::uint32_t ev) { on_device(i, ev); });
  }
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
  if (!opt_.stats_file.empty()) {
    const std::string line = stats_json() + "\n";
    std::FILE* f = std::fopen(opt_.stats_file.c_str(), "w");
    const bool ok = f != nullptr && std::fwrite(line.data(), 1, line.size(), f) == line.size();
    if (f == nullptr || std::fclose(f) != 0 || !ok) {
      std::fprintf(stderr, "utcp backend: cannot write --stats %s\n", opt_.stats_file.c_str());
    }
  }
  if (trace_) {
    stack_.set_trace_sink(nullptr);  // the Stack outlives trace_ only by declaration order
    if (auto r = trace_->write(trace_file_); !r) {
      std::fprintf(stderr, "utcp backend: %s\n", r.error().c_str());
    }
  }
  pending_tx_.reset();  // every TxPacket goes back before the Stack (stack.hpp)
  if (pcap_) {
    pcap_->close();
  }
  if (watched_) {
    for (const auto& queue : queues_) {
      loop_.unwatch(queue.fd);
    }
  }
}

std::string UtcpTransport::stats_json() const {
  JsonLine line;
  line.add("ev", "stack_stats");
  for_each_stat(stack_.stats(), [&](std::string_view name, std::uint64_t v) { line.add(name, v); });
  // The device counters come last, dev_device_failed at the end (the M1
  // backend check reads the line's end).
  const LoopStats& ls = loop_.stats();
  line.add("loop_iterations", ls.iterations)
      .add("loop_deadline_calls", ls.deadline_calls)
      .add("loop_pending_calls", ls.pending_calls)
      .add("loop_lateness_count", ls.lateness.count)
      .add("loop_lateness_max_ns", ls.lateness.max.count());
  for (std::size_t i = 0; i < LatenessHistogram::bucket_count; ++i) {
    if (ls.lateness.buckets[i] != 0) {
      line.add("loop_lateness_bucket_" + std::to_string(i), ls.lateness.buckets[i]);
    }
  }
  if (trace_) {
    line.add("trace_events", trace_->events()).add("trace_blocks", trace_->blocks());
  }
  line.add("dev_tun_ifindex", ifindex_)
      .add("dev_tun_multi_queue", opt_.tun_queues.has_value())
      .add("dev_tun_queues", queues_.size());
  for (std::size_t i = 0; i < queues_.size(); ++i) {
    line.add(std::format("dev_rx_queue_{}_datagrams", i), queues_[i].rx_datagrams)
        .add(std::format("dev_tx_queue_{}_datagrams", i), queues_[i].tx_datagrams);
  }
  line.add("dev_tun_offload", to_string(opt_.tun_offload))
      .add("dev_vnet_hdr_size", vnet_header_size_)
      .add("dev_rx_read_calls", dev_.rx_read_calls)
      .add("dev_tx_write_calls", dev_.tx_write_calls)
      .add("dev_rx_csum_valid", dev_.rx_csum_valid)
      .add("dev_rx_csum_partial", dev_.rx_csum_partial)
      .add("dev_rx_gro_datagrams", dev_.rx_gro_datagrams)
      .add("dev_rx_gro_segments", dev_.rx_gro_segments)
      .add("dev_rx_vnet_drops", dev_.rx_vnet_drops)
      .add("dev_tx_csum_partial", dev_.tx_csum_partial)
      .add("dev_tx_gso_datagrams", dev_.tx_gso_datagrams)
      .add("dev_tx_gso_segments", dev_.tx_gso_segments)
      .add("dev_rx_datagrams", dev_.rx_datagrams)
      .add("dev_rx_bytes", dev_.rx_bytes)
      .add("dev_rx_errors", dev_.rx_errors)
      .add("dev_tx_datagrams", dev_.tx_datagrams)
      .add("dev_tx_bytes", dev_.tx_bytes)
      .add("dev_tx_eagain", dev_.tx_eagain)
      .add("dev_tx_errors", dev_.tx_errors)
      .add("dev_last_tx_errno", dev_.last_tx_errno)
      .add("dev_rx_batches", dev_.rx_batches)
      .add("dev_rx_batch_limit", dev_.rx_batch_limit)
      .add("dev_pcap_records", dev_.pcap_records)
      .add("dev_pcap_failed", dev_.pcap_failed)
      .add("dev_tx_batch_max", dev_.tx_batch_max)
      .add("dev_device_failed", dev_.device_failed);
  return line.str();
}

void UtcpTransport::enable_trace(std::string path, bool tx_retransmissions_only) {
  UTCP_CHECK(!in_run_);
  trace_ = std::make_unique<TraceRecorder>(tx_retransmissions_only);
  trace_file_ = std::move(path);
  stack_.set_trace_sink(trace_.get());
}

// --- Device.

void UtcpTransport::on_device(std::size_t queue, std::uint32_t events) {
  if ((events & EPOLLOUT) != 0 && watching_out_ && queue == pending_tx_queue_) {
    drain_tx();
  }
  if ((events & EPOLLIN) != 0) {
    read_batch(queues_[queue]);
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
    for (const auto& queue : queues_) {
      loop_.unwatch(queue.fd);
    }
    watched_ = false;
    watching_out_ = false;
  }
}

void UtcpTransport::read_batch(DeviceQueue& queue) {
  ++dev_.rx_batches;
  // §8.2: the iteration starts with advance(clock()): timers due before these
  // datagrams arrived fire first.
  stack_.advance(mono_now());
  int n_read = 0;
  while (n_read < rx_batch) {
    ++dev_.rx_read_calls;
    const ssize_t n = ::read(queue.fd, rxbuf_.data(), rxbuf_.size());
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
    std::span<const std::byte> d(rxbuf_.data(), static_cast<std::size_t>(n));
    RxMeta meta;
    if (vnet_header_size_ != 0) {
      const auto packet = decode_tun_vnet(d, opt_.tun_offload);
      if (!packet) {
        ++dev_.rx_vnet_drops;
        continue;
      }
      d = packet->ip;
      meta = packet->meta;
      dev_.rx_csum_valid += meta.csum_verified;
      dev_.rx_csum_partial += meta.csum_partial;
      if (meta.gso_size != 0) {
        ++dev_.rx_gro_datagrams;
        dev_.rx_gro_segments += packet->segments;
      }
    }
    record_pcap(d);
    ++dev_.rx_datagrams;
    ++queue.rx_datagrams;
    dev_.rx_bytes += d.size();
    stack_.receive(mono_now(), d, meta);  // per packet, for RTT precision (§8.2)
  }
  ++dev_.rx_batch_limit;  // more may be waiting: epoll is level-triggered
}

void UtcpTransport::drain_tx() {
  if (dev_.device_failed) {
    return;
  }
  std::uint64_t popped = 0;
  for (;;) {
    if (!pending_tx_) {
      pending_tx_ = stack_.pop_transmit();
      if (!pending_tx_) {
        break;
      }
      dev_.tx_batch_max = std::max(dev_.tx_batch_max, ++popped);
      pending_tx_queue_ = queues_.size() == 1
                              ? 0
                              : tun_tx_queue(std::as_const(pending_tx_->buf).bytes(), queues_.size());
      if (vnet_header_size_ != 0) {
        pending_tx_segments_ = prepend_tun_vnet(*pending_tx_);
      }
    }
    const std::span<const std::byte> b = std::as_const(pending_tx_->buf).bytes();
    DeviceQueue& queue = queues_[pending_tx_queue_];
    ++dev_.tx_write_calls;
    const ssize_t n = ::write(queue.fd, b.data(), b.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // §8.2: keep the packet and wait for EPOLLOUT.
        ++dev_.tx_eagain;
        if (!watching_out_) {
          loop_.modify(queue.fd, EPOLLIN | EPOLLOUT);
          watching_out_ = true;
        }
        return;
      }
      ++dev_.tx_errors;  // EIO (interface down), EINVAL, ...: dropped, as a full link would
      dev_.last_tx_errno = errno;
    } else if (static_cast<std::size_t>(n) != b.size()) {
      ++dev_.tx_errors;  // one TUN write must consume one full frame
      dev_.last_tx_errno = EIO;
    } else {
      record_pcap(b.subspan(vnet_header_size_));
      ++dev_.tx_datagrams;
      ++queue.tx_datagrams;
      dev_.tx_bytes += b.size() - vnet_header_size_;
      dev_.tx_csum_partial += pending_tx_->csum_partial;
      if (pending_tx_->gso_size != 0) {
        ++dev_.tx_gso_datagrams;
        dev_.tx_gso_segments += pending_tx_segments_;
      }
    }
    if (watching_out_) {
      loop_.modify(queue.fd, EPOLLIN);
      watching_out_ = false;
    }
    pending_tx_.reset();
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

bool UtcpTransport::closing_done() const {
  const auto open = static_cast<std::uint32_t>(std::ranges::count_if(
      socks_, [](const auto& kv) { return kv.second.kind != Kind::udp; }));
  const StackUsage u = stack_.debug_usage();
  return u.tcp_slots <= open && u.time_wait_entries == 0 && !pending_tx_;
}

void UtcpTransport::finish_closing(Duration max) {
  UTCP_CHECK(!in_run_);  // not from a callback
  Handler none;
  handler_ = &none;
  in_run_ = true;
  stop_requested_ = dev_.device_failed;
  bool expired = false;
  const TimerToken limit = add_oneshot(max, [&expired] { expired = true; });
  stack_.advance(mono_now());
  for (;;) {
    deliver_events();
    drain_tx();
    flush_pcap();
    if (expired || stop_requested_ || loop_.stopped() || closing_done()) {
      break;
    }
    loop_.run_once();
  }
  cancel_timer(limit);
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
