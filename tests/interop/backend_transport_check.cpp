// backend_transport_check: checks UtcpTransport (apps/common/utcp_transport.hpp)
// over one end of a SOCK_SEQPACKET socketpair (UtcpTransport::attach), the
// other end playing the kernel. Prints one PASS or FAIL line per check and
// exits 1 if any failed.
//
// Always (the link-stub Stack is enough):
//   attach_errors   attach(-1) fails; a missing local address fails
//   timers          one-shot and periodic timers fire in deadline order, a
//                   callback may cancel another timer, stop() ends run()
//   rerun           run() works again after stop()
//   device_rx_pcap  datagrams read from the device are counted and recorded
//                   in the --pcap file byte for byte (LINKTYPE_RAW,
//                   nanosecond magic, CLOCK_REALTIME stamps)
//   signal          SIGTERM ends run() through the EventLoop's signalfd
//   device_hup      the device's peer closing ends run() (device_failed)
// With --expect-stack (needs the m1-ip Stack):
//   icmp_echo       an echo request written to the device is answered
//   udp_echo        a UDP datagram reaches a Handler that echoes it back
//   tx_eagain       64 datagrams sent while the device's peer does not read:
//                   writes hit EAGAIN, the packet is kept, EPOLLOUT resumes
//                   the drain, and all 64 arrive in order
// With --tun IFNAME (an existing, running TUN interface, MTU 1500):
//   open_tun        open() refuses a stack MTU that differs from the
//                   interface's and accepts the right one
#include <fcntl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iterator>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/cli.hpp"
#include "common/utcp_transport.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/udp.hpp"
#include "utcp/checksum.hpp"
#include "utcp/pcap.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Ipv4Addr;
using utcp::Time;
using utcp::app::ConnId;
using utcp::app::UtcpTransport;
using utcp::app::UtcpTransportOptions;
namespace wire = utcp::wire;

const Ipv4Addr stack_addr = Ipv4Addr::from_octets(198, 18, 0, 2);
const Ipv4Addr kernel_addr = Ipv4Addr::from_octets(198, 18, 0, 1);

int failures = 0;

void expect(bool ok, std::string_view check, std::string_view detail) {
  std::println("{} {}: {}", ok ? "PASS" : "FAIL", check, detail);
  if (!ok) {
    ++failures;
  }
}

Time realtime_now() {
  timespec ts{};
  clock_gettime(CLOCK_REALTIME, &ts);
  return Time{static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec};
}

// fds[0] goes to the transport, fds[1] is the kernel's end (non-blocking).
struct Pair {
  int ours = -1, theirs = -1;
  Pair() {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds) != 0) {
      std::println("socketpair: {}", std::strerror(errno));
      std::exit(2);
    }
    ours = fds[0];
    theirs = fds[1];
    fcntl(theirs, F_SETFL, fcntl(theirs, F_GETFL) | O_NONBLOCK);
  }
  ~Pair() {
    if (theirs >= 0) {
      close(theirs);
    }
  }
  Pair(const Pair&) = delete;
  Pair& operator=(const Pair&) = delete;
  // The transport owns `ours` after attach.
  int give() { return std::exchange(ours, -1); }
  std::optional<std::vector<std::byte>> read_theirs() const {
    std::vector<std::byte> b(65536);
    const ssize_t n = read(theirs, b.data(), b.size());
    if (n <= 0) {
      return std::nullopt;
    }
    b.resize(static_cast<std::size_t>(n));
    return b;
  }
  bool write_theirs(std::span<const std::byte> d) const {
    return write(theirs, d.data(), d.size()) == static_cast<ssize_t>(d.size());
  }
};

UtcpTransportOptions options(std::string pcap = {}) {
  UtcpTransportOptions o;
  o.stack.local_addr = stack_addr;
  o.stack.mtu = 1500;
  o.seed_from_getrandom = false;
  o.stack.seed = utcp::Seed::from_u64(20261112);
  o.pcap_file = std::move(pcap);
  return o;
}

std::unique_ptr<UtcpTransport> attach(Pair& p, const UtcpTransportOptions& o) {
  auto t = UtcpTransport::attach(p.give(), o);
  if (!t) {
    std::println("FAIL attach: {}", t.error());
    std::exit(1);
  }
  return std::move(*t);
}

// Handler that records events and echoes UDP datagrams.
struct Recorder final : utcp::app::Handler {
  UtcpTransport* t = nullptr;
  bool echo_udp = false;
  std::uint64_t udp_echoed = 0;
  void on_readable(ConnId id) override {
    std::array<std::byte, 2048> buf{};
    for (;;) {
      const auto r = t->recv_from(id, buf);
      if (!r) {
        return;
      }
      if (echo_udp && t->send_to(id, r->from, std::span(buf).first(r->len))) {
        ++udp_echoed;
      }
    }
  }
};

std::vector<std::byte> ipv4_datagram(Ipv4Addr src, Ipv4Addr dst, std::uint8_t proto,
                                     std::span<const std::byte> l4) {
  std::vector<std::byte> d(wire::ipv4_header_len + l4.size());
  std::ranges::copy(l4, d.begin() + wire::ipv4_header_len);
  wire::write_ipv4(d, wire::Ipv4Header{.ttl = 64,
                                       .proto = proto,
                                       .total_len = static_cast<std::uint16_t>(d.size()),
                                       .id = 1,
                                       .src = src,
                                       .dst = dst});
  return d;
}

std::vector<std::byte> udp_from_kernel(std::uint16_t sport, std::uint16_t dport,
                                       std::span<const std::byte> payload) {
  std::vector<std::byte> l4(wire::udp_header_len + payload.size());
  std::ranges::copy(payload, l4.begin() + wire::udp_header_len);
  wire::write_udp_header(l4, wire::UdpHeader{.sport = sport,
                                             .dport = dport,
                                             .len = static_cast<std::uint16_t>(l4.size())});
  wire::set_l4_checksum(l4, kernel_addr, stack_addr, utcp::ip_proto_udp);
  return ipv4_datagram(kernel_addr, stack_addr, utcp::ip_proto_udp, l4);
}

std::vector<std::byte> bytes_of(std::string_view s) {
  std::vector<std::byte> b(s.size());
  std::memcpy(b.data(), s.data(), s.size());
  return b;
}

// --- Checks.

void check_attach_errors() {
  const auto bad_fd = UtcpTransport::attach(-1, options());
  expect(!bad_fd, "attach_errors", "attach(-1) fails");
  Pair p;
  UtcpTransportOptions o = options();
  o.stack.local_addr = Ipv4Addr{};
  const auto no_addr = UtcpTransport::attach(p.give(), o);
  expect(!no_addr && no_addr.error().find("local_addr") != std::string::npos, "attach_errors",
         no_addr ? "attach without an address succeeded" : no_addr.error());
}

void check_timers_and_rerun() {
  Pair p;
  auto t = attach(p, options());
  std::string log;
  int periodic = 0;
  const Time t0 = t->now();
  std::optional<Time> stopped_at;
  t->add_timer(10ms, [&] {
    log += 'p';
    if (++periodic == 3) {
      stopped_at = t->now();
      t->stop();
    }
  });
  t->add_oneshot(5ms, [&] { log += 'a'; });
  t->add_oneshot(5ms, [&] { log += 'b'; });
  const auto never = t->add_oneshot(15ms, [&] { log += 'X'; });
  t->add_oneshot(12ms, [&] {
    log += 'c';
    t->cancel_timer(never);
  });
  Recorder h;
  h.t = t.get();
  t->run(h);
  const auto elapsed = (stopped_at.value_or(t0) - t0);
  expect(log == "abpcpp", "timers", std::format("order {} (want abpcpp)", log));
  expect(elapsed >= 30ms && elapsed < 200ms, "timers",
         std::format("third periodic tick after {} us (want >= 30000)", elapsed.count() / 1000));
  const auto* ls = t->loop_stats();
  expect(ls != nullptr && ls->deadline_calls >= 5 && ls->lateness.count == ls->deadline_calls,
         "timers",
         std::format("loop stats: {} deadline calls, {} lateness samples",
                     ls ? ls->deadline_calls : 0, ls ? ls->lateness.count : 0));

  bool ran = false;
  t->add_oneshot(1ms, [&] {
    ran = true;
    t->stop();
  });
  t->run(h);
  expect(ran, "rerun", "run() after stop() fires a new timer and returns on stop()");
}

void check_device_rx_pcap(const std::filesystem::path& dir) {
  const std::filesystem::path pcap = dir / "backend_transport_check.pcap";
  std::vector<std::vector<std::byte>> sent;
  for (const std::size_t n : {60u, 1500u, 20u}) {
    std::vector<std::byte> d(n);
    for (std::size_t i = 0; i < n; ++i) {
      d[i] = static_cast<std::byte>((i * 7 + n) & 0x0f);  // version nibble 0: not IPv4
    }
    sent.push_back(std::move(d));
  }
  const Time before = realtime_now();
  {
    Pair p;
    auto t = attach(p, options(pcap.string()));
    for (const auto& d : sent) {
      if (!p.write_theirs(d)) {
        expect(false, "device_rx_pcap", "write to the socketpair failed");
        return;
      }
    }
    t->add_oneshot(30ms, [&] { t->stop(); });
    Recorder h;
    h.t = t.get();
    t->run(h);
    const auto& d = t->device_stats();
    expect(d.rx_datagrams == 3 && d.rx_bytes == 1580 && d.rx_errors == 0 && d.rx_batches >= 1,
           "device_rx_pcap",
           std::format("rx_datagrams {} rx_bytes {} rx_errors {} (want 3, 1580, 0)",
                       d.rx_datagrams, d.rx_bytes, d.rx_errors));
    expect(d.pcap_records == 3 && !d.pcap_failed, "device_rx_pcap",
           std::format("pcap_records {}", d.pcap_records));
  }  // destroyed: the pcap buffer is flushed
  const Time after = realtime_now();

  std::ifstream f(pcap, std::ios::binary);
  const std::vector<char> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::span<const std::byte> b(reinterpret_cast<const std::byte*>(raw.data()), raw.size());
  const auto le32 = [&b](std::size_t at) {
    std::uint32_t v = 0;
    for (int i = 3; i >= 0; --i) {
      v = (v << 8) | std::to_integer<std::uint32_t>(b[at + static_cast<std::size_t>(i)]);
    }
    return v;
  };
  bool ok = b.size() >= 24 && le32(0) == utcp::pcap_magic_ns && le32(16) == 65535 &&
            le32(20) == utcp::pcap_linktype_raw;
  std::size_t at = 24;
  std::string detail = std::format("{} bytes", b.size());
  for (const auto& d : sent) {
    if (!ok || at + 16 > b.size()) {
      ok = false;
      break;
    }
    const std::int64_t ts = std::int64_t{le32(at)} * 1'000'000'000 + le32(at + 4);
    const std::uint32_t caplen = le32(at + 8), len = le32(at + 12);
    ok = ts >= before.ns && ts <= after.ns && caplen == d.size() && len == d.size() &&
         at + 16 + caplen <= b.size() &&
         std::ranges::equal(b.subspan(at + 16, caplen), std::span<const std::byte>(d));
    at += 16 + caplen;
  }
  ok = ok && at == b.size();
  expect(ok, "device_rx_pcap",
         detail + ": header (magic a1b23c4d, snaplen 65535, LINKTYPE_RAW) and 3 records "
                  "with CLOCK_REALTIME stamps and the bytes read");
  std::filesystem::remove(pcap);
}

void check_signal() {
  Pair p;
  auto t = attach(p, options());
  t->add_oneshot(5ms, [] { kill(getpid(), SIGTERM); });
  bool timed_out = false;
  t->add_oneshot(2s, [&] {
    timed_out = true;
    t->stop();
  });
  Recorder h;
  h.t = t.get();
  t->run(h);
  expect(!timed_out && t->stop_signal() == SIGTERM, "signal",
         std::format("run() returned with stop_signal {} (want {})", t->stop_signal(), SIGTERM));
}

void check_device_hup() {
  Pair p;
  auto t = attach(p, options());
  t->add_oneshot(5ms, [&p] {
    close(p.theirs);
    p.theirs = -1;
  });
  bool timed_out = false;
  t->add_oneshot(2s, [&] {
    timed_out = true;
    t->stop();
  });
  Recorder h;
  h.t = t.get();
  t->run(h);
  expect(!timed_out && t->device_stats().device_failed, "device_hup",
         "run() returned when the device's peer closed, device_failed set");
}

// Runs until done() or 2 s; poll() is called every millisecond.
void run_until(UtcpTransport& t, utcp::app::Handler& h, const std::function<void()>& poll,
               const std::function<bool()>& done) {
  const auto tick = t.add_timer(1ms, [&] {
    poll();
    if (done()) {
      t.stop();
    }
  });
  const auto limit = t.add_oneshot(2s, [&] { t.stop(); });
  t.run(h);
  t.cancel_timer(tick);
  t.cancel_timer(limit);
}

void check_icmp_echo() {
  Pair p;
  auto t = attach(p, options());
  const auto payload = bytes_of("backend_transport_check echo payload");
  std::vector<std::byte> icmp(wire::icmp_header_len + payload.size());
  std::ranges::copy(payload, icmp.begin() + wire::icmp_header_len);
  wire::write_icmp(icmp, wire::icmp_echo_header(wire::icmp_echo_request, 0x1234, 7));
  const bool wrote = p.write_theirs(ipv4_datagram(kernel_addr, stack_addr, utcp::ip_proto_icmp, icmp));
  bool got = false;
  Recorder h;
  h.t = t.get();
  run_until(
      *t, h,
      [&] {
        while (const auto d = p.read_theirs()) {
          const auto ip = wire::parse_ipv4(*d);
          if (!ip || ip->h.proto != utcp::ip_proto_icmp) {
            continue;
          }
          const auto m = wire::parse_icmp(ip->payload, true);
          got = got || (m && m->h.type == wire::icmp_echo_reply && m->h.echo_id() == 0x1234 &&
                        m->h.echo_seq() == 7 && ip->h.src == stack_addr &&
                        ip->h.dst == kernel_addr && std::ranges::equal(m->body, payload));
        }
      },
      [&] { return got; });
  expect(wrote && got, "icmp_echo", "echo request id 0x1234 seq 7 answered with the same payload");
}

void check_udp_echo() {
  Pair p;
  auto t = attach(p, options());
  const auto sock = t->udp_open(utcp::Endpoint{stack_addr, 7});
  if (!sock) {
    expect(false, "udp_echo", std::format("udp_open: {}", utcp::to_string(sock.error())));
    return;
  }
  const auto payload = bytes_of("one datagram for the echo handler");
  const bool wrote = p.write_theirs(udp_from_kernel(5555, 7, payload));
  bool got = false;
  Recorder h;
  h.t = t.get();
  h.echo_udp = true;
  run_until(
      *t, h,
      [&] {
        while (const auto d = p.read_theirs()) {
          const auto ip = wire::parse_ipv4(*d);
          if (!ip || ip->h.proto != utcp::ip_proto_udp) {
            continue;
          }
          const auto u = wire::parse_udp(ip->payload, ip->h.src, ip->h.dst, true);
          got = got || (u && u->h.sport == 7 && u->h.dport == 5555 && ip->h.dst == kernel_addr &&
                        std::ranges::equal(u->payload, payload));
        }
      },
      [&] { return got; });
  expect(wrote && got && h.udp_echoed == 1, "udp_echo",
         std::format("datagram echoed by the Handler ({} sends)", h.udp_echoed));
}

void check_tx_eagain() {
  Pair p;
  const int small = 4096;  // the kernel doubles it; a few 1 KB datagrams fill it
  setsockopt(p.ours, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
  auto t = attach(p, options());
  const auto sock = t->udp_open(utcp::Endpoint{stack_addr, 9000});
  if (!sock) {
    expect(false, "tx_eagain", std::format("udp_open: {}", utcp::to_string(sock.error())));
    return;
  }
  constexpr std::uint32_t n = 64;
  std::uint32_t send_errors = 0;
  bool reading = false;
  t->add_oneshot(1ms, [&] {
    std::vector<std::byte> payload(1000);
    for (std::uint32_t i = 0; i < n; ++i) {
      wire::store_be32(payload, 0, i);
      if (!t->send_to(*sock, utcp::Endpoint{kernel_addr, 9001}, payload)) {
        ++send_errors;
      }
    }
  });
  t->add_oneshot(30ms, [&] { reading = true; });  // the kernel side starts reading late
  std::vector<std::uint32_t> got;
  Recorder h;
  h.t = t.get();
  run_until(
      *t, h,
      [&] {
        if (!reading) {
          return;
        }
        while (const auto d = p.read_theirs()) {
          const auto ip = wire::parse_ipv4(*d);
          if (!ip || ip->h.proto != utcp::ip_proto_udp) {
            continue;
          }
          const auto u = wire::parse_udp(ip->payload, ip->h.src, ip->h.dst, true);
          if (u && u->payload.size() == 1000) {
            got.push_back(wire::load_be32(u->payload, 0));
          }
        }
      },
      [&] { return got.size() >= n; });
  bool in_order = got.size() == n;
  for (std::uint32_t i = 0; in_order && i < n; ++i) {
    in_order = got[i] == i;
  }
  const auto& d = t->device_stats();
  expect(send_errors == 0 && in_order && d.tx_eagain > 0 && d.tx_errors == 0, "tx_eagain",
         std::format("{} of {} datagrams in order, {} send errors, tx_eagain {}, tx_errors {}",
                     got.size(), n, send_errors, d.tx_eagain, d.tx_errors));
}

void check_open_tun(const std::string& tun) {
  UtcpTransportOptions o = options();
  o.tun = tun;
  o.stack.mtu = 1400;
  const auto wrong = UtcpTransport::open(o);
  expect(!wrong && wrong.error().find("differs") != std::string::npos, "open_tun",
         wrong ? "open with a stack MTU of 1400 succeeded" : wrong.error());
  o.stack.mtu = 1500;
  const auto right = UtcpTransport::open(o);
  expect(right.has_value(), "open_tun",
         right ? std::format("open {} with MTU 1500", tun) : right.error());
}

}  // namespace

int main(int argc, char** argv) {
  std::setvbuf(stdout, nullptr, _IOLBF, 0);
  utcp::app::CliParser cli("backend_transport_check",
                           "Checks UtcpTransport over a socketpair (and a TUN interface).");
  cli.flag("expect-stack", "also run the checks that need a working Stack (m1-ip)")
      .option("tun", "IFNAME", "also check open() on this existing TUN interface (MTU 1500)")
      .option("tmp", "DIR", "directory for the pcap file", "/tmp");
  const auto args = cli.parse(argc, argv);
  if (!args || args->help()) {
    std::println(stderr, "{}{}", args ? "" : args.error() + "\n", cli.usage());
    return args ? 0 : 2;
  }
  check_attach_errors();
  check_timers_and_rerun();
  check_device_rx_pcap(*args->get("tmp"));
  check_signal();
  check_device_hup();
  if (args->flag("expect-stack")) {
    check_icmp_echo();
    check_udp_echo();
    check_tx_eagain();
  }
  if (const auto tun = args->get("tun")) {
    check_open_tun(*tun);
  }
  std::println("{} check(s) failed", failures);
  return failures == 0 ? 0 : 1;
}
