// backend_transport_check: checks UtcpTransport (apps/common/utcp_transport.hpp)
// over one end of a SOCK_SEQPACKET socketpair (UtcpTransport::attach), the
// other end playing the kernel. Prints one PASS or FAIL line per check and
// exits 1 if any failed.
//
// Always (the link-stub Stack is enough):
//   attach_errors   attach(-1) fails; a missing local address fails
//   timers          one-shot and periodic timers fire in deadline order, a
//                   callback may cancel another timer, stop() ends run()
//   timer_ties      timers with equal deadlines fire in creation order
//   rerun           run() works again after stop()
//   device_rx_pcap  datagrams read from the device are counted and recorded
//                   in the --pcap file byte for byte (LINKTYPE_RAW,
//                   nanosecond magic, CLOCK_REALTIME stamps); the file
//                   header is on disk right after open, and the records
//                   before the transport is destroyed (a killed process
//                   keeps them)
//   stats_file      with stats_file set, the destructor writes one JSON line
//                   with every StackStats field and the device counters
//                   (3 datagrams read: IpInReceives 3, dev_rx_datagrams 3)
//   signal          SIGTERM ends run() through the EventLoop's signalfd
//   device_hup      the device's peer closing ends run() (device_failed)
//   open_missing    open() on a TUN interface that does not exist fails at
//                   once with "does not exist" and creates nothing
// With --expect-stack (needs the m1-ip Stack):
//   icmp_echo       an echo request written to the device is answered
//   udp_echo        a UDP datagram reaches a Handler that echoes it back
//                   (both without a periodic timer: a reply left queued
//                   across a blocking wait is never written, and the check
//                   fails after 2 s)
//   tx_eagain       64 datagrams sent while the device's peer does not read:
//                   writes hit EAGAIN, the packet is kept, EPOLLOUT resumes
//                   the drain, and all 64 arrive in order
//   rx_clock        §8.2 for a batch of two echo replies read after a stack
//                   timer (PMTU expiry) fell due: the timer fires before the
//                   batch is received (advance(clock()) first), and each
//                   datagram gets its own receive time (strictly increasing)
//   outside_run_drain  udp_open, listen and a failing connect called outside
//                   run() leave nothing in the transmit queue when they return
//   finish_closing  the program closes an accepted connection and run()
//                   returns; the peer's FIN arrives after that and
//                   finish_closing ACKs it at once (without it the FIN is
//                   never ACKed: interop case E-chunked); the peer sends its
//                   FIN again 200 ms later, as if that ACK were lost, and the
//                   connection, in TIME-WAIT, ACKs it again (interop case
//                   B-sack1-ts1-ws0-s2l: the program had exited in TIME-WAIT
//                   and the peer's 4 retransmitted FINs were never ACKed);
//                   finish_closing returns at its limit with the TIME-WAIT
//                   entry still there
// With --tun IFNAME (an existing, running TUN interface, MTU 1500):
//   open_tun        open() refuses a stack MTU that differs from the
//                   interface's and accepts the right one
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
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
#include <thread>
#include <vector>

#include "common/cli.hpp"
#include "common/utcp_transport.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "core/wire/udp.hpp"
#include "utcp/checksum.hpp"
#include "utcp/event_loop.hpp"
#include "utcp/pcap.hpp"
#include "utcp/trace.hpp"

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
    if (ours >= 0) {
      close(ours);
    }
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

void check_timers_and_rerun(bool start_overdue) {
  Pair p;
  auto t = attach(p, options());
  const auto check = start_overdue ? "timers_coalesced" : "timers";
  constexpr auto period = 10ms;
  std::string log;
  std::string early;
  std::vector<Time> ticks;
  std::vector<Time> batches;
  const auto record = [&](char name, Time earliest) {
    // Stack::now() is the dispatch time passed to every timer in this batch.
    const Time now = t->stack().now();
    if (batches.empty() || batches.back() != now) {
      batches.push_back(now);
    }
    log += name;
    if (now < earliest) {
      early += name;
    }
    return now;
  };
  const Time t0 = t->now();
  std::optional<Time> stopped_at;
  Time earliest_tick = t0 + period;
  t->add_timer(period, [&] {
    ticks.push_back(record('p', earliest_tick));
    earliest_tick += period;
    if (ticks.size() == 3) {
      stopped_at = t->now();
      t->stop();
    }
  });
  t->add_oneshot(5ms, [&, due = t->now() + 5ms] { record('a', due); });
  t->add_oneshot(5ms, [&, due = t->now() + 5ms] { record('b', due); });
  const auto never = t->add_oneshot(15ms, [&] { log += 'X'; });
  t->add_oneshot(12ms, [&, due = t->now() + 12ms] {
    record('c', due);
    t->cancel_timer(never);
    if (start_overdue) {
      // Leave the second tick part of a period late to exercise drift-free rearming.
      std::this_thread::sleep_for(15ms);
    }
  });
  Recorder h;
  h.t = t.get();
  if (start_overdue) {
    // All one-shots and the first periodic tick are due in the same dispatch.
    std::this_thread::sleep_for(25ms);
  }
  t->run(h);
  const auto elapsed = stopped_at.value_or(t0) - t0;
  expect(log == "abpcpp", check, std::format("order {} (want abpcpp)", log));
  expect(early.empty(), check, std::format("callbacks before their deadlines: '{}'", early));
  expect(elapsed >= 30ms && elapsed < 200ms, check,
         std::format("third periodic tick after {} us (want [30000, 200000))",
                     elapsed.count() / 1000));
  expect(ticks.size() == 3 && ticks[0] < ticks[1] && ticks[1] < ticks[2], check,
         "three periodic ticks in distinct batches");
  const auto* ls = t->loop_stats();
  expect(ls && ls->deadline_calls + ls->deadline_calls_after_wake == batches.size() &&
             ls->lateness.count == ls->deadline_calls,
         check,
         std::format("{} timer batches, {} deadlines at wake, {} after wake, {} lateness samples",
                     batches.size(), ls ? ls->deadline_calls : 0,
                     ls ? ls->deadline_calls_after_wake : 0, ls ? ls->lateness.count : 0));
  if (start_overdue && ticks.size() == 3 && ls) {
    expect(batches.size() == 3 && ls->lateness.max >= 20ms, check,
           "three batches, with the first deadline at least 20 ms overdue");
    // The first missed period resets the phase. A partially late second tick
    // keeps that phase; only another whole missed period resets it again.
    const Time phase = ticks[0] + 2 * period;
    const Time third_due = ticks[1] < phase ? phase : ticks[1] + period;
    expect(ticks[1] >= ticks[0] + period && ticks[2] >= third_due, check,
           "overdue periodic timer rearmed without an early tick");
    // The final wait starts after the second dispatch. Even a late wake
    // must have requested at most the time remaining to the third deadline.
    expect(ls->last_timeout_ns >= 0 && ls->last_timeout_ns <= (third_due - ticks[1]).count(), check,
           std::format("third tick requested {} ns of wait (at most {})", ls->last_timeout_ns,
                       (third_due - ticks[1]).count()));
  }

  bool ran = false;
  t->add_oneshot(1ms, [&] {
    ran = true;
    t->stop();
  });
  t->run(h);
  expect(ran, "rerun", "run() after stop() fires a new timer and returns on stop()");
}

// Equal deadlines fire in creation order (fire_timers). Two periodic timers
// of 10 ms that fell behind by more than a period before run() are both
// rescheduled to now + 10 ms in the same handler call, so their next firing
// is a tie: A was created first and must fire first again.
void check_timer_ties() {
  Pair p;
  auto t = attach(p, options());
  std::string log;
  int fired = 0;
  const auto tick = [&](char name) {
    log += name;
    if (++fired == 4) {
      t->stop();
    }
  };
  t->add_timer(10ms, [&] { tick('A'); });
  t->add_timer(10ms, [&] { tick('B'); });
  bool timed_out = false;
  t->add_oneshot(2s, [&] {
    timed_out = true;
    t->stop();
  });
  std::this_thread::sleep_for(35ms);
  Recorder h;
  h.t = t.get();
  t->run(h);
  expect(!timed_out && log == "ABAB", "timer_ties",
         std::format("order {} (want ABAB: A, B fell behind and were both rescheduled to "
                     "now + 10 ms, then the tie fires in creation order)",
                     log));
}

// What is wrong with the pcap file at `path`, empty if nothing: it must hold
// the file header (magic a1b23c4d, snaplen 65535, LINKTYPE_RAW) and exactly
// `records`, in order, with CLOCK_REALTIME stamps in [before, after].
std::string pcap_problem(const std::filesystem::path& path,
                         const std::vector<std::vector<std::byte>>& records, Time before,
                         Time after) {
  std::ifstream f(path, std::ios::binary);
  const std::vector<char> raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  const std::span<const std::byte> b(reinterpret_cast<const std::byte*>(raw.data()), raw.size());
  const auto le32 = [&b](std::size_t at) {
    std::uint32_t v = 0;
    for (int i = 3; i >= 0; --i) {
      v = (v << 8) | std::to_integer<std::uint32_t>(b[at + static_cast<std::size_t>(i)]);
    }
    return v;
  };
  if (b.size() < utcp::pcap_file_header_size) {
    return std::format("{} bytes on disk: no file header", b.size());
  }
  if (le32(0) != utcp::pcap_magic_ns || le32(16) != 65535 || le32(20) != utcp::pcap_linktype_raw) {
    return "wrong file header";
  }
  std::size_t at = utcp::pcap_file_header_size;
  for (std::size_t k = 0; k < records.size(); ++k) {
    const auto& d = records[k];
    if (at + utcp::pcap_record_header_size > b.size()) {
      return std::format("{} bytes on disk: record {} of {} missing", b.size(), k + 1,
                         records.size());
    }
    const std::int64_t ts = std::int64_t{le32(at)} * 1'000'000'000 + le32(at + 4);
    const std::uint32_t caplen = le32(at + 8), len = le32(at + 12);
    at += utcp::pcap_record_header_size;
    if (ts < before.ns || ts > after.ns) {
      return std::format("record {} stamped outside the run", k + 1);
    }
    if (caplen != d.size() || len != d.size() || at + caplen > b.size() ||
        !std::ranges::equal(b.subspan(at, caplen), std::span<const std::byte>(d))) {
      return std::format("record {} differs from the datagram", k + 1);
    }
    at += caplen;
  }
  if (at != b.size()) {
    return std::format("{} bytes after the last record", b.size() - at);
  }
  return {};
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
    const std::string at_open = pcap_problem(pcap, {}, before, before);
    expect(at_open.empty(), "device_rx_pcap",
           at_open.empty() ? "the file header is on disk right after open" : at_open);
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
    // The datagrams were read before run()'s last wait, so they are on disk
    // now, with the transport still alive: a process killed here keeps them.
    const std::string in_run = pcap_problem(pcap, sent, before, realtime_now());
    expect(in_run.empty(), "device_rx_pcap",
           in_run.empty() ? "the 3 records are on disk before the transport is destroyed"
                          : in_run + " before the transport is destroyed");
  }
  const Time after = realtime_now();
  const std::string final_problem = pcap_problem(pcap, sent, before, after);
  expect(final_problem.empty(), "device_rx_pcap",
         final_problem.empty() ? "after destruction: header (magic a1b23c4d, snaplen 65535, "
                                 "LINKTYPE_RAW) and 3 records with CLOCK_REALTIME stamps and "
                                 "the bytes read"
                               : final_problem);
  std::filesystem::remove(pcap);
}

void check_stats_file(const std::filesystem::path& dir) {
  const std::filesystem::path file = dir / "backend_transport_check.stats.json";
  std::filesystem::remove(file);
  {
    Pair p;
    UtcpTransportOptions o = options();
    o.stats_file = file.string();
    auto t = attach(p, o);
    for (const std::size_t n : {20u, 40u, 60u}) {
      const std::vector<std::byte> d(n, std::byte{0});  // version 0: IpInHdrErrors
      if (!p.write_theirs(d)) {
        expect(false, "stats_file", "write to the socketpair failed");
        return;
      }
    }
    t->add_oneshot(30ms, [&] { t->stop(); });
    Recorder h;
    h.t = t.get();
    t->run(h);
    expect(!std::filesystem::exists(file), "stats_file", "nothing is written before destruction");
  }
  std::ifstream in(file);
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  const bool ok = text.starts_with("{\"ev\":\"stack_stats\",\"") && text.ends_with("}\n") &&
                  std::ranges::count(text, '\n') == 1 &&
                  text.contains("\"IpInReceives\":3,") && text.contains("\"IpInHdrErrors\":3,") &&
                  text.contains("\"TcpRetransSegs\":0,") &&
                  text.contains("\"dev_rx_datagrams\":3,") &&
                  text.contains("\"dev_device_failed\":false}");
  expect(ok, "stats_file",
         ok ? "one JSON line with IpInReceives 3, IpInHdrErrors 3, TcpRetransSegs 0, "
              "dev_rx_datagrams 3"
            : "unexpected content: " + text);
  std::filesystem::remove(file);
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

// Runs `t` until a datagram that `wanted` accepts comes out of the device,
// at most 2 s. A helper thread reads the kernel's end with poll(2) and ends
// run() with SIGTERM (the EventLoop's signalfd) once it has seen the
// datagram. No periodic timer wakes the loop, so a datagram left queued
// across a blocking wait (host contract 1, §3.4: pop_transmit is drained
// before every wait) never comes out and the 2 s limit fails the check.
bool run_until_datagram(UtcpTransport& t, const Pair& p, utcp::app::Handler& h,
                        const std::function<bool(std::span<const std::byte>)>& wanted) {
  std::atomic<bool> seen{false};
  std::atomic<bool> quit{false};
  // Started after the transport's EventLoop blocked SIGTERM, so it is blocked
  // here too and the signal stays pending for the signalfd.
  std::thread reader([&] {
    while (!quit.load()) {
      pollfd pfd{.fd = p.theirs, .events = POLLIN, .revents = 0};
      if (poll(&pfd, 1, 10) <= 0) {
        continue;
      }
      while (const auto d = p.read_theirs()) {
        if (wanted(*d)) {
          seen = true;
          kill(getpid(), SIGTERM);
          return;
        }
      }
    }
  });
  bool timed_out = false;
  const auto limit = t.add_oneshot(2s, [&] {
    timed_out = true;
    t.stop();
  });
  t.run(h);
  quit = true;
  reader.join();
  t.cancel_timer(limit);
  // A SIGTERM sent after run() returned is still pending: take it before the
  // EventLoop's destructor unblocks the signal.
  sigset_t term;
  sigemptyset(&term);
  sigaddset(&term, SIGTERM);
  const timespec zero{};
  while (sigtimedwait(&term, nullptr, &zero) == SIGTERM) {
  }
  return seen.load() && !timed_out && t.stop_signal() == SIGTERM;
}

void check_icmp_echo() {
  Pair p;
  auto t = attach(p, options());
  const auto payload = bytes_of("backend_transport_check echo payload");
  std::vector<std::byte> icmp(wire::icmp_header_len + payload.size());
  std::ranges::copy(payload, icmp.begin() + wire::icmp_header_len);
  wire::write_icmp(icmp, wire::icmp_echo_header(wire::icmp_echo_request, 0x1234, 7));
  const bool wrote = p.write_theirs(ipv4_datagram(kernel_addr, stack_addr, utcp::ip_proto_icmp, icmp));
  Recorder h;
  h.t = t.get();
  const bool got = run_until_datagram(*t, p, h, [&](std::span<const std::byte> d) {
    const auto ip = wire::parse_ipv4(d);
    if (!ip || ip->h.proto != utcp::ip_proto_icmp) {
      return false;
    }
    const auto m = wire::parse_icmp(ip->payload, true);
    return m && m->h.type == wire::icmp_echo_reply && m->h.echo_id() == 0x1234 &&
           m->h.echo_seq() == 7 && ip->h.src == stack_addr && ip->h.dst == kernel_addr &&
           std::ranges::equal(m->body, payload);
  });
  expect(wrote && got, "icmp_echo",
         "echo request id 0x1234 seq 7 answered with the same payload, without a periodic "
         "wake-up");
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
  Recorder h;
  h.t = t.get();
  h.echo_udp = true;
  const bool got = run_until_datagram(*t, p, h, [&](std::span<const std::byte> d) {
    const auto ip = wire::parse_ipv4(d);
    if (!ip || ip->h.proto != utcp::ip_proto_udp) {
      return false;
    }
    const auto u = wire::parse_udp(ip->payload, ip->h.src, ip->h.dst, true);
    return u && u->h.sport == 7 && u->h.dport == 5555 && ip->h.dst == kernel_addr &&
           std::ranges::equal(u->payload, payload);
  });
  expect(wrote && got && h.udp_echoed == 1, "udp_echo",
         std::format("datagram echoed by the Handler ({} sends), without a periodic wake-up",
                     h.udp_echoed));
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

// The stack's PMTU-expiry timer events (TraceKind::timer).
struct PmtuTimerTrace final : utcp::TraceSink {
  std::vector<Time> armed, fired;
  void on_event(const utcp::TraceEvent& e) override {
    if (e.kind != utcp::TraceKind::timer || e.timer != utcp::TraceTimer::pmtu_expiry) {
      return;
    }
    if (e.timer_op == utcp::TimerOp::armed) {
      armed.push_back(e.t);
    } else if (e.timer_op == utcp::TimerOp::fired) {
      fired.push_back(e.t);
    }
  }
};

// ICMP 3/4 (next-hop MTU `mtu`) from the kernel side, quoting a 1500-byte DF
// UDP datagram stack:sport -> dst:dport.
std::vector<std::byte> frag_needed_from_kernel(Ipv4Addr dst, std::uint16_t sport,
                                               std::uint16_t dport, std::uint16_t mtu) {
  std::vector<std::byte> icmp(wire::icmp_header_len + wire::ipv4_header_len + wire::udp_header_len);
  const std::span<std::byte> quote = std::span(icmp).subspan(wire::icmp_header_len);
  wire::write_ipv4(quote, wire::Ipv4Header{.ttl = 64,
                                           .proto = utcp::ip_proto_udp,
                                           .total_len = 1500,
                                           .id = 0,
                                           .df = true,
                                           .src = stack_addr,
                                           .dst = dst});
  wire::write_udp_header(quote.subspan(wire::ipv4_header_len),
                         wire::UdpHeader{.sport = sport, .dport = dport, .len = 1480});
  wire::write_icmp(icmp, wire::icmp_unreach_header(wire::icmp_frag_needed, mtu));
  return ipv4_datagram(kernel_addr, stack_addr, utcp::ip_proto_icmp, icmp);
}

std::vector<std::byte> echo_reply_from_kernel(std::uint16_t id, std::uint16_t seq) {
  std::vector<std::byte> icmp(wire::icmp_header_len + 16);
  wire::write_icmp(icmp, wire::icmp_echo_header(wire::icmp_echo_reply, id, seq));
  return ipv4_datagram(kernel_addr, stack_addr, utcp::ip_proto_icmp, icmp);
}

// §8.2, with the m1-ip Stack: an ICMP frag-needed creates a PMTU cache entry
// that expires 20 ms later (tcp.pmtu_expiry), i.e. a stack timer. An app
// timer 5 ms into the run writes two echo replies to the device and then
// keeps the loop busy until 5 ms past the expiry, so the next wake-up finds
// both the passed timer and a readable batch. The timer must fire before the
// batch is received (the readable callback starts with advance(mono_now())),
// and the two replies must get different receive times (EchoReply::t; one
// mono_now() per datagram).
void check_rx_clock() {
  Pair p;
  PmtuTimerTrace trace;  // outlives the transport
  UtcpTransportOptions o = options();
  o.stack.tcp.pmtu_expiry = 20ms;
  o.stack.trace_mask = utcp::trace_bit(utcp::TraceKind::timer);
  auto t = attach(p, o);
  t->stack().set_trace_sink(&trace);
  const Ipv4Addr far_host = Ipv4Addr::from_octets(198, 19, 3, 4);
  if (const auto sock = t->udp_open(utcp::Endpoint{stack_addr, 9200}); !sock) {
    expect(false, "rx_clock", std::format("udp_open: {}", utcp::to_string(sock.error())));
    return;
  }
  if (!p.write_theirs(frag_needed_from_kernel(far_host, 9200, 9201, 1400))) {
    expect(false, "rx_clock", "write to the socketpair failed");
    return;
  }
  bool wrote = false, timed_out = false;
  t->add_oneshot(5ms, [&] {
    if (trace.armed.empty()) {
      t->stop();  // the frag-needed created no PMTU entry: reported below
      return;
    }
    wrote = p.write_theirs(echo_reply_from_kernel(0x5151, 1)) &&
            p.write_theirs(echo_reply_from_kernel(0x5151, 2));
    const Time until = trace.armed.front() + 20ms + 5ms;
    for (Time now = utcp::mono_now(); now < until; now = utcp::mono_now()) {
      std::this_thread::sleep_for(until - now);
    }
    t->add_oneshot(5ms, [&] { t->stop(); });
  });
  t->add_oneshot(2s, [&] {
    timed_out = true;
    t->stop();
  });
  Recorder h;
  h.t = t.get();
  t->run(h);
  t->stack().set_trace_sink(nullptr);
  std::vector<utcp::EchoReply> replies;
  while (const auto r = t->stack().poll_echo_reply()) {
    replies.push_back(*r);
  }
  if (trace.armed.empty() || timed_out || !wrote || replies.size() != 2) {
    expect(false, "rx_clock",
           std::format("setup: PMTU timer armed {} times, replies written {}, {} echo replies "
                       "received (want 2), timed out {}",
                       trace.armed.size(), wrote, replies.size(), timed_out));
    return;
  }
  const Time expiry = trace.armed.front() + 20ms;
  const Time r1 = replies[0].t, r2 = replies[1].t;
  expect(r1 < r2, "rx_clock",
         std::format("receive times of the two datagrams of one batch: +{} ns apart (want > 0)",
                     (r2 - r1).count()));
  const bool fired_first = !trace.fired.empty() && trace.fired.front() >= expiry &&
                           trace.fired.front() <= r1;
  expect(fired_first, "rx_clock",
         trace.fired.empty()
             ? std::string("the PMTU-expiry timer never fired")
             : std::format("the PMTU-expiry timer, due {} us before the batch was received, "
                           "fired {} ns before its first datagram (want >= 0)",
                           (r1 - expiry).count() / 1000, (r1 - trace.fired.front()).count()));
}

// Transport calls made outside run() drain the transmit queue on every
// return path (utcp_transport.hpp). An echo request queued with
// Stack::icmp_echo (not a Transport call, so nothing drains it) must be on
// the device as soon as udp_open, listen and a connect that fails return.
void check_outside_run_drain() {
  Pair p;
  auto t = attach(p, options());
  std::uint16_t seq = 0;
  const auto drained_by = [&](std::string_view call, const std::function<std::string()>& f) {
    ++seq;
    const auto payload = bytes_of("queued before the call");
    if (!t->stack().icmp_echo(kernel_addr, 0x6262, seq, payload)) {
      expect(false, "outside_run_drain", "icmp_echo failed");
      return;
    }
    const std::string result = f();
    bool found = false;
    while (const auto d = p.read_theirs()) {
      const auto ip = wire::parse_ipv4(*d);
      if (!ip || ip->h.proto != utcp::ip_proto_icmp) {
        continue;
      }
      const auto m = wire::parse_icmp(ip->payload, true);
      found = found || (m && m->h.type == wire::icmp_echo_request &&
                        m->h.echo_id() == 0x6262 && m->h.echo_seq() == seq);
    }
    expect(found, "outside_run_drain",
           std::format("{} ({}): the queued echo request {} on the device when it returned", call,
                       result, found ? "is" : "is NOT"));
  };
  const auto outcome = [](const auto& r) {
    return r ? std::string("succeeded") : std::format("failed: {}", utcp::to_string(r.error()));
  };
  drained_by("udp_open", [&] { return outcome(t->udp_open(utcp::Endpoint{stack_addr, 9300})); });
  drained_by("listen",
             [&] { return outcome(t->listen(utcp::Endpoint{stack_addr, 9301}, 8, {})); });
  drained_by("connect to 0.0.0.0:0",
             [&] { return outcome(t->connect(utcp::Endpoint{Ipv4Addr{}, 0}, {})); });
}

std::vector<std::byte> tcp_from_kernel(std::uint16_t sport, std::uint16_t dport, std::uint32_t seq,
                                       std::uint32_t ack, std::uint16_t flags) {
  wire::TcpOptions opt;
  const bool syn = (flags & wire::tcp_syn) != 0;
  if (syn) {
    opt.mss = 1460;
  }
  std::vector<std::byte> l4(wire::tcp_header_len(opt, syn));
  wire::write_tcp_header(l4,
                         wire::TcpHeader{.sport = sport,
                                         .dport = dport,
                                         .seq = utcp::Seq32(seq),
                                         .ack = utcp::Seq32(ack),
                                         .window = 65535,
                                         .flags = flags},
                         opt, syn);
  wire::set_l4_checksum(l4, kernel_addr, stack_addr, utcp::ip_proto_tcp);
  return ipv4_datagram(kernel_addr, stack_addr, utcp::ip_proto_tcp, l4);
}

// The TCP segments the transport wrote to the device since the last call.
std::vector<wire::TcpHeader> tcp_from_stack(const Pair& p) {
  std::vector<wire::TcpHeader> out;
  while (const auto d = p.read_theirs()) {
    const auto ip = wire::parse_ipv4(*d);
    if (!ip || ip->h.proto != utcp::ip_proto_tcp) {
      continue;
    }
    if (const auto t = wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true)) {
      out.push_back(t->h);
    }
  }
  return out;
}

// Force later ingress for an established flow through the other fd. Its
// server replies, including the ACK to FIN, must continue using its SYN-ACK
// queue. Also hold a packet on queue 1 under write backpressure.
void check_multiqueue() {
  std::array<Pair, 2> pairs;
  const int small = 4096;
  if (setsockopt(pairs[1].ours, SOL_SOCKET, SO_SNDBUF, &small, sizeof small) != 0) {
    expect(false, "multiqueue", "cannot reduce queue 1 send buffer");
    return;
  }
  // Keep a writer for test setup only. This is the same socket and buffer as
  // queue 1, not a third queue in the transport.
  const int fill_fd = dup(pairs[1].ours);
  if (fill_fd < 0) {
    expect(false, "multiqueue", "dup failed");
    return;
  }
  auto opened = UtcpTransport::attach_queues({pairs[0].give(), pairs[1].give()}, options());
  if (!opened) {
    close(fill_fd);
    expect(false, "multiqueue", opened.error());
    return;
  }
  auto& transport = **opened;
  constexpr std::uint16_t listen_port = 9600;
  constexpr std::uint16_t first_port = 41000;
  constexpr std::uint32_t peer_isn = 1000;
  constexpr std::size_t flows = 8;
  const auto listen = transport.listen(utcp::Endpoint{stack_addr, listen_port}, 16, {});
  if (!listen) {
    close(fill_fd);
    expect(false, "multiqueue", "listen failed");
    return;
  }
  struct Receiver final : utcp::app::Handler {
    ConnId selected = utcp::app::no_conn;
    std::size_t accepted = 0;
    void on_accept(ConnId, ConnId conn) override {
      ++accepted;
      selected = conn;
    }
  } h;

  bool valid = true;
  for (std::size_t i = 0; i < flows; ++i) {
    const auto port = static_cast<std::uint16_t>(first_port + i);
    valid &= pairs[0].write_theirs(tcp_from_kernel(port, listen_port, peer_isn, 0, wire::tcp_syn));
  }

  struct Placement {
    std::size_t queue = 0;
    std::uint32_t isn = 0;
    bool seen = false;
  };
  std::array<Placement, flows> initial{};
  std::size_t seen = 0;
  run_until(transport, h, [&] {
    for (std::size_t q = 0; q < pairs.size(); ++q) {
      for (const auto& tcp : tcp_from_stack(pairs[q])) {
        const auto slot = static_cast<std::size_t>(tcp.dport - first_port);
        if (slot >= flows || initial[slot].seen || tcp.sport != listen_port ||
            tcp.flags != (wire::tcp_syn | wire::tcp_ack)) {
          valid = false;
          continue;
        }
        initial[slot] = Placement{q, tcp.seq.raw(), true};
        ++seen;
      }
    }
  }, [&] { return seen == flows; });
  const auto chosen = std::ranges::find_if(initial, [](const Placement& p) {
    return p.seen && p.queue == 1;
  });
  const bool uses_first = std::ranges::any_of(initial, [](const Placement& p) {
    return p.seen && p.queue == 0;
  });
  if (!valid || seen != flows || chosen == initial.end() || !uses_first) {
    close(fill_fd);
    expect(false, "multiqueue", "SYN-ACKs must reach both queues");
    return;
  }
  const auto peer_port = static_cast<std::uint16_t>(first_port + (chosen - initial.begin()));
  // The SYN came through queue 0. Complete the handshake through queue 1.
  valid &= pairs[1].write_theirs(tcp_from_kernel(
      peer_port, listen_port, peer_isn + 1, chosen->isn + 1, wire::tcp_ack));
  run_until(transport, h, [] {}, [&] { return h.accepted == 1; });
  if (!valid || h.accepted != 1) {
    close(fill_fd);
    expect(false, "multiqueue", "connection did not establish from queue 1");
    return;
  }

  // Fill the selected FD with sentinel datagrams. There is room on queue 0.
  // The application sends real TCP data on the established flow below.
  const auto marker = bytes_of("filtered test buffer marker");
  const ssize_t marker_size = static_cast<ssize_t>(marker.size());
  while (write(fill_fd, marker.data(), marker.size()) == marker_size) {}
  const bool full = errno == EAGAIN || errno == EWOULDBLOCK;
  close(fill_fd);
  const auto payload = bytes_of("connection data after EAGAIN");
  const auto sent = transport.send(h.selected, payload);
  const auto before = transport.device_stats().tx_eagain;
  const bool other_empty = !pairs[0].read_theirs();
  bool received = false;
  std::size_t wrong_queue = 0;
  run_until(transport, h, [&] {
    // Removing the markers makes the original fd writable. Check the real
    // data packet separately from the test-only buffer fill.
    while (const auto d = pairs[1].read_theirs()) {
      if (*d == marker) continue;
      const auto ip = wire::parse_ipv4(*d);
      if (!ip) { valid = false; continue; }
      const auto tcp = wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
      valid &= tcp && tcp->h.dport == peer_port && tcp->h.seq.raw() == chosen->isn + 1 &&
               std::ranges::equal(tcp->payload, payload) && !received;
      received = true;
    }
    wrong_queue += tcp_from_stack(pairs[0]).size();
  }, [&] { return received; });
  expect(full && sent && *sent == payload.size() && before > 0 && received &&
             valid && other_empty && wrong_queue == 0 && transport.device_stats().tx_errors == 0,
         "multiqueue", "flow used the original queue after EAGAIN");
  if (!received || !valid) return;

  valid &= pairs[0].write_theirs(tcp_from_kernel(peer_port, listen_port, peer_isn + 1,
      chosen->isn + 1 + static_cast<std::uint32_t>(payload.size()), wire::tcp_fin | wire::tcp_ack));
  bool acked = false;
  run_until(transport, h, [&] {
    for (const auto& tcp : tcp_from_stack(pairs[1])) {
      acked |= tcp.dport == peer_port && tcp.ack.raw() == peer_isn + 2 &&
               (tcp.flags & wire::tcp_ack) != 0;
    }
    wrong_queue += tcp_from_stack(pairs[0]).size();
  }, [&] { return acked; });
  expect(valid && acked && wrong_queue == 0, "multiqueue",
         "the same flow processed FIN on its alternate ingress queue");

  const auto udp = transport.udp_open(utcp::Endpoint{stack_addr, 9601});
  const bool udp_sent = udp && transport.send_to(*udp, utcp::Endpoint{kernel_addr, 9602}, payload);
  const auto d = pairs[0].read_theirs();
  const auto ip = d ? wire::parse_ipv4(*d) : std::unexpected(wire::ParseError::truncated);
  expect(udp_sent && ip && ip->h.proto == utcp::ip_proto_udp && !pairs[1].read_theirs(),
         "multiqueue", "non-TCP datagram used queue 0");
}

// Interop case E-chunked: utcp-http-get closed after a chunked body and
// exited before the server's FIN (0.15 ms later) arrived, so the server
// retransmitted its FIN to a stack that was gone. The kernel's end here
// opens a connection to a listener, the program closes it and stops, and the
// kernel's FIN reaches the device only after run() returned.
void check_finish_closing() {
  Pair p;
  auto t = attach(p, options());
  constexpr std::uint16_t port = 9400, kport = 40000;
  constexpr std::uint32_t kiss = 1000;
  const auto l = t->listen(utcp::Endpoint{stack_addr, port}, 8, {});
  if (!l) {
    expect(false, "finish_closing", "listen failed");
    return;
  }
  struct Closer final : utcp::app::Handler {
    UtcpTransport* t = nullptr;
    ConnId listener = utcp::app::no_conn;
    bool accepted = false;
    void on_accept(ConnId, ConnId conn) override {
      accepted = true;
      t->close(conn);  // FIN
      t->close(listener);
      t->stop();
    }
  } h;
  h.t = t.get();
  h.listener = *l;
  const auto run_for = [&](std::chrono::milliseconds limit) {
    const auto stop = t->add_oneshot(limit, [&] { t->stop(); });
    t->run(h);
    t->cancel_timer(stop);
  };
  (void)p.write_theirs(tcp_from_kernel(kport, port, kiss, 0, wire::tcp_syn));
  run_for(200ms);
  const auto synack = tcp_from_stack(p);
  if (synack.size() != 1 || synack[0].flags != (wire::tcp_syn | wire::tcp_ack)) {
    expect(false, "finish_closing", std::format("{} segments, no SYN-ACK", synack.size()));
    return;
  }
  const std::uint32_t iss = synack[0].seq.raw();
  (void)p.write_theirs(tcp_from_kernel(kport, port, kiss + 1, iss + 1, wire::tcp_ack));
  run_for(2000ms);
  const auto fin = tcp_from_stack(p);
  const bool fin_ok = h.accepted && fin.size() == 1 && (fin[0].flags & wire::tcp_fin) != 0 &&
                      fin[0].seq.raw() == iss + 1;
  expect(fin_ok, "finish_closing",
         std::format("accepted {}, then {} segment(s), the first a FIN at ISS+1: {}", h.accepted,
                     fin.size(), fin_ok));
  if (!fin_ok) {
    return;
  }
  // The kernel's FIN, ACKing ours, after run() returned; the same FIN again
  // 200 ms later (the kernel did not get the ACK).
  const auto kernel_fin = tcp_from_kernel(kport, port, kiss + 1, iss + 2, wire::tcp_fin | wire::tcp_ack);
  (void)p.write_theirs(kernel_fin);
  std::size_t acks_before_resend = 0;
  (void)t->add_oneshot(200ms, [&] {
    acks_before_resend = tcp_from_stack(p).size();
    (void)p.write_theirs(kernel_fin);
  });
  const Time t0 = utcp::mono_now();
  t->finish_closing(600ms);
  const auto took = utcp::mono_now() - t0;
  const auto acks = tcp_from_stack(p);
  const bool acked = acks_before_resend == 1;
  const bool reacked = acks.size() == 1 && acks[0].flags == wire::tcp_ack &&
                       acks[0].ack.raw() == kiss + 2 && acks[0].seq.raw() == iss + 2;
  const auto u = t->stack().debug_usage();
  expect(acked && reacked && took >= 590ms && took < 1000ms && u.tcp_slots == 0 &&
             u.time_wait_entries == 1,
         "finish_closing",
         std::format("the peer's FIN {} ({} segments in 200 ms), its retransmission {} ({} "
                     "segments), returned after {} us (limit 600 ms), tcp_slots {}, "
                     "time_wait_entries {}",
                     acked ? "ACKed" : "NOT ACKed", acks_before_resend,
                     reacked ? "ACKed again" : "NOT ACKed", acks.size(), took.count() / 1000,
                     u.tcp_slots, u.time_wait_entries));
}

// open() on an interface that does not exist fails at once: TUNSETIFF would
// create a new interface that never comes up, and open() would wait 1 s for it.
void check_open_missing() {
  UtcpTransportOptions o = options();
  o.tun = std::format("utcpnx{}", getpid() % 100000);
  const std::filesystem::path sys = "/sys/class/net/" + o.tun;
  if (std::filesystem::exists(sys)) {
    expect(false, "open_missing", std::format("{} exists", sys.string()));
    return;
  }
  const Time t0 = utcp::mono_now();
  const auto r = UtcpTransport::open(o);
  const auto took = utcp::mono_now() - t0;
  expect(!r && r.error().find("does not exist") != std::string::npos && took < 100ms,
         "open_missing",
         std::format("{} after {} us", r ? "open succeeded" : r.error(), took.count() / 1000));
  expect(!std::filesystem::exists(sys), "open_missing", std::format("{} not created", o.tun));
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
  check_timers_and_rerun(false);
  check_timers_and_rerun(true);
  check_timer_ties();
  check_device_rx_pcap(*args->get("tmp"));
  check_stats_file(*args->get("tmp"));
  check_signal();
  check_device_hup();
  check_open_missing();
  if (args->flag("expect-stack")) {
    check_icmp_echo();
    check_udp_echo();
    check_tx_eagain();
    check_multiqueue();
    check_rx_clock();
    check_outside_run_drain();
    check_finish_closing();
  }
  if (const auto tun = args->get("tun")) {
    check_open_tun(*tun);
  }
  std::println("{} check(s) failed", failures);
  return failures == 0 ? 0 : 1;
}
