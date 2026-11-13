// backend_udp_echo: a UDP echo server on UtcpTransport (m1-backend test 7).
// Attaches the stack to the testbed's TUN interface (address --addr), opens
// a UDP socket on --port and sends every datagram back to its sender. The
// stack answers pings by itself. Runs until --count datagrams were echoed
// (0: no limit), SIGINT or SIGTERM, then prints one JSON summary line: echo
// counts, the stack's non-zero counters, the device counters and the loop's
// wake-up lateness.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <format>
#include <print>
#include <span>
#include <string>
#include <string_view>

#include "common/cli.hpp"
#include "common/utcp_transport.hpp"

namespace {

using utcp::app::ConnId;
using utcp::app::UtcpTransport;

std::string ip_str(utcp::Ipv4Addr a) {
  return std::format("{}.{}.{}.{}", a.octet(0), a.octet(1), a.octet(2), a.octet(3));
}

class Echo final : public utcp::app::Handler {
public:
  Echo(UtcpTransport& t, std::uint64_t limit) : t_(t), limit_(limit) {}

  void on_readable(ConnId id) override {
    for (;;) {
      const auto r = t_.recv_from(id, buf_);
      if (!r) {
        if (r.error() != utcp::Error::would_block) {
          ++recv_errors;
        }
        return;
      }
      ++received;
      truncated += r->truncated ? 1 : 0;
      const std::span<const std::byte> data(buf_.data(), std::min(r->len, buf_.size()));
      if (const auto s = t_.send_to(id, r->from, data); s) {
        ++echoed;
        bytes += data.size();
      } else {
        ++send_errors;
        last_send_error = std::string(utcp::to_string(s.error()));
      }
      if (limit_ != 0 && echoed >= limit_) {
        t_.stop();
        return;
      }
    }
  }

  std::uint64_t received = 0, echoed = 0, bytes = 0, truncated = 0;
  std::uint64_t recv_errors = 0, send_errors = 0;
  std::string last_send_error;

private:
  UtcpTransport& t_;
  std::uint64_t limit_;
  std::array<std::byte, 65536> buf_{};
};

}  // namespace

int main(int argc, char** argv) {
  std::setvbuf(stdout, nullptr, _IOLBF, 0);
  utcp::app::CliParser cli("backend_udp_echo", "UDP echo server on UtcpTransport (TUN backend).");
  cli.option("tun", "IFNAME", "TUN interface", "utcp0")
      .option("addr", "IP", "the stack's address", "198.18.0.2")
      .option("mtu", "N", "the TUN interface's MTU (checked)", "1500")
      .option("port", "PORT", "UDP port", "7")
      .option("count", "N", "exit after echoing N datagrams (0: run until a signal)", "0")
      .option("pcap", "FILE", "record the datagrams that cross the TUN")
      .option("spin-us", "US", "busy-poll the last US microseconds before a deadline", "0");
  const auto args = cli.parse(argc, argv);
  if (!args || args->help()) {
    std::println(stderr, "{}{}", args ? "" : args.error() + "\n", cli.usage());
    return args ? 0 : 2;
  }
  const auto addr = utcp::app::parse_ipv4(*args->get("addr"));
  const auto mtu = utcp::app::parse_u64(*args->get("mtu"));
  const auto port = utcp::app::parse_port(*args->get("port"));
  const auto count = utcp::app::parse_u64(*args->get("count"));
  const auto spin = utcp::app::parse_u64(*args->get("spin-us"));
  if (!addr || !mtu || *mtu < 576 || *mtu > 65535 || !port || *port == 0 || !count || !spin ||
      *spin > 1'000'000) {
    std::println(stderr, "backend_udp_echo: bad --addr, --mtu, --port, --count or --spin-us");
    return 2;
  }

  utcp::app::UtcpTransportOptions o;
  o.stack.local_addr = *addr;
  o.stack.mtu = static_cast<std::uint16_t>(*mtu);
  o.tun = *args->get("tun");
  o.pcap_file = args->get("pcap").value_or("");
  o.spin_us = static_cast<std::uint32_t>(*spin);
  auto t = UtcpTransport::open(o);
  if (!t) {
    std::println(stderr, "backend_udp_echo: {}", t.error());
    return 1;
  }
  const auto sock = (*t)->udp_open(utcp::Endpoint{*addr, *port});
  if (!sock) {
    std::println(stderr, "backend_udp_echo: udp_open {}:{}: {}", ip_str(*addr), *port,
                 utcp::to_string(sock.error()));
    return 1;
  }
  std::println("listening on {}:{} ({}, mtu {})", ip_str(*addr), *port, o.tun, *mtu);

  Echo echo(**t, *count);
  (*t)->run(echo);
  (*t)->flush_pcap();

  std::string stats;
  utcp::for_each_stat((*t)->stack().stats(), [&stats](std::string_view name, std::uint64_t v) {
    if (v != 0) {
      stats += std::format("{}\"{}\":{}", stats.empty() ? "" : ",", name, v);
    }
  });
  const auto& d = (*t)->device_stats();
  const utcp::LoopStats& ls = *(*t)->loop_stats();
  std::println(
      "{{\"received\":{},\"echoed\":{},\"bytes\":{},\"truncated\":{},\"recv_errors\":{},"
      "\"send_errors\":{},\"last_send_error\":\"{}\",\"stop_signal\":{},"
      "\"stack\":{{{}}},"
      "\"device\":{{\"rx_datagrams\":{},\"rx_bytes\":{},\"tx_datagrams\":{},\"tx_bytes\":{},"
      "\"rx_errors\":{},\"tx_errors\":{},\"tx_eagain\":{},\"pcap_records\":{},"
      "\"pcap_failed\":{},\"device_failed\":{}}},"
      "\"loop\":{{\"iterations\":{},\"deadline_calls\":{},\"lateness_p50_ns\":{},"
      "\"lateness_p99_ns\":{},\"lateness_max_ns\":{}}}}}",
      echo.received, echo.echoed, echo.bytes, echo.truncated, echo.recv_errors, echo.send_errors,
      echo.last_send_error, (*t)->stop_signal(), stats, d.rx_datagrams, d.rx_bytes,
      d.tx_datagrams, d.tx_bytes, d.rx_errors, d.tx_errors, d.tx_eagain, d.pcap_records,
      d.pcap_failed, d.device_failed, ls.iterations, ls.deadline_calls,
      ls.lateness.percentile(0.5).count(), ls.lateness.percentile(0.99).count(),
      ls.lateness.max.count());
  return d.device_failed || d.pcap_failed ? 1 : 0;
}
