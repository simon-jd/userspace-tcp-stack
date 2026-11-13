// backend_tun_tool: writes one hand-built IPv4 datagram into the testbed's
// TUN interface, as the stack would, and waits for the answer. Used by
// tests/interop/backend_testbed.sh where no stack exists yet (M0's tun_probe
// only answers pings).
//
//   df  --dst IP [--size N]: a UDP datagram of N bytes (IPv4 total length,
//       default 1500) with DF set, to port 9 of IP. Waits for an ICMP
//       destination unreachable code 4 (RFC 1191 §4) that quotes it and
//       prints its source and next-hop MTU. Exit 0 if one arrived.
//   dns --server IP [--name NAME]: a DNS query for the A records of NAME
//       (RFC 1035 §4.1), over UDP to port 53 of IP. Prints the response's
//       rcode and A records. Exit 0 if a response with rcode 0 arrived.
//
// The interface must exist (testbed/m1/up.sh creates utcp0 persistent); the
// tool attaches to it with IFF_TUN|IFF_NO_PI and waits until it is running
// (TunDevice::wait_running) before writing. Other packets read meanwhile are
// printed and skipped.
#include <poll.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/cli.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/udp.hpp"
#include "utcp/checksum.hpp"
#include "utcp/event_loop.hpp"
#include "utcp/tun_device.hpp"

namespace {

using utcp::Ipv4Addr;
namespace wire = utcp::wire;

constexpr std::uint16_t src_port = 40001;
constexpr std::uint16_t dns_id = 0x7a31;

std::string ip_str(Ipv4Addr a) {
  return std::format("{}.{}.{}.{}", a.octet(0), a.octet(1), a.octet(2), a.octet(3));
}

// A UDP datagram from src:src_port to dst:dport with `payload`, IPv4 total
// length 28 + payload size.
std::vector<std::byte> udp_datagram(Ipv4Addr src, Ipv4Addr dst, std::uint16_t dport,
                                    std::span<const std::byte> payload, bool df) {
  const std::size_t total = wire::ipv4_header_len + wire::udp_header_len + payload.size();
  std::vector<std::byte> d(total);
  const std::span<std::byte> s(d);
  const std::span<std::byte> l4 = s.subspan(wire::ipv4_header_len);
  std::memcpy(l4.data() + wire::udp_header_len, payload.data(), payload.size());
  wire::write_udp_header(l4, wire::UdpHeader{.sport = src_port,
                                             .dport = dport,
                                             .len = static_cast<std::uint16_t>(l4.size())});
  wire::set_l4_checksum(l4, src, dst, utcp::ip_proto_udp);
  wire::write_ipv4(s, wire::Ipv4Header{.ttl = 64,
                                       .proto = utcp::ip_proto_udp,
                                       .total_len = static_cast<std::uint16_t>(total),
                                       .id = 0x4d31,
                                       .df = df,
                                       .src = src,
                                       .dst = dst});
  return d;
}

// RFC 1035 §4.1: header (id, RD), one question (QNAME, QTYPE A, QCLASS IN).
std::optional<std::vector<std::byte>> dns_query(std::string_view name) {
  std::vector<std::byte> q;
  const auto put16 = [&q](std::uint16_t v) {
    q.push_back(static_cast<std::byte>(v >> 8));
    q.push_back(static_cast<std::byte>(v & 0xff));
  };
  put16(dns_id);
  put16(0x0100);  // RD
  put16(1);       // QDCOUNT
  put16(0);
  put16(0);
  put16(0);
  while (!name.empty()) {
    const std::size_t dot = name.find('.');
    const std::string_view label = name.substr(0, dot);
    if (label.empty() || label.size() > 63) {
      return std::nullopt;
    }
    q.push_back(static_cast<std::byte>(label.size()));
    for (const char c : label) {
      q.push_back(static_cast<std::byte>(c));
    }
    name = dot == std::string_view::npos ? std::string_view{} : name.substr(dot + 1);
  }
  q.push_back(std::byte{0});
  put16(1);  // A
  put16(1);  // IN
  return q;
}

// Skips a (possibly compressed) name at `at`; the offset after it, or nullopt.
std::optional<std::size_t> skip_name(std::span<const std::byte> m, std::size_t at) {
  while (at < m.size()) {
    const std::uint8_t len = wire::load_u8(m, at);
    if ((len & 0xc0) == 0xc0) {
      return at + 2 <= m.size() ? std::optional(at + 2) : std::nullopt;
    }
    if (len == 0) {
      return at + 1;
    }
    at += 1 + len;
  }
  return std::nullopt;
}

// Prints the response; true if it is ours with rcode 0.
bool print_dns_response(std::span<const std::byte> m) {
  if (m.size() < 12 || wire::load_be16(m, 0) != dns_id) {
    std::println("  not our DNS response");
    return false;
  }
  const std::uint16_t flags = wire::load_be16(m, 2);
  const unsigned rcode = flags & 0xfu;
  const std::uint16_t qd = wire::load_be16(m, 4);
  const std::uint16_t an = wire::load_be16(m, 6);
  std::println("  DNS response: QR {} rcode {} questions {} answers {}", (flags >> 15) & 1u,
               rcode, qd, an);
  std::optional<std::size_t> at = 12;
  for (std::uint16_t i = 0; i < qd && at; ++i) {
    at = skip_name(m, *at);
    if (at) {
      *at += 4;
    }
  }
  for (std::uint16_t i = 0; i < an && at; ++i) {
    at = skip_name(m, *at);
    if (!at || *at + 10 > m.size()) {
      break;
    }
    const std::uint16_t type = wire::load_be16(m, *at);
    const std::uint16_t rdlen = wire::load_be16(m, *at + 8);
    const std::size_t rdata = *at + 10;
    if (rdata + rdlen > m.size()) {
      break;
    }
    if (type == 1 && rdlen == 4) {
      std::println("  A {}", ip_str(Ipv4Addr{wire::load_be32(m, rdata)}));
    }
    at = rdata + rdlen;
  }
  return (flags >> 15) == 1 && rcode == 0;
}

enum class Verdict { skip, done, fail };

int run(const utcp::TunDevice& tun, std::span<const std::byte> out, int timeout_ms,
        const auto& on_packet) {
  if (auto w = tun.write(out); !w) {
    std::println(stderr, "write to {}: {}", tun.name(), w.error().message());
    return 1;
  }
  std::println("wrote {} bytes to {}", out.size(), tun.name());
  const utcp::Time deadline = utcp::mono_now() + std::chrono::milliseconds{timeout_ms};
  std::array<std::byte, 65536> buf{};
  for (;;) {
    const auto left = (deadline - utcp::mono_now()).count() / 1'000'000;
    if (left <= 0) {
      std::println("timed out after {} ms", timeout_ms);
      return 1;
    }
    pollfd p{.fd = tun.fd(), .events = POLLIN, .revents = 0};
    if (::poll(&p, 1, static_cast<int>(left)) <= 0) {
      continue;
    }
    const auto n = tun.read(buf);
    if (!n) {
      if (n.error() == std::errc::resource_unavailable_try_again) {
        continue;
      }
      std::println(stderr, "read from {}: {}", tun.name(), n.error().message());
      return 1;
    }
    const std::span<const std::byte> pkt(buf.data(), *n);
    const auto ip = wire::parse_ipv4(pkt);
    if (!ip) {
      std::println("read {} bytes: not a valid IPv4 datagram ({}), skipped", *n,
                   wire::to_string(ip.error()));
      continue;
    }
    std::print("read {} bytes: {} -> {} proto {}", *n, ip_str(ip->h.src), ip_str(ip->h.dst),
               ip->h.proto);
    switch (on_packet(*ip)) {
      case Verdict::skip: std::println(", skipped"); break;
      case Verdict::done: return 0;
      case Verdict::fail: return 1;
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::setvbuf(stdout, nullptr, _IOLBF, 0);
  utcp::app::CliParser cli("backend_tun_tool",
                           "Writes one datagram into a TUN interface and waits for the answer.");
  cli.option("tun", "IFNAME", "TUN interface (exists already)", "utcp0")
      .option("src", "IP", "source address of the datagram (the stack's)", "198.18.0.2")
      .option("dst", "IP", "df: destination")
      .option("size", "N", "df: IPv4 total length", "1500")
      .option("server", "IP", "dns: resolver")
      .option("name", "NAME", "dns: name to resolve", "example.com")
      .option("timeout-ms", "MS", "how long to wait for the answer", "3000")
      .positional("MODE", "df or dns");
  const auto args = cli.parse(argc, argv);
  if (!args || args->help()) {
    std::println(stderr, "{}{}", args ? "" : args.error() + "\n", cli.usage());
    return args ? 0 : 2;
  }
  const auto bad = [&](std::string_view msg) {
    std::println(stderr, "backend_tun_tool: {}", msg);
    return 2;
  };
  const auto src = utcp::app::parse_ipv4(*args->get("src"));
  const auto timeout = utcp::app::parse_u64(*args->get("timeout-ms"));
  if (!src || !timeout || *timeout > 600'000) {
    return bad("bad --src or --timeout-ms");
  }
  auto tun = utcp::TunDevice::open(*args->get("tun"), /*nonblocking=*/true);
  if (!tun) {
    return bad(std::format("cannot attach to {}: {}", *args->get("tun"), tun.error().message()));
  }
  if (!tun->wait_running(std::chrono::seconds{2})) {
    return bad(std::format("{} is not running (operstate \"{}\")", tun->name(), tun->operstate()));
  }
  const int timeout_ms = static_cast<int>(*timeout);
  const std::string mode = args->positionals().at(0);

  if (mode == "df") {
    const auto dst = args->get("dst") ? utcp::app::parse_ipv4(*args->get("dst"))
                                      : std::unexpected(std::string("missing"));
    const auto size = utcp::app::parse_u64(*args->get("size"));
    if (!dst || !size || *size < 28 || *size > 65535) {
      return bad("df needs --dst IP and a --size in [28, 65535]");
    }
    const std::vector<std::byte> payload(*size - 28);
    const auto d = udp_datagram(*src, *dst, 9, payload, /*df=*/true);
    std::println("df: UDP {}:{} -> {}:9, IPv4 total length {}, DF", ip_str(*src), src_port,
                 ip_str(*dst), d.size());
    return run(*tun, d, timeout_ms, [&](const wire::Ipv4View& ip) {
      if (ip.h.proto != utcp::ip_proto_icmp) {
        return Verdict::skip;
      }
      const auto icmp = wire::parse_icmp(ip.payload, /*verify_csum=*/true);
      if (!icmp) {
        std::print(", ICMP {}", wire::to_string(icmp.error()));
        return Verdict::skip;
      }
      std::print(", ICMP type {} code {}", icmp->h.type, icmp->h.code);
      if (icmp->h.type != wire::icmp_dest_unreach || icmp->h.code != wire::icmp_frag_needed) {
        return Verdict::skip;
      }
      const auto q = wire::parse_icmp_quote(icmp->body);
      if (!q || q->ip.src != *src || q->ip.dst != *dst || q->ip.proto != utcp::ip_proto_udp ||
          wire::load_be16(q->l4, 0) != src_port) {
        std::print(" (quotes another datagram)");
        return Verdict::skip;
      }
      std::println(" (fragmentation needed) from {}: next-hop MTU {}, quotes {} -> {} total "
                   "length {} DF {}",
                   ip_str(ip.h.src), icmp->h.next_hop_mtu(), ip_str(q->ip.src),
                   ip_str(q->ip.dst), q->ip.total_len, q->ip.df ? 1 : 0);
      return Verdict::done;
    });
  }
  if (mode == "dns") {
    const auto server = args->get("server") ? utcp::app::parse_ipv4(*args->get("server"))
                                            : std::unexpected(std::string("missing"));
    const auto q = dns_query(*args->get("name"));
    if (!server || !q) {
      return bad("dns needs --server IP and a valid --name");
    }
    const auto d = udp_datagram(*src, *server, 53, *q, /*df=*/false);
    std::println("dns: A {} from {}:{} to {}:53", *args->get("name"), ip_str(*src), src_port,
                 ip_str(*server));
    return run(*tun, d, timeout_ms, [&](const wire::Ipv4View& ip) {
      if (ip.h.proto != utcp::ip_proto_udp || ip.h.src != *server) {
        return Verdict::skip;
      }
      const auto u = wire::parse_udp(ip.payload, ip.h.src, ip.h.dst, /*verify_csum=*/true);
      if (!u || u->h.sport != 53 || u->h.dport != src_port) {
        return Verdict::skip;
      }
      std::println(", UDP {} -> {}, {} bytes", u->h.sport, u->h.dport, u->payload.size());
      return print_dns_response(u->payload) ? Verdict::done : Verdict::fail;
    });
  }
  return bad("MODE is df or dns");
}
