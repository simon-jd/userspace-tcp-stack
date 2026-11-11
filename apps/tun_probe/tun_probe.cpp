// tun_probe: creates a TUN interface (IFF_TUN | IFF_NO_PI), reads packets from
// its file descriptor and reports each one, checking the IPv4 header and ICMP
// checksums with utcp_core. With --reply it answers ICMP echo requests, so
// `ping` through the interface gets replies. Used by testbed/verify-env.sh.

#include "utcp/checksum.hpp"
#include "utcp/tun_device.hpp"

#include <poll.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct Options {
  std::string name = "utcp0";
  int count = 3;          // stop after this many echo requests
  int timeout_ms = 10000; // overall deadline
  bool reply = false;
  bool hex = false;
};

void usage() {
  std::println(stderr,
               "usage: tun_probe [--name IFNAME] [--count N] [--timeout-ms MS] [--reply] [--hex]\n"
               "Creates TUN interface IFNAME (IFF_TUN|IFF_NO_PI) and prints the packets read from\n"
               "it. Exits 0 after N ICMP echo requests, 1 if MS milliseconds pass first.");
}

bool parse_int(std::string_view s, int& out) {
  const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
  return ec == std::errc{} && ptr == s.data() + s.size() && out >= 0;
}

bool parse_args(int argc, char** argv, Options& o) {
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    const bool has_value = i + 1 < argc;
    if (a == "--name" && has_value) {
      o.name = argv[++i];
    } else if (a == "--count" && has_value) {
      if (!parse_int(argv[++i], o.count)) return false;
    } else if (a == "--timeout-ms" && has_value) {
      if (!parse_int(argv[++i], o.timeout_ms)) return false;
    } else if (a == "--reply") {
      o.reply = true;
    } else if (a == "--hex") {
      o.hex = true;
    } else {
      return false;
    }
  }
  return true;
}

std::uint16_t be16(std::span<const std::byte> p, std::size_t off) {
  return static_cast<std::uint16_t>((std::to_integer<unsigned>(p[off]) << 8) |
                                    std::to_integer<unsigned>(p[off + 1]));
}

std::uint32_t be32(std::span<const std::byte> p, std::size_t off) {
  return (std::uint32_t{be16(p, off)} << 16) | be16(p, off + 2);
}

void put_be16(std::span<std::byte> p, std::size_t off, std::uint16_t v) {
  p[off] = static_cast<std::byte>(v >> 8);
  p[off + 1] = static_cast<std::byte>(v & 0xFF);
}

std::string ipv4_str(std::uint32_t a) {
  return std::format("{}.{}.{}.{}", a >> 24, (a >> 16) & 0xFF, (a >> 8) & 0xFF, a & 0xFF);
}

std::string hex_str(std::span<const std::byte> p) {
  std::string s;
  s.reserve(p.size() * 2);
  for (const std::byte b : p) {
    s += std::format("{:02x}", std::to_integer<unsigned>(b));
  }
  return s;
}

constexpr std::uint8_t icmp_echo_reply = 0;
constexpr std::uint8_t icmp_echo_request = 8;

// Handles one packet. Returns true if it was an ICMP echo request with valid
// IPv4 header and ICMP checksums.
bool handle_packet(const utcp::TunDevice& tun, std::span<std::byte> pkt, const Options& o) {
  std::print("read {} bytes:", pkt.size());
  if (o.hex) {
    std::print(" hex={}", hex_str(pkt));
  }
  // RFC 791 section 3.1 header layout.
  if (pkt.size() < 20 || (std::to_integer<unsigned>(pkt[0]) >> 4) != 4) {
    std::println(" not IPv4 (first byte 0x{:02x})",
                 pkt.empty() ? 0u : std::to_integer<unsigned>(pkt[0]));
    return false;
  }
  const std::size_t ihl = (std::to_integer<unsigned>(pkt[0]) & 0x0Fu) * 4u;
  const std::size_t total = be16(pkt, 2);
  if (ihl < 20 || ihl > pkt.size() || total < ihl || total > pkt.size()) {
    std::println(" malformed IPv4 header (ihl {}, total length {})", ihl, total);
    return false;
  }
  const auto proto = std::to_integer<std::uint8_t>(pkt[9]);
  const std::uint32_t src = be32(pkt, 12);
  const std::uint32_t dst = be32(pkt, 16);
  const bool ip_ok = utcp::checksum_valid(pkt.first(ihl));
  std::print(" IPv4 {} -> {} proto {} ttl {} header-checksum {}", ipv4_str(src), ipv4_str(dst),
             proto, std::to_integer<unsigned>(pkt[8]), ip_ok ? "ok" : "BAD");

  const std::span<std::byte> icmp = pkt.subspan(ihl, total - ihl);
  if (proto != utcp::ip_proto_icmp || icmp.size() < 8) {
    std::println("");
    return false;
  }
  const auto type = std::to_integer<std::uint8_t>(icmp[0]);
  const auto code = std::to_integer<std::uint8_t>(icmp[1]);
  const bool icmp_ok = utcp::checksum_valid(icmp);
  if (type != icmp_echo_request || code != 0) {
    std::println("; ICMP type {} code {} checksum {}", type, code, icmp_ok ? "ok" : "BAD");
    return false;
  }
  const std::uint16_t id = be16(icmp, 4);
  const std::uint16_t seq = be16(icmp, 6);
  std::println("; ICMP echo request id 0x{:04x} seq {} checksum {}", id, seq,
               icmp_ok ? "ok" : "BAD");
  if (!ip_ok || !icmp_ok || !o.reply) {
    return ip_ok && icmp_ok;
  }

  // Echo reply (RFC 792): swap the addresses and change the type to 0. The
  // IPv4 header checksum is unchanged by the swap since the sum does not
  // depend on word order; the ICMP checksum is updated per RFC 1624.
  std::vector<std::byte> out(pkt.begin(), pkt.begin() + static_cast<std::ptrdiff_t>(total));
  const std::span<std::byte> out_icmp = std::span(out).subspan(ihl);
  std::ranges::swap_ranges(std::span(out).subspan(12, 4), std::span(out).subspan(16, 4));
  const std::uint16_t old_sum = be16(out_icmp, 2);
  const auto type_code = [](std::uint8_t t, std::uint8_t c) {
    return static_cast<std::uint16_t>((t << 8) | c);
  };
  const std::uint16_t new_sum = utcp::checksum_update16(
      old_sum, type_code(icmp_echo_request, code), type_code(icmp_echo_reply, code));
  out_icmp[0] = std::byte{icmp_echo_reply};
  put_be16(out_icmp, 2, new_sum);

  // Cross-check the incremental update against a full recomputation.
  std::vector<std::byte> scratch(out_icmp.begin(), out_icmp.end());
  put_be16(scratch, 2, 0);
  const std::uint16_t full = utcp::internet_checksum(scratch);

  const auto written = tun.write(out);
  if (!written) {
    std::println("write failed: {}", written.error().message());
    return true;
  }
  std::println(
      "wrote {} bytes: ICMP echo reply {} -> {} id 0x{:04x} seq {} checksum 0x{:04x} -> 0x{:04x} "
      "(RFC 1624 update; full recompute 0x{:04x}, {})",
      *written, ipv4_str(dst), ipv4_str(src), id, seq, old_sum, new_sum, full,
      full == new_sum ? "match" : "MISMATCH");
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  std::setvbuf(stdout, nullptr, _IOLBF, 0);
  Options o;
  if (!parse_args(argc, argv, o)) {
    usage();
    return 2;
  }

  auto tun = utcp::TunDevice::open(o.name, /*nonblocking=*/true);
  if (!tun) {
    std::println(stderr, "tun_probe: cannot create TUN interface {}: {}", o.name,
                 tun.error().message());
    return 1;
  }
  std::println("opened /dev/net/tun: interface {} flags IFF_TUN|IFF_NO_PI fd {}", tun->name(),
               tun->fd());

  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + std::chrono::milliseconds(o.timeout_ms);
  std::array<std::byte, 65536> buf{};
  int requests = 0;
  while (requests < o.count) {
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock::now()).count();
    if (left <= 0) {
      break;
    }
    pollfd pfd{.fd = tun->fd(), .events = POLLIN, .revents = 0};
    const int ready = ::poll(&pfd, 1, static_cast<int>(left));
    if (ready < 0) {
      std::println(stderr, "tun_probe: poll: {}", std::strerror(errno));
      return 1;
    }
    if (ready == 0) {
      continue;
    }
    const auto n = tun->read(buf);
    if (!n) {
      if (n.error() == std::errc::resource_unavailable_try_again) {
        continue;
      }
      std::println(stderr, "tun_probe: read: {}", n.error().message());
      return 1;
    }
    if (handle_packet(*tun, std::span(buf).first(*n), o)) {
      ++requests;
    }
  }
  std::println("echo requests read: {} (wanted {})", requests, o.count);
  return requests >= o.count ? 0 : 1;
}
