// Addresses, endpoints, handles and the TCP state enumerations (DESIGN §3.2,
// §4.2).
#pragma once

#include <charconv>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "utcp/seq.hpp"

namespace utcp {

// An IPv4 address as a host-order integer: 192.0.2.1 is 0xC0000201 (the
// convention of utcp/checksum.hpp).
struct Ipv4Addr {
  std::uint32_t v = 0;

  [[nodiscard]] static constexpr Ipv4Addr from_octets(std::uint8_t a, std::uint8_t b,
                                                      std::uint8_t c, std::uint8_t d) noexcept {
    return Ipv4Addr{(std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) |
                    (std::uint32_t{c} << 8) | std::uint32_t{d}};
  }
  [[nodiscard]] constexpr std::uint8_t octet(int i) const noexcept {  // i = 0 is the first
    return static_cast<std::uint8_t>(v >> (24 - 8 * i));
  }

  constexpr auto operator<=>(const Ipv4Addr&) const = default;
};

struct Endpoint {
  Ipv4Addr addr;
  std::uint16_t port = 0;

  constexpr auto operator<=>(const Endpoint&) const = default;
};

struct FourTuple {
  Endpoint local, remote;

  constexpr auto operator<=>(const FourTuple&) const = default;
};

// Half-open range [begin, end) of 64-bit stream offsets.
struct Range {
  std::uint64_t begin = 0, end = 0;

  [[nodiscard]] constexpr std::uint64_t size() const noexcept {
    return end > begin ? end - begin : 0;
  }
  [[nodiscard]] constexpr bool empty() const noexcept { return end <= begin; }
  [[nodiscard]] constexpr bool contains(std::uint64_t off) const noexcept {
    return begin <= off && off < end;
  }
  constexpr bool operator==(const Range&) const = default;
};

enum class Proto : std::uint8_t { tcp, udp };

// A socket. `slot` indexes the stack's slot vector; `gen` increments each
// time the slot is reused, so a stale handle is detected (Error::bad_handle).
struct Handle {
  std::uint32_t slot = 0;
  std::uint32_t gen = 0;
  Proto proto = Proto::tcp;

  constexpr auto operator<=>(const Handle&) const = default;
};

// RFC 9293 §3.3.2.
enum class TcpState : std::uint8_t {
  closed,
  listen,
  syn_sent,
  syn_received,
  established,
  fin_wait_1,
  fin_wait_2,
  close_wait,
  closing,
  last_ack,
  time_wait,
};
inline constexpr int tcp_state_count = 11;

// Congestion state, as Linux tcp_ca_state.
enum class CaState : std::uint8_t { open, disorder, cwr, recovery, loss };
inline constexpr int ca_state_count = 5;

[[nodiscard]] constexpr std::string_view to_string(Proto p) noexcept {
  return p == Proto::tcp ? "tcp" : "udp";
}

[[nodiscard]] constexpr std::string_view to_string(TcpState s) noexcept {
  switch (s) {
    case TcpState::closed: return "closed";
    case TcpState::listen: return "listen";
    case TcpState::syn_sent: return "syn_sent";
    case TcpState::syn_received: return "syn_received";
    case TcpState::established: return "established";
    case TcpState::fin_wait_1: return "fin_wait_1";
    case TcpState::fin_wait_2: return "fin_wait_2";
    case TcpState::close_wait: return "close_wait";
    case TcpState::closing: return "closing";
    case TcpState::last_ack: return "last_ack";
    case TcpState::time_wait: return "time_wait";
  }
  return "?";
}

[[nodiscard]] constexpr std::string_view to_string(CaState s) noexcept {
  switch (s) {
    case CaState::open: return "open";
    case CaState::disorder: return "disorder";
    case CaState::cwr: return "cwr";
    case CaState::recovery: return "recovery";
    case CaState::loss: return "loss";
  }
  return "?";
}

// Dotted-quad text, "192.0.2.1".
[[nodiscard]] inline std::string to_string(Ipv4Addr a) {
  std::string s;
  for (int i = 0; i < 4; ++i) {
    if (i > 0) {
      s += '.';
    }
    s += std::to_string(a.octet(i));
  }
  return s;
}

// "192.0.2.1:80".
[[nodiscard]] inline std::string to_string(Endpoint e) {
  return to_string(e.addr) + ':' + std::to_string(e.port);
}

// Parses a dotted quad ("192.0.2.1"); nullopt unless exactly four decimal
// octets 0..255 with no other characters.
[[nodiscard]] inline std::optional<Ipv4Addr> ipv4_from_string(std::string_view s) noexcept {
  std::uint32_t v = 0;
  const char* p = s.data();
  const char* const end = s.data() + s.size();
  for (int i = 0; i < 4; ++i) {
    if (i > 0) {
      if (p == end || *p != '.') {
        return std::nullopt;
      }
      ++p;
    }
    unsigned octet = 0;
    const auto [next, ec] = std::from_chars(p, end, octet);
    if (ec != std::errc{} || next == p || next - p > 3 || octet > 255) {
      return std::nullopt;
    }
    p = next;
    v = (v << 8) | octet;
  }
  if (p != end) {
    return std::nullopt;
  }
  return Ipv4Addr{v};
}

}  // namespace utcp
