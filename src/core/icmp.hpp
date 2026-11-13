// ICMP (RFC 792; DESIGN §3.7): echo reply and the echo API, generated
// destination-unreachable errors with a global token bucket, and received
// errors dispatched to TCP (TcpEngine::on_icmp_error) or UDP.
//
// Received errors, as Linux icmp_unreach / tcp_v4_err: destination
// unreachable with codes 0-15 (codes above NR_ICMP_UNREACH = 15 are counted
// and ignored), time exceeded and parameter problem go to the protocol of the
// quoted datagram. RFC 1122 §4.2.3.9 handles parameter problem like the soft
// unreachables; Linux tcp_v4_err maps it to EPROTO and treats it like every
// other error it accepts (fatal in SYN-SENT, soft once synchronized). What
// TCP does with each type and code is the engine's (§4.7). Source quench and
// redirects are counted and ignored.
//
// Generated errors (port unreachable for UDP, protocol unreachable) quote as
// much of the offending datagram as fits in 576 bytes or the path MTU, if
// smaller (RFC 1812 §4.3.2.3, Linux icmp_send), and are never sent to a
// non-unicast source (RFC 1122 §3.2.2). The token bucket holds
// IcmpConfig::burst tokens and refills at rate_per_s, exactly, in integer
// arithmetic (Linux icmp_global_allow refills in steps of at least 20 ms and
// takes 0-2 tokens at random; the per-destination icmp_ratelimit is not
// modelled). Echo replies are not rate-limited (as Linux).
//
// Every ICMP datagram the stack sends has DF set, IP ID 0 (Linux
// ip_select_ident_segs for DF datagrams without a connected socket) and TOS 0.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

#include "core/tcp/tcp_engine.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "utcp/error.hpp"
#include "utcp/stack.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

class StackCore;
class UdpLayer;

// RFC 792 type 12 (wire/icmp.hpp has no constant for it).
inline constexpr std::uint8_t icmp_parameter_problem = 12;
// Highest destination-unreachable code acted on (Linux NR_ICMP_UNREACH).
inline constexpr std::uint8_t icmp_max_unreach_code = 15;

// RFC 1191 §7: the largest plateau of the table (65535, 32000, 17914, 8166,
// 4352, 2002, 1492, 1006, 508, 296, 68) below `total_len`; 68 if none is.
[[nodiscard]] std::uint16_t pmtu_plateau_below(std::uint16_t total_len) noexcept;

// The path MTU a frag-needed message (type 3 code 4) asks for: the next-hop
// MTU field (RFC 1191 §4), or the plateau below the quoted total length when
// the field is 0 (§7); at least `min_pmtu` (Linux __ip_rt_update_pmtu).
[[nodiscard]] std::uint16_t frag_needed_mtu(std::uint16_t next_hop_mtu,
                                            std::uint16_t quoted_total_len,
                                            std::uint16_t min_pmtu) noexcept;

// RFC 1122 §3.2.2: an address an ICMP error may be sent to: not 0.0.0.0/8,
// not 127.0.0.0/8, not multicast, class E or the limited broadcast
// (224.0.0.0 and above).
[[nodiscard]] bool is_unicast_source(Ipv4Addr a) noexcept;

// The TcpIcmpError for an error message `h` whose quote `q` is a TCP segment:
// tuple from the quoted addresses and ports (local = the quoted source), the
// quoted sequence number, and for type 3 code 4 new_pmtu =
// min(frag_needed_mtu(...), current_pmtu), in [min_pmtu, current_pmtu] (if
// current_pmtu >= min_pmtu): the value the cache holds once the engine has
// lowered it (Linux dst_mtu after __ip_rt_update_pmtu). It is not always a
// reduction of the connection's PMTU: it equals the cached value when the
// next-hop MTU is at or above it, and it can exceed the connection's PMTU
// when the cache entry expired back to the interface MTU. The engine applies
// it only if it is below the connection's PMTU and never raises that (Linux
// tcp_v4_mtu_reduced: icsk_pmtu_cookie > mtu). Precondition: q.ip.proto is
// TCP.
[[nodiscard]] TcpIcmpError tcp_icmp_error(const wire::IcmpHeader& h, const wire::IcmpQuote& q,
                                          std::uint16_t current_pmtu,
                                          std::uint16_t min_pmtu) noexcept;

// Global token bucket of generated ICMP errors (§3.7). Credit is kept in
// billionths of a token: full (burst tokens) at construction, refilled by
// rate_per_s tokens per second of `now`, capped at burst.
class IcmpRateLimiter {
public:
  IcmpRateLimiter(std::uint32_t rate_per_s, std::uint32_t burst) noexcept;
  // True, taking one token, if a token is available at `now`. `now` is
  // non-decreasing (an earlier time refills nothing).
  bool allow(Time now) noexcept;
  // Whole tokens available at the last call.
  [[nodiscard]] std::uint64_t tokens() const noexcept { return credit_ / unit; }

private:
  static constexpr std::uint64_t unit = 1'000'000'000;  // credit of one token
  std::uint64_t rate_, cap_, credit_;
  Time stamp_;
};

// Receives the errors IcmpLayer parses from ICMP messages quoting TCP. In a
// Stack it is the TcpEngine (StackImpl registers it); a test may register a
// recorder instead.
class TcpIcmpSink {
public:
  virtual void on_icmp_error(Time now, const TcpIcmpError& e) = 0;

protected:
  TcpIcmpSink() = default;
  TcpIcmpSink(const TcpIcmpSink&) = default;
  TcpIcmpSink& operator=(const TcpIcmpSink&) = default;
  ~TcpIcmpSink() = default;
};

class IcmpLayer {
public:
  static constexpr std::uint32_t echo_queue_capacity = 64;

  IcmpLayer(StackCore& core, UdpLayer& udp);
  IcmpLayer(const IcmpLayer&) = delete;
  IcmpLayer& operator=(const IcmpLayer&) = delete;

  // The receiver of errors quoting TCP (StackImpl sets the engine). Must be
  // set before such an error arrives.
  void set_tcp_sink(TcpIcmpSink* sink) noexcept { tcp_ = sink; }

  // --- From the IP layer.
  // An ICMP message (ip.payload) in a validated datagram for the stack address.
  void on_message(const wire::Ipv4View& ip);
  // Sends destination unreachable `code` about a received datagram: `ip` is
  // its parsed header, `datagram` its bytes [0, total length). Rate-limited.
  void send_unreach(std::uint8_t code, const wire::Ipv4View& ip,
                    std::span<const std::byte> datagram);

  // --- Echo API (Stack::icmp_echo, poll_echo_reply).
  // invalid_argument for destination 0; message_too_big above pmtu(dst) - 28
  // bytes of payload; no_buffers when the transmit queue or the pool is full.
  std::expected<void, Error> echo(Ipv4Addr dst, std::uint16_t id, std::uint16_t seq,
                                  std::span<const std::byte> payload);
  std::optional<EchoReply> poll_echo_reply() noexcept;
  [[nodiscard]] std::uint32_t echo_replies_queued() const noexcept { return echo_count_; }

  [[nodiscard]] const IcmpRateLimiter& rate_limiter() const noexcept { return limiter_; }

  void check_invariants() const;

private:
  void on_echo_request(const wire::Ipv4View& ip, const wire::IcmpView& m);
  void on_echo_reply(const wire::Ipv4View& ip, const wire::IcmpView& m);
  void on_error(const wire::IcmpView& m);
  // Builds the message (header `h`, then `body`) and queues it to `dst`. No
  // counters: false when the queue or the pool is full.
  bool transmit(Ipv4Addr dst, const wire::IcmpHeader& h, std::span<const std::byte> body);

  StackCore& core_;
  TcpIcmpSink* tcp_ = nullptr;
  UdpLayer& udp_;
  IcmpRateLimiter limiter_;
  std::array<EchoReply, echo_queue_capacity> echo_q_{};
  std::uint32_t echo_head_ = 0, echo_count_ = 0;
};

}  // namespace utcp
