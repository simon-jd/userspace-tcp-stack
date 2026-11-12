// Stack configuration and the two TCP parameter profiles (DESIGN §3.9).
//
// tcp_config(ProfileId) returns a fully populated TcpConfig; any field can
// then be overridden (the M2 ablation flips one field at a time). Sizes are
// payload bytes, windows and cwnd are as noted per field. A default-constructed
// TcpConfig equals tcp_config(ProfileId::linux_compat).
//
// Extra TcpConfig fields, test knobs and StackConfig fields that belong to one
// task are declared in include/utcp/defs/config_{ip,rx,tx,tcp}.def (one owner
// per file, see the file headers); the types they need, in
// include/utcp/defs/config_{ip,rx,tx,tcp}_types.hpp (same owners).
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>

#include "utcp/defs/config_ip_types.hpp"
#include "utcp/defs/config_rx_types.hpp"
#include "utcp/defs/config_tcp_types.hpp"
#include "utcp/defs/config_tx_types.hpp"
#include "utcp/random.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

using namespace std::chrono_literals;

enum class ProfileId : std::uint8_t { rfc, linux_compat };

enum class CcAlgo : std::uint8_t {
  newreno,  // M1
  cubic,    // M2b
  bbr,      // M2c (BBRv1 as Linux tcp_bbr.c)
};

// SRTT/RTTVAR/RTO computation (§4.8).
enum class RttEstimatorKind : std::uint8_t {
  rfc6298,  // RFC 6298 §2: alpha 1/8, beta 1/4, K 4, G 1 ms
  linux,    // Linux tcp_rtt_estimator, fixed point
};

// Which segments give RTT samples. One rule in both profiles.
enum class RttSampleRule : std::uint8_t {
  linux,  // tcp_clean_rtx_queue: seq_rtt for SRTT/RTO, ca_rtt for min_rtt and CC, TSecr fallback
};

// When the initial window drops to 1 segment after SYN or SYN-ACK loss.
enum class IwAfterSynLoss : std::uint8_t {
  after_any,            // RFC 5681 §3.1: after any SYN/SYN-ACK retransmission
  after_more_than_one,  // Linux tcp_init_transfer: after more than one
};

// Congestion window after an idle period longer than the RTO.
enum class IdleRestart : std::uint8_t {
  rfc5681,  // RFC 5681 §4.1: cwnd = min(IW, cwnd)
  linux,    // tcp_cwnd_restart: halve per RTO idle, floor IW
};

// cwnd during fast recovery (M2a).
enum class RecoveryReduction : std::uint8_t {
  rfc6675,  // RFC 6675 §5: cwnd = ssthresh on entry
  prr,      // RFC 9937 with SafeACK, as Linux tcp_cwnd_reduction
};

// CUBIC slow-start exit (M2b).
enum class Hystart : std::uint8_t {
  hystart_pp,       // RFC 9406
  hystart_classic,  // tcp_cubic.c: ACK train + delay
};

// Whether the pacing gate applies (§5.5). The rate is always computed.
enum class Pacing : std::uint8_t {
  cc_requested,  // only when the CC sets pacing_needed (BBR)
  always,
  never,
};

// Delayed-ACK timeout.
enum class DelackAto : std::uint8_t {
  fixed,     // always delack_max
  adaptive,  // Linux: inter-arrival estimate between delack_ato_min and delack_max
};

// When to ACK immediately besides the AckPolicy rules shared by both profiles.
enum class Quickack : std::uint8_t {
  rfc,    // out-of-order and hole-filling segments only (RFC 5681 §4.2)
  linux,  // also the first min(quickack_max, rcv_wnd/(2*rcv_mss)) segments and after idle > RTO
};

enum class Nagle : std::uint8_t {
  rfc896,    // hold a small segment while any data is unacknowledged
  minshall,  // hold while a small segment is unacknowledged (tcp_minshall_check)
};

// PAWS treatment of reordered pure ACKs (§4.4 step 1).
enum class PawsDisorderedAck : std::uint8_t {
  strict,  // RFC 7323 §5.3 R1
  linux,   // tcp_disordered_ack: old-TSval pure duplicate ACKs kept
};

// Receive window growth (§4.10).
enum class RcvWindowGrowth : std::uint8_t {
  free_space,  // window = free buffer, receiver SWS rule
  linux,       // rcv_ssthresh clamp from the initial window, +2*rcv_mss per in-order segment
};

// Window advertised in our SYN or SYN-ACK.
enum class SynWindow : std::uint8_t {
  rfc,    // min(rcv_buf, 65535)
  linux,  // 65535 rounded down to a multiple of the MSS (64240 at MSS 1460)
};

// When reading from the receive buffer triggers a window update.
enum class WindowUpdateAfterRead : std::uint8_t {
  rfc,    // the right edge can move by >= min(rcv_buf/2, MSS) (RFC 9293 §3.8.6.2.2)
  linux,  // the new window is >= 2 * the current window (tcp_cleanup_rbuf)
};

// Zero-window probe form. One rule in both profiles.
enum class ZeroWindowProbe : std::uint8_t {
  linux_zero_length,  // zero-length <SEQ=SND.UNA-1> (tcp_xmit_probe_skb)
};

// RST received in TIME-WAIT.
enum class RstInTimeWait : std::uint8_t {
  ignore,  // RFC 1337
  accept,  // Linux tcp_rfc1337 = 0: close the TIME-WAIT entry
};

// Deliberate bugs that test the simulator's checkers (§7.3).
enum class TestFault : std::uint8_t {
  none,
  unscaled_peer_window,  // treat the peer's window field as unscaled
};

// Inclusive port range.
struct PortRange {
  std::uint16_t lo = 0, hi = 0;

  [[nodiscard]] constexpr std::uint32_t size() const noexcept {
    return hi >= lo ? std::uint32_t{hi} - std::uint32_t{lo} + 1u : 0u;
  }
  constexpr bool operator==(const PortRange&) const = default;
};

// "Infinite" ssthresh, as Linux TCP_INFINITE_SSTHRESH.
inline constexpr std::uint32_t cwnd_infinite = 0x7fff'ffff;
// Largest window scale shift (RFC 7323 §2.3).
inline constexpr std::uint8_t max_wscale = 14;

// Per-connection defaults. Every row of DESIGN §3.9 is a field (frto and undo
// are not modelled and have none, §1.2). The in-class values are the
// linux_compat profile; tcp_config() sets every field of both profiles.
struct TcpConfig {
  // RTO (RFC 6298, §4.8).
  Duration rto_min = 200ms;
  Duration rto_initial = 1s;
  Duration rto_max = 120s;
  Duration rto_after_syn_rexmit = 3s;  // RFC 6298 §5.7, TCP_TIMEOUT_FALLBACK
  RttEstimatorKind rtt_estimator = RttEstimatorKind::linux;
  RttSampleRule rtt_sample_rule = RttSampleRule::linux;

  // Congestion window, in packets (segments).
  std::optional<std::uint32_t> initial_cwnd = 10;  // nullopt: RFC 5681 §3.1 by SMSS
  IwAfterSynLoss iw_after_syn_loss = IwAfterSynLoss::after_more_than_one;
  std::uint32_t initial_ssthresh = cwnd_infinite;
  IdleRestart idle_restart = IdleRestart::linux;
  bool cwnd_growth_needs_cwnd_limited = true;  // tcp_is_cwnd_limited, RFC 7661
  RecoveryReduction recovery_reduction = RecoveryReduction::prr;
  bool rack_tlp = true;                        // RFC 8985 (M2a)
  std::uint32_t dupthresh = 3;                 // RFC 5681; tcp_reordering
  bool adaptive_reordering = true;             // raise dupthresh on reordering, up to max_reordering
  std::uint32_t max_reordering = 300;          // tcp_max_reordering; unused if !adaptive_reordering
  CcAlgo cc = CcAlgo::newreno;
  Hystart hystart = Hystart::hystart_classic;
  std::uint32_t hystart_low_window = 16;       // tcp_cubic hystart_low_window
  Duration hystart_ack_delta = 2ms;            // tcp_cubic hystart_ack_delta_us
  Pacing pacing = Pacing::cc_requested;
  std::uint32_t pacing_ss_ratio = 200;         // percent, tcp_pacing_ss_ratio
  std::uint32_t pacing_ca_ratio = 120;         // percent, tcp_pacing_ca_ratio
  // Bytes. veth gso_ipv4_max_size (65536) - MAX_TCP_HEADER - 1, with
  // MAX_TCP_HEADER = 320 assumed; M2b records the testbed's actual value.
  std::uint32_t gso_max_size = 65536 - 320 - 1;

  // ACKs (RFC 9293 §3.8.6.3, RFC 5681 §4.2).
  Duration delack_max = 200ms;                 // TCP_DELACK_MAX
  DelackAto delack_ato = DelackAto::adaptive;
  Duration delack_ato_min = 40ms;              // TCP_ATO_MIN; unused if delack_ato == fixed
  std::uint32_t ack_every_full_segments = 2;
  Quickack quickack = Quickack::linux;
  std::uint32_t quickack_max = 16;             // TCP_MAX_QUICKACKS; unused if quickack == rfc

  // Sending (§4.9).
  Nagle nagle = Nagle::minshall;
  bool nodelay = false;                        // default for TcpSocketOptions::nodelay
  bool sender_sws = true;                      // RFC 9293 §3.8.6.2.1, Fs = 1/2
  ZeroWindowProbe zero_window_probe = ZeroWindowProbe::linux_zero_length;
  std::optional<std::uint16_t> mss_clamp;      // default for TcpSocketOptions::mss_clamp

  // Options (§4.5).
  bool sack = true;
  bool timestamps = true;
  bool window_scaling = true;
  bool dsack = true;
  bool ts_offset_random = true;                // RFC 7323 §5.4
  PawsDisorderedAck paws_disordered_ack = PawsDisorderedAck::linux;
  std::optional<std::uint8_t> rcv_wscale;      // nullopt: default_rcv_wscale(rcv_buf_max)

  // Buffers, payload bytes. Autotuning runs when init < max.
  std::uint32_t snd_buf_init = 16 * 1024;
  std::uint32_t snd_buf_max = 4 * 1024 * 1024;
  std::uint32_t rcv_buf_init = 128 * 1024;
  std::uint32_t rcv_buf_max = 32 * 1024 * 1024;
  RcvWindowGrowth rcv_window_growth = RcvWindowGrowth::linux;
  SynWindow syn_window = SynWindow::linux;
  WindowUpdateAfterRead window_update_after_read = WindowUpdateAfterRead::linux;

  // Retries and timeouts (§4.8, §4.12). Retry limits are counts.
  std::uint8_t syn_retries = 6;
  std::uint8_t syn_linear_timeouts = 4;        // SYN-SENT only
  std::uint8_t synack_retries = 5;
  std::uint8_t data_retries = 15;              // tcp_retries2, through retry_abort_time()
  Duration time_wait = 60s;
  RstInTimeWait rst_in_time_wait = RstInTimeWait::accept;
  Duration orphan_fin_wait2_timeout = 60s;
  Duration oow_ack_interval = 500ms;           // RFC 5961 §7 limiter, per connection
  PortRange ephemeral_ports{32768, 60999};     // RFC 6056 §3.2

  // MSS and PMTU (§4.13).
  std::uint16_t default_snd_mss = 536;         // peer sent no MSS option (RFC 9293 §3.7.1)
  std::uint16_t min_snd_mss = 48;              // tcp_min_snd_mss
  std::uint16_t min_pmtu = 552;                // ip_rt_min_pmtu
  Duration pmtu_expiry = 10min;                // RFC 1191 §6.3, mtu_expires

#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) type name = linux_value;
#define UTCP_STACK_KNOB(type, name, value, doc)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB

  bool operator==(const TcpConfig&) const = default;
};

// Returns the profile with every field set (DESIGN §3.9).
[[nodiscard]] TcpConfig tcp_config(ProfileId profile);

struct UdpConfig {
  std::uint32_t rcv_buf = 256 * 1024;  // per socket, length-prefixed datagrams
  // nullopt: the same range as StackConfig::tcp.ephemeral_ports, so it follows
  // the TCP profile (§3.9 "as TCP"); udp_ephemeral_ports() resolves it.
  std::optional<PortRange> ephemeral_ports;

  bool operator==(const UdpConfig&) const = default;
};

struct IcmpConfig {
  bool echo_reply = true;
  std::uint32_t rate_per_s = 1000;  // generated errors, global token bucket (icmp_msgs_per_sec)
  std::uint32_t burst = 50;         // icmp_msgs_burst

  bool operator==(const IcmpConfig&) const = default;
};

struct StackConfig {
  Ipv4Addr local_addr;
  std::uint16_t mtu = 1500;  // interface MTU; must equal the TUN MTU
  std::uint8_t ip_ttl = 64;
  Seed seed;                 // the only source of randomness
  TcpConfig tcp = tcp_config(ProfileId::linux_compat);
  UdpConfig udp;
  IcmpConfig icmp;
  std::uint32_t pool_buffers = 4096;     // PacketPool buffers (2 KiB each in M1)
  std::uint32_t tx_queue_packets = 1024; // transmit queue bound (§3.4)
  std::uint32_t max_connections = 65536; // TCP and UDP slots
  std::uint32_t chunk_limit = 1u << 20;  // ChunkPool limit, in 4 KiB chunks
  std::uint32_t trace_mask = 0;          // bit i enables TraceKind i (§10.2)
  std::uint16_t tx_headroom = 0;         // M4: room for virtio_net_hdr
  bool assert_time_monotonic = false;    // §3.4 item 4; on in the simulator

#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc)
#define UTCP_STACK_KNOB(type, name, value, doc) type name = value;
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB

  bool operator==(const StackConfig&) const = default;
};

// The ephemeral port range of UDP sockets (§3.6, §3.9): UdpConfig's if set,
// else TCP's.
[[nodiscard]] constexpr PortRange udp_ephemeral_ports(const StackConfig& c) noexcept {
  return c.udp.ephemeral_ports.value_or(c.tcp.ephemeral_ports);
}

// RFC 7323 §2.3: the smallest shift s with 65535 * 2^s >= rcv_buf_max, at
// most 14 (7 for 4 MiB, 10 for 32 MiB, as Linux).
[[nodiscard]] constexpr std::uint8_t default_rcv_wscale(std::uint32_t rcv_buf_max) noexcept {
  std::uint8_t s = 0;
  while (s < max_wscale && (std::uint64_t{65535} << s) < rcv_buf_max) {
    ++s;
  }
  return s;
}

// The receive window scale a connection with this configuration offers.
[[nodiscard]] constexpr std::uint8_t effective_rcv_wscale(const TcpConfig& c) noexcept {
  return c.rcv_wscale.value_or(default_rcv_wscale(c.rcv_buf_max));
}

// RFC 5681 §3.1 initial window in segments for sender MSS `smss`: 2 above
// 2190 bytes, 3 above 1095, else 4.
[[nodiscard]] constexpr std::uint32_t rfc5681_initial_cwnd(std::uint32_t smss) noexcept {
  return smss > 2190 ? 2u : smss > 1095 ? 3u : 4u;
}

// The initial window in segments a connection with this configuration uses.
[[nodiscard]] constexpr std::uint32_t effective_initial_cwnd(const TcpConfig& c,
                                                             std::uint32_t smss) noexcept {
  return c.initial_cwnd.value_or(rfc5681_initial_cwnd(smss));
}

[[nodiscard]] constexpr std::string_view to_string(ProfileId p) noexcept {
  return p == ProfileId::rfc ? "rfc" : "linux_compat";
}
// Accepts "rfc", "linux_compat" and "linux".
[[nodiscard]] constexpr std::optional<ProfileId> profile_from_string(std::string_view s) noexcept {
  if (s == "rfc") {
    return ProfileId::rfc;
  }
  if (s == "linux_compat" || s == "linux") {
    return ProfileId::linux_compat;
  }
  return std::nullopt;
}

[[nodiscard]] constexpr std::string_view to_string(CcAlgo a) noexcept {
  switch (a) {
    case CcAlgo::newreno: return "newreno";
    case CcAlgo::cubic: return "cubic";
    case CcAlgo::bbr: return "bbr";
  }
  return "?";
}
// Accepts "newreno" (also "reno"), "cubic" and "bbr".
[[nodiscard]] constexpr std::optional<CcAlgo> cc_from_string(std::string_view s) noexcept {
  if (s == "newreno" || s == "reno") {
    return CcAlgo::newreno;
  }
  if (s == "cubic") {
    return CcAlgo::cubic;
  }
  if (s == "bbr") {
    return CcAlgo::bbr;
  }
  return std::nullopt;
}

}  // namespace utcp
