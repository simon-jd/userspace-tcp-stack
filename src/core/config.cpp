// The two TCP parameter profiles, one assignment per row of DESIGN §3.9,
// the check of forbidden field combinations, and the text form of every
// TcpConfig field (set_config_field).
#include "utcp/config.hpp"

#include <array>
#include <charconv>
#include <cstddef>
#include <limits>
#include <system_error>
#include <type_traits>

namespace utcp {
namespace {

// Same: the value both profiles use.
TcpConfig shared_rows() {
  TcpConfig c;
  c.rto_initial = 1s;           // RFC 6298 §2.1; TCP_TIMEOUT_INIT
  c.rto_after_syn_rexmit = 3s;  // RFC 6298 §5.7; TCP_TIMEOUT_FALLBACK
  c.rtt_sample_rule = RttSampleRule::linux;  // tcp_clean_rtx_queue, tcp_ack_update_rtt
  c.initial_ssthresh = cwnd_infinite;        // RFC 5681 §3.1
  c.cwnd_growth_needs_cwnd_limited = true;   // tcp_is_cwnd_limited; RFC 7661
  c.dupthresh = 3;                           // RFC 5681; tcp_reordering
  c.max_reordering = 300;                    // tcp_max_reordering
  c.cc = CcAlgo::newreno;                    // M1; cubic from M2b
  c.hystart_low_window = 16;
  c.hystart_ack_delta = 2ms;
  c.pacing = Pacing::cc_requested;           // §5.5
  c.pacing_ss_ratio = 200;
  c.pacing_ca_ratio = 120;
  c.gso_max_size = 65536 - 320 - 1;          // sk_setup_caps; M2b records the testbed value
  c.delack_max = 200ms;                      // RFC 9293 §3.8.6.3; TCP_DELACK_MAX
  c.delack_ato_min = 40ms;                   // TCP_ATO_MIN
  c.ack_every_full_segments = 2;             // RFC 5681 §4.2; __tcp_ack_snd_check
  c.quickack_max = 16;                       // TCP_MAX_QUICKACKS
  c.nodelay = false;
  c.sender_sws = true;                       // RFC 9293 §3.8.6.2.1
  c.zero_window_probe = ZeroWindowProbe::linux_zero_length;  // tcp_xmit_probe_skb
  c.mss_clamp = std::nullopt;
  c.sack = true;
  c.timestamps = true;
  c.window_scaling = true;
  c.dsack = true;
  c.ts_offset_random = true;                 // RFC 7323 §5.4
  c.rcv_wscale = std::nullopt;               // RFC 7323 §2.3 from rcv_buf_max
  c.synack_retries = 5;                      // tcp_synack_retries
  c.data_retries = 15;                       // RFC 1122 R2; tcp_retries2
  c.oow_ack_interval = 500ms;                // RFC 5961 §7; tcp_invalid_ratelimit
  c.default_snd_mss = 536;                   // RFC 9293 §3.7.1
  c.min_snd_mss = 48;                        // tcp_min_snd_mss
  c.min_pmtu = 552;                          // ip_rt_min_pmtu
  c.pmtu_expiry = 10min;                     // RFC 1191 §6.3; mtu_expires
  return c;
}

TcpConfig rfc_profile() {
  TcpConfig c = shared_rows();
  c.rto_min = 1s;                                        // RFC 6298 §2.4
  c.rto_max = 60s;                                       // RFC 6298 §2.5 (>= 60 s)
  c.rtt_estimator = RttEstimatorKind::rfc6298;
  c.initial_cwnd = std::nullopt;                         // RFC 5681 §3.1 by SMSS
  c.iw_after_syn_loss = IwAfterSynLoss::after_any;       // RFC 5681 §3.1
  c.idle_restart = IdleRestart::rfc5681;                 // RFC 5681 §4.1
  c.recovery_reduction = RecoveryReduction::rfc6675;     // RFC 6675 §5
  c.rack_tlp = false;                                    // RFC 8985 §9.2: not with RFC 6675
  c.adaptive_reordering = false;
  c.cc_flavor = CcFlavor::rfc;                           // RFC 5681 eq. 4, RFC 9438
  c.hystart = Hystart::hystart_pp;                       // RFC 9406
  c.delack_ato = DelackAto::fixed;
  c.quickack = Quickack::rfc;
  c.nagle = Nagle::rfc896;                               // RFC 9293 §3.7.4
  c.paws_disordered_ack = PawsDisorderedAck::strict;     // RFC 7323 §5.3 R1
  c.snd_buf_init = 4 * 1024 * 1024;
  c.snd_buf_max = 4 * 1024 * 1024;
  c.rcv_buf_init = 4 * 1024 * 1024;
  c.rcv_buf_max = 4 * 1024 * 1024;
  c.rcv_window_growth = RcvWindowGrowth::free_space;     // RFC 9293 §3.8.6.2.2
  c.syn_window = SynWindow::rfc;
  c.window_update_after_read = WindowUpdateAfterRead::rfc;
  c.syn_retries = 7;                                     // 183 s >= 3 min, RFC 1122 §4.2.3.5
  c.syn_linear_timeouts = 0;
  c.time_wait = 240s;                                    // 2*MSL, RFC 9293 §3.4.2
  c.rst_in_time_wait = RstInTimeWait::ignore;            // RFC 1337
  c.orphan_fin_wait2_timeout = 240s;
  c.ephemeral_ports = PortRange{1024, 65535};            // RFC 6056 §3.2
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) c.name = rfc_value;
#define UTCP_STACK_KNOB(type, name, value, doc)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
  return c;
}

TcpConfig linux_profile() {
  TcpConfig c = shared_rows();
  c.rto_min = 200ms;                                     // TCP_RTO_MIN
  c.rto_max = 120s;                                      // TCP_RTO_MAX
  c.rtt_estimator = RttEstimatorKind::linux;             // tcp_rtt_estimator
  c.initial_cwnd = 10;                                   // RFC 6928; TCP_INIT_CWND
  c.iw_after_syn_loss = IwAfterSynLoss::after_more_than_one;  // tcp_init_transfer
  c.idle_restart = IdleRestart::linux;                   // tcp_cwnd_restart
  c.recovery_reduction = RecoveryReduction::prr;         // RFC 9937; tcp_cwnd_reduction
  c.rack_tlp = true;                                     // RFC 8985; tcp_recovery=1, tcp_early_retrans=3
  c.adaptive_reordering = true;
  c.cc_flavor = CcFlavor::linux;                         // tcp_reno_ssthresh, tcp_cubic.c
  c.hystart = Hystart::hystart_classic;                  // tcp_cubic.c
  c.delack_ato = DelackAto::adaptive;
  c.quickack = Quickack::linux;                          // tcp_incr_quickack
  c.nagle = Nagle::minshall;                             // tcp_minshall_check
  c.paws_disordered_ack = PawsDisorderedAck::linux;      // tcp_disordered_ack
  c.snd_buf_init = 16 * 1024;                            // tcp_wmem
  c.snd_buf_max = 4 * 1024 * 1024;
  c.rcv_buf_init = 128 * 1024;                           // tcp_rmem
  c.rcv_buf_max = 32 * 1024 * 1024;
  c.rcv_window_growth = RcvWindowGrowth::linux;          // tcp_grow_window
  c.syn_window = SynWindow::linux;                       // tcp_select_initial_window
  c.window_update_after_read = WindowUpdateAfterRead::linux;  // tcp_cleanup_rbuf
  c.syn_retries = 6;                                     // tcp_syn_retries
  c.syn_linear_timeouts = 4;                             // tcp_syn_linear_timeouts
  c.time_wait = 60s;                                     // TCP_TIMEWAIT_LEN
  c.rst_in_time_wait = RstInTimeWait::accept;            // tcp_rfc1337 = 0
  c.orphan_fin_wait2_timeout = 60s;                      // tcp_fin_timeout
  c.ephemeral_ports = PortRange{32768, 60999};           // ip_local_port_range
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) c.name = linux_value;
#define UTCP_STACK_KNOB(type, name, value, doc)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
  return c;
}

// ---- Text form of the fields (set_config_field) ----

// Value names, one switch per enum so that -Wswitch flags a new enumerator
// without a name; an out-of-range value has the empty name.
std::string_view enum_name(RttEstimatorKind v) {
  switch (v) {
    case RttEstimatorKind::rfc6298: return "rfc6298";
    case RttEstimatorKind::linux: return "linux";
  }
  return {};
}
std::string_view enum_name(RttSampleRule v) {
  switch (v) {
    case RttSampleRule::linux: return "linux";
  }
  return {};
}
std::string_view enum_name(IwAfterSynLoss v) {
  switch (v) {
    case IwAfterSynLoss::after_any: return "after_any";
    case IwAfterSynLoss::after_more_than_one: return "after_more_than_one";
  }
  return {};
}
std::string_view enum_name(IdleRestart v) {
  switch (v) {
    case IdleRestart::rfc5681: return "rfc5681";
    case IdleRestart::linux: return "linux";
  }
  return {};
}
std::string_view enum_name(RecoveryReduction v) {
  switch (v) {
    case RecoveryReduction::rfc6675: return "rfc6675";
    case RecoveryReduction::prr: return "prr";
  }
  return {};
}
std::string_view enum_name(CcAlgo v) {
  switch (v) {
    case CcAlgo::newreno:
    case CcAlgo::cubic:
    case CcAlgo::bbr: return to_string(v);
  }
  return {};
}
std::string_view enum_name(CcFlavor v) {
  switch (v) {
    case CcFlavor::rfc:
    case CcFlavor::linux: return to_string(v);
  }
  return {};
}
std::string_view enum_name(Hystart v) {
  switch (v) {
    case Hystart::hystart_pp: return "hystart_pp";
    case Hystart::hystart_classic: return "hystart_classic";
  }
  return {};
}
std::string_view enum_name(Pacing v) {
  switch (v) {
    case Pacing::cc_requested: return "cc_requested";
    case Pacing::always: return "always";
    case Pacing::never: return "never";
  }
  return {};
}
std::string_view enum_name(DelackAto v) {
  switch (v) {
    case DelackAto::fixed: return "fixed";
    case DelackAto::adaptive: return "adaptive";
  }
  return {};
}
std::string_view enum_name(Quickack v) {
  switch (v) {
    case Quickack::rfc: return "rfc";
    case Quickack::linux: return "linux";
  }
  return {};
}
std::string_view enum_name(Nagle v) {
  switch (v) {
    case Nagle::rfc896: return "rfc896";
    case Nagle::minshall: return "minshall";
  }
  return {};
}
std::string_view enum_name(PawsDisorderedAck v) {
  switch (v) {
    case PawsDisorderedAck::strict: return "strict";
    case PawsDisorderedAck::linux: return "linux";
  }
  return {};
}
std::string_view enum_name(RcvWindowGrowth v) {
  switch (v) {
    case RcvWindowGrowth::free_space: return "free_space";
    case RcvWindowGrowth::linux: return "linux";
  }
  return {};
}
std::string_view enum_name(SynWindow v) {
  switch (v) {
    case SynWindow::rfc: return "rfc";
    case SynWindow::linux: return "linux";
  }
  return {};
}
std::string_view enum_name(WindowUpdateAfterRead v) {
  switch (v) {
    case WindowUpdateAfterRead::rfc: return "rfc";
    case WindowUpdateAfterRead::linux: return "linux";
  }
  return {};
}
std::string_view enum_name(ZeroWindowProbe v) {
  switch (v) {
    case ZeroWindowProbe::linux_zero_length: return "linux_zero_length";
  }
  return {};
}
std::string_view enum_name(RstInTimeWait v) {
  switch (v) {
    case RstInTimeWait::ignore: return "ignore";
    case RstInTimeWait::accept: return "accept";
  }
  return {};
}
std::string_view enum_name(TestFault v) {
  switch (v) {
    case TestFault::none: return "none";
    case TestFault::unscaled_peer_window: return "unscaled_peer_window";
    case TestFault::overscaled_peer_window: return "overscaled_peer_window";
    case TestFault::prr_skip_force: return "prr_skip_force";
    case TestFault::double_tlp: return "double_tlp";
    case TestFault::ignore_pacing_gate: return "ignore_pacing_gate";
  }
  return {};
}

// What an integer field holds: its suffixes on input.
enum class Unit : std::uint8_t {
  count,  // plain decimal
  bytes,  // also Ki, Mi, Gi
  rate,   // payload bytes/s; also bit, kbit, Mbit, Gbit (divided by 8)
};

template <class T>
inline constexpr bool is_optional_v = false;
template <class T>
inline constexpr bool is_optional_v<std::optional<T>> = true;

using Parsed = std::expected<std::uint64_t, std::string>;

// Leading decimal digits of `v` (at least one); `rest` gets what follows.
Parsed parse_digits(std::string_view v, std::string_view& rest) {
  std::uint64_t n = 0;
  const auto [p, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
  if (ec == std::errc::result_out_of_range) {
    return std::unexpected("'" + std::string(v) + "' is too large");
  }
  if (ec != std::errc{} || p == v.data()) {
    return std::unexpected("'" + std::string(v) + "' does not start with a decimal number");
  }
  rest = v.substr(static_cast<std::size_t>(p - v.data()));
  return n;
}

Parsed scale(std::uint64_t n, std::uint64_t mul, std::string_view v) {
  std::uint64_t r = 0;
  if (__builtin_mul_overflow(n, mul, &r)) {
    return std::unexpected("'" + std::string(v) + "' is too large");
  }
  return r;
}

Parsed parse_integer(std::string_view v, Unit unit) {
  std::string_view rest;
  const Parsed n = parse_digits(v, rest);
  if (!n || rest.empty()) {
    return n;
  }
  if (unit == Unit::bytes) {
    if (rest == "Ki") {
      return scale(*n, std::uint64_t{1} << 10, v);
    }
    if (rest == "Mi") {
      return scale(*n, std::uint64_t{1} << 20, v);
    }
    if (rest == "Gi") {
      return scale(*n, std::uint64_t{1} << 30, v);
    }
    return std::unexpected("'" + std::string(v) + "': a size takes no suffix or Ki, Mi, Gi");
  }
  if (unit == Unit::rate) {
    std::uint64_t mul = 0;
    if (rest == "bit") {
      mul = 1;
    } else if (rest == "kbit") {
      mul = 1'000;
    } else if (rest == "Mbit") {
      mul = 1'000'000;
    } else if (rest == "Gbit") {
      mul = 1'000'000'000;
    } else {
      return std::unexpected("'" + std::string(v) +
                             "': a rate takes no suffix (bytes/s) or bit, kbit, Mbit, Gbit");
    }
    const Parsed bits = scale(*n, mul, v);
    if (!bits) {
      return bits;
    }
    if (*bits % 8 != 0) {
      return std::unexpected("'" + std::string(v) + "' is not a whole number of bytes/s");
    }
    return *bits / 8;
  }
  return std::unexpected("'" + std::string(v) + "' is not a decimal integer");
}

std::expected<Duration, std::string> parse_duration(std::string_view v) {
  std::string_view rest;
  const Parsed n = parse_digits(v, rest);
  if (!n) {
    return std::unexpected(n.error());
  }
  std::uint64_t ns_per = 0;
  if (rest == "ns") {
    ns_per = 1;
  } else if (rest == "us") {
    ns_per = 1'000;
  } else if (rest == "ms") {
    ns_per = 1'000'000;
  } else if (rest == "s") {
    ns_per = 1'000'000'000;
  } else if (rest == "min") {
    ns_per = 60'000'000'000;
  } else {
    return std::unexpected("'" + std::string(v) +
                           "' is not a duration (an integer with ns, us, ms, s or min)");
  }
  const Parsed ns = scale(*n, ns_per, v);
  if (!ns || *ns > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
    return std::unexpected("'" + std::string(v) + "' is too large");
  }
  return Duration{static_cast<std::int64_t>(*ns)};
}

template <class T>
std::expected<T, std::string> parse_value(std::string_view v, Unit unit) {
  if constexpr (is_optional_v<T>) {
    if (v == "none") {
      return T{};
    }
    auto r = parse_value<typename T::value_type>(v, unit);
    if (!r) {
      return std::unexpected(r.error());
    }
    return T{*r};
  } else if constexpr (std::is_same_v<T, bool>) {
    if (v == "true" || v == "on" || v == "1") {
      return true;
    }
    if (v == "false" || v == "off" || v == "0") {
      return false;
    }
    return std::unexpected("'" + std::string(v) + "' is not true/false, on/off or 1/0");
  } else if constexpr (std::is_same_v<T, Duration>) {
    return parse_duration(v);
  } else if constexpr (std::is_same_v<T, PortRange>) {
    const std::size_t dash = v.find('-');
    if (dash == std::string_view::npos) {
      return std::unexpected("'" + std::string(v) + "' is not a port range lo-hi");
    }
    const auto lo = parse_value<std::uint16_t>(v.substr(0, dash), Unit::count);
    const auto hi = parse_value<std::uint16_t>(v.substr(dash + 1), Unit::count);
    if (!lo || !hi) {
      return std::unexpected("'" + std::string(v) + "' is not a port range lo-hi");
    }
    return PortRange{*lo, *hi};
  } else if constexpr (std::is_enum_v<T>) {
    if constexpr (std::is_same_v<T, CcAlgo>) {
      if (const auto a = cc_from_string(v)) {
        return *a;
      }
    }
    using U = std::underlying_type_t<T>;
    for (unsigned i = 0; i <= unsigned{std::numeric_limits<U>::max()}; ++i) {
      const std::string_view name = enum_name(static_cast<T>(i));
      if (name.empty()) {
        break;
      }
      if (name == v) {
        return static_cast<T>(i);
      }
    }
    return std::unexpected("'" + std::string(v) + "' is not a value name of this field");
  } else {
    static_assert(std::is_unsigned_v<T>);
    const Parsed n = parse_integer(v, unit);
    if (!n) {
      return std::unexpected(n.error());
    }
    if (*n > std::uint64_t{std::numeric_limits<T>::max()}) {
      return std::unexpected("'" + std::string(v) + "' is above the field's maximum " +
                             std::to_string(std::uint64_t{std::numeric_limits<T>::max()}));
    }
    return static_cast<T>(*n);
  }
}

std::string format_duration(Duration d) {
  const std::int64_t ns = d.count();
  struct UnitName {
    std::int64_t ns;
    std::string_view name;
  };
  constexpr std::array<UnitName, 4> units{{{60'000'000'000, "min"},
                                           {1'000'000'000, "s"},
                                           {1'000'000, "ms"},
                                           {1'000, "us"}}};
  if (ns != 0) {
    for (const UnitName& u : units) {
      if (ns % u.ns == 0) {
        return std::to_string(ns / u.ns) + std::string(u.name);
      }
    }
  }
  return std::to_string(ns) + "ns";
}

template <class T>
std::string format_value(const T& v) {
  if constexpr (is_optional_v<T>) {
    return v ? format_value(*v) : std::string("none");
  } else if constexpr (std::is_same_v<T, bool>) {
    return v ? "true" : "false";
  } else if constexpr (std::is_same_v<T, Duration>) {
    return format_duration(v);
  } else if constexpr (std::is_same_v<T, PortRange>) {
    return std::to_string(v.lo) + "-" + std::to_string(v.hi);
  } else if constexpr (std::is_enum_v<T>) {
    return std::string(enum_name(v));
  } else {
    static_assert(std::is_unsigned_v<T>);
    return std::to_string(std::uint64_t{v});
  }
}

using FieldSetter = std::expected<void, std::string> (*)(TcpConfig&, std::string_view);
using FieldGetter = std::string (*)(const TcpConfig&);

struct FieldEntry {
  std::string_view name;
  FieldSetter set;
  FieldGetter get;
};

template <auto Member, Unit U>
std::expected<void, std::string> set_member(TcpConfig& c, std::string_view v) {
  using T = std::remove_cvref_t<decltype(c.*Member)>;
  auto r = parse_value<T>(v, U);
  if (!r) {
    return std::unexpected(r.error());
  }
  c.*Member = *r;
  return {};
}

template <auto Member>
std::string get_member(const TcpConfig& c) {
  return format_value(c.*Member);
}

// The unit of a def-file knob.
constexpr Unit knob_unit(std::string_view name) {
  return name == "test_fixed_pacing_rate" ? Unit::rate : Unit::count;
}

// Every TcpConfig field in declaration order: X(name, unit). The def-file
// knobs follow, added by the UTCP_TCP_KNOB expansion below.
#define UTCP_CONFIG_FIELDS(X)                                                              \
  X(rto_min, count) X(rto_initial, count) X(rto_max, count) X(rto_after_syn_rexmit, count)  \
  X(rtt_estimator, count) X(rtt_sample_rule, count) X(initial_cwnd, count)                 \
  X(iw_after_syn_loss, count) X(initial_ssthresh, count) X(idle_restart, count)            \
  X(cwnd_growth_needs_cwnd_limited, count) X(recovery_reduction, count) X(rack_tlp, count) \
  X(dupthresh, count) X(adaptive_reordering, count) X(max_reordering, count) X(cc, count)  \
  X(cc_flavor, count) X(hystart, count) X(hystart_low_window, count)                       \
  X(hystart_ack_delta, count) X(pacing, count) X(pacing_ss_ratio, count)                   \
  X(pacing_ca_ratio, count) X(gso_max_size, bytes) X(delack_max, count)                    \
  X(delack_ato, count) X(delack_ato_min, count) X(ack_every_full_segments, count)          \
  X(quickack, count) X(quickack_max, count) X(nagle, count) X(nodelay, count)              \
  X(sender_sws, count) X(zero_window_probe, count) X(mss_clamp, count) X(sack, count)      \
  X(timestamps, count) X(window_scaling, count) X(dsack, count) X(ts_offset_random, count) \
  X(paws_disordered_ack, count) X(rcv_wscale, count) X(snd_buf_init, bytes)                \
  X(snd_buf_max, bytes) X(rcv_buf_init, bytes) X(rcv_buf_max, bytes)                       \
  X(rcv_window_growth, count) X(syn_window, count) X(window_update_after_read, count)      \
  X(syn_retries, count) X(syn_linear_timeouts, count) X(synack_retries, count)             \
  X(data_retries, count) X(time_wait, count) X(rst_in_time_wait, count)                    \
  X(orphan_fin_wait2_timeout, count) X(oow_ack_interval, count) X(ephemeral_ports, count)  \
  X(default_snd_mss, count) X(min_snd_mss, count) X(min_pmtu, count) X(pmtu_expiry, count)

#define UTCP_FIELD_ENTRY(name, unit) \
  FieldEntry{#name, &set_member<&TcpConfig::name, Unit::unit>, &get_member<&TcpConfig::name>},
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) \
  FieldEntry{#name, &set_member<&TcpConfig::name, knob_unit(#name)>, &get_member<&TcpConfig::name>},
#define UTCP_STACK_KNOB(type, name, value, doc)
constexpr FieldEntry config_fields[] = {
    UTCP_CONFIG_FIELDS(UTCP_FIELD_ENTRY)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
};
#undef UTCP_FIELD_ENTRY
#define UTCP_FIELD_NAME(name, unit) std::string_view{#name},
#undef UTCP_TCP_KNOB
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) std::string_view{#name},
constexpr std::string_view config_field_name_list[] = {
    UTCP_CONFIG_FIELDS(UTCP_FIELD_NAME)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
};
#undef UTCP_FIELD_NAME
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
#undef UTCP_CONFIG_FIELDS

const FieldEntry* find_field(std::string_view name) {
  for (const FieldEntry& f : config_fields) {
    if (f.name == name) {
      return &f;
    }
  }
  return nullptr;
}

}  // namespace

TcpConfig tcp_config(ProfileId profile) {
  return profile == ProfileId::rfc ? rfc_profile() : linux_profile();
}

std::optional<std::string> check_tcp_config(const TcpConfig& c) {
  if (c.rack_tlp && c.recovery_reduction == RecoveryReduction::rfc6675) {
    return std::string(
        "rack_tlp with recovery_reduction = rfc6675: RFC 8985 §9.2 says RFC 6675 recovery MUST "
        "NOT be used with RACK-TLP (use rack_tlp = false, or recovery_reduction = prr)");
  }
  return std::nullopt;
}

std::expected<void, std::string> set_config_field(TcpConfig& c, std::string_view name,
                                                  std::string_view value) {
  const FieldEntry* f = find_field(name);
  if (f == nullptr) {
    return std::unexpected("unknown TcpConfig field '" + std::string(name) + "'");
  }
  auto r = f->set(c, value);
  if (!r) {
    return std::unexpected(std::string(name) + ": " + r.error());
  }
  return {};
}

std::optional<std::string> get_config_field(const TcpConfig& c, std::string_view name) {
  const FieldEntry* f = find_field(name);
  if (f == nullptr) {
    return std::nullopt;
  }
  return f->get(c);
}

std::span<const std::string_view> config_field_names() { return config_field_name_list; }

}  // namespace utcp
