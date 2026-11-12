// Stack counters, per-connection counters and TcpInfo (DESIGN §10.1).
//
// StackStats and TcpCounters are generated from include/utcp/defs/stats_*.def,
// one file per owning task. for_each_stat/for_each_counter/for_each_field
// visit every field with its name, in declaration order, for writers (JSONL)
// and tests.
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <string_view>

#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

struct StackStats {
#define UTCP_STACK_STAT(name, doc) std::uint64_t name = 0;
#define UTCP_CONN_STAT(name, doc)
#include "utcp/defs/stats_ip.def"
#include "utcp/defs/stats_icmp.def"
#include "utcp/defs/stats_udp.def"
#include "utcp/defs/stats_rx.def"
#include "utcp/defs/stats_tx.def"
#include "utcp/defs/stats_tcp.def"
#undef UTCP_STACK_STAT
#undef UTCP_CONN_STAT

  bool operator==(const StackStats&) const = default;
};

// f(std::string_view name, std::uint64_t value) for every StackStats field.
template <class F>
void for_each_stat(const StackStats& s, F&& f) {
#define UTCP_STACK_STAT(name, doc) f(std::string_view{#name}, s.name);
#define UTCP_CONN_STAT(name, doc)
#include "utcp/defs/stats_ip.def"
#include "utcp/defs/stats_icmp.def"
#include "utcp/defs/stats_udp.def"
#include "utcp/defs/stats_rx.def"
#include "utcp/defs/stats_tx.def"
#include "utcp/defs/stats_tcp.def"
#undef UTCP_STACK_STAT
#undef UTCP_CONN_STAT
}

// Per-connection counters, kept in the TCB and reported through TcpInfo.
struct TcpCounters {
#define UTCP_STACK_STAT(name, doc)
#define UTCP_CONN_STAT(name, doc) std::uint64_t name = 0;
#include "utcp/defs/stats_rx.def"
#include "utcp/defs/stats_tx.def"
#include "utcp/defs/stats_tcp.def"
#undef UTCP_STACK_STAT
#undef UTCP_CONN_STAT

  bool operator==(const TcpCounters&) const = default;
};

// f(std::string_view name, std::uint64_t value) for every TcpCounters field.
template <class F>
void for_each_counter(const TcpCounters& c, F&& f) {
#define UTCP_STACK_STAT(name, doc)
#define UTCP_CONN_STAT(name, doc) f(std::string_view{#name}, c.name);
#include "utcp/defs/stats_rx.def"
#include "utcp/defs/stats_tx.def"
#include "utcp/defs/stats_tcp.def"
#undef UTCP_STACK_STAT
#undef UTCP_CONN_STAT
}

// Connection statistics (Stack::tcp_info). Field names follow `ss -ti`; the
// comments give the TCP_INFO field, so KernelTransport fills the same struct
// (ConnSample). Units: Duration fields are exact, cwnd and ssthresh are
// packets, rates are bytes per second, windows and buffers are bytes.
struct TcpInfo {
  std::array<char, 16> cc_name{};  // NUL-padded, TCP_CONGESTION; "newreno", "cubic", "bbr"
  TcpState state = TcpState::closed;  // tcpi_state
  CaState ca_state = CaState::open;   // tcpi_ca_state
  std::uint8_t snd_wscale = 0;        // tcpi_snd_wscale (peer's shift)
  std::uint8_t rcv_wscale = 0;        // tcpi_rcv_wscale (our shift)

  Duration rto{};      // tcpi_rto, with backoff
  Duration ato{};      // tcpi_ato
  Duration srtt{};     // tcpi_rtt
  Duration rttvar{};   // tcpi_rttvar
  Duration min_rtt{};  // tcpi_min_rtt
  std::uint32_t cwnd = 0;      // tcpi_snd_cwnd
  std::uint32_t ssthresh = 0;  // tcpi_snd_ssthresh

  std::uint32_t snd_mss = 0;  // tcpi_snd_mss (mss_cache)
  std::uint32_t rcv_mss = 0;  // tcpi_rcv_mss
  std::uint32_t adv_mss = 0;  // tcpi_advmss
  std::uint32_t pmtu = 0;     // tcpi_pmtu

  std::uint64_t bytes_sent = 0;      // tcpi_bytes_sent, retransmissions included
  std::uint64_t bytes_retrans = 0;   // tcpi_bytes_retrans
  std::uint64_t bytes_acked = 0;     // tcpi_bytes_acked
  std::uint64_t bytes_received = 0;  // tcpi_bytes_received
  std::uint64_t segs_out = 0;        // tcpi_segs_out
  std::uint64_t segs_in = 0;         // tcpi_segs_in
  std::uint64_t data_segs_out = 0;   // tcpi_data_segs_out
  std::uint64_t data_segs_in = 0;    // tcpi_data_segs_in

  std::uint64_t pacing_rate = 0;    // tcpi_pacing_rate
  std::uint64_t delivery_rate = 0;  // tcpi_delivery_rate
  std::uint64_t delivered = 0;      // tcpi_delivered, packets
  bool app_limited = false;         // tcpi_delivery_rate_app_limited

  Duration busy_time{};       // tcpi_busy_time
  Duration rwnd_limited{};    // tcpi_rwnd_limited
  Duration sndbuf_limited{};  // tcpi_sndbuf_limited

  std::uint32_t unacked = 0;        // tcpi_unacked (packets_out)
  std::uint32_t sacked = 0;         // tcpi_sacked
  std::uint32_t lost = 0;           // tcpi_lost
  std::uint32_t retrans = 0;        // tcpi_retrans (retrans_out)
  std::uint32_t total_retrans = 0;  // tcpi_total_retrans

  std::uint32_t dsack_dups = 0;     // tcpi_dsack_dups
  std::uint32_t reordering = 0;     // tcpi_reordering (dupthresh)
  std::uint32_t reord_seen = 0;     // tcpi_reord_seen
  Duration rcv_rtt{};               // tcpi_rcv_rtt
  std::uint32_t rcv_space = 0;      // tcpi_rcv_space
  std::uint32_t rcv_ssthresh = 0;   // tcpi_rcv_ssthresh
  std::uint32_t snd_wnd = 0;        // tcpi_snd_wnd
  std::uint32_t rcv_wnd = 0;        // tcpi_rcv_wnd
  std::uint32_t notsent_bytes = 0;  // tcpi_notsent_bytes

  Duration last_data_sent{};  // tcpi_last_data_sent: time since
  Duration last_data_recv{};  // tcpi_last_data_recv
  Duration last_ack_recv{};   // tcpi_last_ack_recv

  // Not in TCP_INFO: the connection's TraceEvent::conn_id, which links a
  // Handle to its trace events (§10.2); 0 for kernel sockets.
  std::uint32_t conn_id = 0;

  [[nodiscard]] std::string_view cc_name_view() const noexcept {
    const auto end = std::find(cc_name.begin(), cc_name.end(), '\0');
    return {cc_name.data(), static_cast<std::size_t>(end - cc_name.begin())};
  }
  // Truncates to 15 characters.
  void set_cc_name(std::string_view name) noexcept {
    cc_name.fill('\0');
    std::copy_n(name.begin(), std::min(name.size(), cc_name.size() - 1), cc_name.begin());
  }

  bool operator==(const TcpInfo&) const = default;
};

// f(std::string_view name, const auto& value) for every TcpInfo field, in
// declaration order. cc_name is passed as std::string_view.
template <class F>
void for_each_field(const TcpInfo& i, F&& f) {
  f(std::string_view{"cc_name"}, i.cc_name_view());
  f(std::string_view{"state"}, i.state);
  f(std::string_view{"ca_state"}, i.ca_state);
  f(std::string_view{"snd_wscale"}, i.snd_wscale);
  f(std::string_view{"rcv_wscale"}, i.rcv_wscale);
  f(std::string_view{"rto"}, i.rto);
  f(std::string_view{"ato"}, i.ato);
  f(std::string_view{"srtt"}, i.srtt);
  f(std::string_view{"rttvar"}, i.rttvar);
  f(std::string_view{"min_rtt"}, i.min_rtt);
  f(std::string_view{"cwnd"}, i.cwnd);
  f(std::string_view{"ssthresh"}, i.ssthresh);
  f(std::string_view{"snd_mss"}, i.snd_mss);
  f(std::string_view{"rcv_mss"}, i.rcv_mss);
  f(std::string_view{"adv_mss"}, i.adv_mss);
  f(std::string_view{"pmtu"}, i.pmtu);
  f(std::string_view{"bytes_sent"}, i.bytes_sent);
  f(std::string_view{"bytes_retrans"}, i.bytes_retrans);
  f(std::string_view{"bytes_acked"}, i.bytes_acked);
  f(std::string_view{"bytes_received"}, i.bytes_received);
  f(std::string_view{"segs_out"}, i.segs_out);
  f(std::string_view{"segs_in"}, i.segs_in);
  f(std::string_view{"data_segs_out"}, i.data_segs_out);
  f(std::string_view{"data_segs_in"}, i.data_segs_in);
  f(std::string_view{"pacing_rate"}, i.pacing_rate);
  f(std::string_view{"delivery_rate"}, i.delivery_rate);
  f(std::string_view{"delivered"}, i.delivered);
  f(std::string_view{"app_limited"}, i.app_limited);
  f(std::string_view{"busy_time"}, i.busy_time);
  f(std::string_view{"rwnd_limited"}, i.rwnd_limited);
  f(std::string_view{"sndbuf_limited"}, i.sndbuf_limited);
  f(std::string_view{"unacked"}, i.unacked);
  f(std::string_view{"sacked"}, i.sacked);
  f(std::string_view{"lost"}, i.lost);
  f(std::string_view{"retrans"}, i.retrans);
  f(std::string_view{"total_retrans"}, i.total_retrans);
  f(std::string_view{"dsack_dups"}, i.dsack_dups);
  f(std::string_view{"reordering"}, i.reordering);
  f(std::string_view{"reord_seen"}, i.reord_seen);
  f(std::string_view{"rcv_rtt"}, i.rcv_rtt);
  f(std::string_view{"rcv_space"}, i.rcv_space);
  f(std::string_view{"rcv_ssthresh"}, i.rcv_ssthresh);
  f(std::string_view{"snd_wnd"}, i.snd_wnd);
  f(std::string_view{"rcv_wnd"}, i.rcv_wnd);
  f(std::string_view{"notsent_bytes"}, i.notsent_bytes);
  f(std::string_view{"last_data_sent"}, i.last_data_sent);
  f(std::string_view{"last_data_recv"}, i.last_data_recv);
  f(std::string_view{"last_ack_recv"}, i.last_ack_recv);
  f(std::string_view{"conn_id"}, i.conn_id);
}

}  // namespace utcp
