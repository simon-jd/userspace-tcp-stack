// The shared lists: every counter (DESIGN §10.1 and the sections that count
// drops), test knob (§3.8, §4.6, §5.3, §7.2, §7.3), StackConfig field (§3.9),
// trace kind and field (§10.2) and TcpInfo field (§10.1). The TcpConfig rows
// of §3.9 are listed in config_test.cpp.
//
// Counter and knob lists are subsets: the owning tasks may add entries to
// their def files without editing this test. TraceKind, TxKind, TraceEvent and
// TcpInfo change only with the coordinator, so those lists are exact.
#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "support/field_count.hpp"
#include "utcp/config.hpp"
#include "utcp/stats.hpp"
#include "utcp/trace.hpp"

namespace {

using utcp::StackConfig;
using utcp::StackStats;
using utcp::TcpConfig;
using utcp::TcpCounters;
using utcp::TcpInfo;
using utcp::TraceEvent;
using utcp::TraceKind;
using utcp::TxKind;

std::vector<std::string> stack_stat_names() {
  std::vector<std::string> out;
  utcp::for_each_stat(StackStats{},
                      [&](std::string_view name, std::uint64_t) { out.emplace_back(name); });
  return out;
}

std::vector<std::string> conn_counter_names() {
  std::vector<std::string> out;
  utcp::for_each_counter(TcpCounters{},
                         [&](std::string_view name, std::uint64_t) { out.emplace_back(name); });
  return out;
}

bool contains(const std::vector<std::string>& v, std::string_view name) {
  return std::find(v.begin(), v.end(), name) != v.end();
}

bool is_snake_case(std::string_view s) {
  if (s.empty() || !std::islower(static_cast<unsigned char>(s.front()))) {
    return false;
  }
  for (const char ch : s) {
    const auto c = static_cast<unsigned char>(ch);
    if (!std::islower(c) && !std::isdigit(c) && ch != '_') {
      return false;
    }
  }
  return true;
}

// `nstat -az` form: a MIB group prefix, then the Linux MIB name.
bool is_nstat_name(std::string_view s) {
  for (const std::string_view group : {"IpExt", "Ip", "Icmp", "Udp", "TcpExt", "Tcp"}) {
    if (s.size() > group.size() && s.starts_with(group) &&
        std::isupper(static_cast<unsigned char>(s[group.size()])) &&
        // "IpExt..." must not be read as group "Ip" with MIB name "Ext...".
        !(group == "Ip" && s.starts_with("IpExt")) && !(group == "Tcp" && s.starts_with("TcpExt"))) {
      return true;
    }
  }
  return false;
}

// Stack counters. DESIGN §10.1 names InSegs, OutSegs, RetransSegs,
// InCsumErrors, OutRsts, TCPChallengeACK, PAWSEstab, TCPSACKReneging,
// TCPZeroWindowDrop, frag_dropped and time_regressions; the rest are the drops
// and events the other sections count, with their Linux MIB names.
#define DESIGN_STACK_STATS(X)                                                         \
  /* IP (m1-ip): §1.2 fragments, §3.4 item 4 time regressions */                       \
  X(IpInReceives) X(IpInHdrErrors) X(IpExtInCsumErrors) X(IpExtInTruncatedPkts)       \
  X(IpInAddrErrors) X(IpInUnknownProtos) X(IpInDelivers) X(IpOutRequests)             \
  X(IpOutDiscards) X(frag_dropped) X(time_regressions)                                \
  /* ICMP (m1-ip): §3.7 */                                                             \
  X(IcmpInMsgs) X(IcmpInErrors) X(IcmpInCsumErrors) X(IcmpInDestUnreachs)             \
  X(IcmpInTimeExcds) X(IcmpInSrcQuenchs) X(IcmpInRedirects) X(IcmpInEchos)            \
  X(IcmpInEchoReps) X(IcmpOutMsgs) X(IcmpOutRateLimitGlobal) X(IcmpOutDestUnreachs)   \
  X(IcmpOutEchos) X(IcmpOutEchoReps) X(echo_replies_dropped)                          \
  /* UDP (m1-ip): §3.6 */                                                              \
  X(UdpInDatagrams) X(UdpNoPorts) X(UdpInErrors) X(UdpRcvbufErrors) X(UdpInCsumErrors) \
  X(UdpOutDatagrams) X(udp_icmp_errors)                                               \
  /* Receive side (m1-rx): §4.10 */                                                    \
  X(TcpExtTCPOFOQueue) X(TcpExtTCPOFODrop) X(TcpExtTCPRcvQDrop)                       \
  X(TcpExtTCPZeroWindowDrop) X(TcpExtTCPDSACKOldSent) X(TcpExtTCPDSACKOfoSent)        \
  X(TcpExtDelayedACKs) X(TcpExtTCPToZeroWindowAdv) X(TcpExtTCPFromZeroWindowAdv)      \
  /* Send side (m1-tx): §4.11, §5.3 */                                                 \
  X(TcpExtTCPSACKReneging) X(TcpExtTCPSACKDiscard) X(TcpExtTCPDSACKRecv)              \
  X(TcpExtTCPSackRecovery) X(TcpExtTCPRenoRecovery) X(TcpExtTCPTimeouts)              \
  X(TcpExtTCPFastRetrans) X(TcpExtTCPSlowStartRetrans) X(TcpExtTCPLossProbes)         \
  X(TcpExtTCPOrigDataSent) X(TcpExtTCPDelivered)                                      \
  /* TCP engine (m1-tcp-core, m1-tcp-robust): §4.3, §4.4, §4.7, §4.12 */               \
  X(TcpActiveOpens) X(TcpPassiveOpens) X(TcpAttemptFails) X(TcpEstabResets)           \
  X(TcpInSegs) X(TcpOutSegs) X(TcpRetransSegs) X(TcpInErrs) X(TcpInCsumErrors)        \
  X(TcpOutRsts) X(TcpExtTCPChallengeACK) X(TcpExtTCPSYNChallenge)                     \
  X(TcpExtTCPACKSkippedChallenge) X(TcpExtTCPACKSkippedSeq) X(TcpExtTCPACKSkippedSynRecv) \
  X(TcpExtTCPACKSkippedTimeWait) X(TcpExtPAWSEstab) X(TcpExtListenOverflows)          \
  X(TcpExtListenDrops) X(TcpExtTW) X(TcpExtTCPAbortOnData) X(TcpExtTCPAbortOnClose)   \
  X(TcpExtTCPAbortOnTimeout) X(TcpExtTCPSynRetrans) X(TcpExtTCPWinProbe)              \
  X(icmp_seq_invalid)

// Per-connection counters (TcpInfo, §10.1).
#define DESIGN_CONN_COUNTERS(X)                                                         \
  X(bytes_received) X(data_segs_in) X(rcv_ooopack) X(data_segs_out) X(total_retrans)   \
  X(dsack_dups) X(reord_seen) X(segs_in) X(segs_out) X(paws_drops)

// Test knobs in TcpConfig, with their types.
#define DESIGN_TCP_KNOBS(X)                                       \
  X(test_isn, std::optional<std::uint32_t>)         /* §4.6 */    \
  X(test_fixed_pacing_rate, std::optional<std::uint64_t>) /* §5.3 */ \
  X(test_renege_ppm, std::uint32_t)                 /* §7.2 */    \
  X(test_fault, utcp::TestFault)                    /* §7.3 */

// Compile-time: each listed name is a std::uint64_t member.
#define ASSERT_STACK_STAT(name) \
  static_assert(std::is_same_v<decltype(StackStats::name), std::uint64_t>);
DESIGN_STACK_STATS(ASSERT_STACK_STAT)
#undef ASSERT_STACK_STAT
#define ASSERT_CONN_COUNTER(name) \
  static_assert(std::is_same_v<decltype(TcpCounters::name), std::uint64_t>);
DESIGN_CONN_COUNTERS(ASSERT_CONN_COUNTER)
#undef ASSERT_CONN_COUNTER
#define ASSERT_TCP_KNOB(name, type) static_assert(std::is_same_v<decltype(TcpConfig::name), type>);
DESIGN_TCP_KNOBS(ASSERT_TCP_KNOB)
#undef ASSERT_TCP_KNOB

TEST(Defs, StackStatsDeclareTheDesignCounters) {
  const auto names = stack_stat_names();
#define CHECK_NAME(name) EXPECT_TRUE(contains(names, #name)) << #name;
  DESIGN_STACK_STATS(CHECK_NAME)
#undef CHECK_NAME
}

TEST(Defs, StackStatNamesAreUniqueAndFollowNstat) {
  const auto names = stack_stat_names();
  EXPECT_EQ(std::set<std::string>(names.begin(), names.end()).size(), names.size());
  for (const auto& n : names) {
    EXPECT_TRUE(is_nstat_name(n) || is_snake_case(n)) << n;
  }
  // for_each_stat visits every field.
  EXPECT_EQ(names.size(), utcp::test::field_count<StackStats>());
}

TEST(Defs, ConnectionCountersDeclareTheDesignCounters) {
  const auto names = conn_counter_names();
#define CHECK_NAME(name) EXPECT_TRUE(contains(names, #name)) << #name;
  DESIGN_CONN_COUNTERS(CHECK_NAME)
#undef CHECK_NAME
  EXPECT_EQ(std::set<std::string>(names.begin(), names.end()).size(), names.size());
  for (const auto& n : names) {
    EXPECT_TRUE(is_snake_case(n)) << n;
  }
  EXPECT_EQ(names.size(), utcp::test::field_count<TcpCounters>());
}

TEST(Defs, EveryDefEntryHasADoc) {
  std::size_t stats = 0;
  auto check = [](std::string_view name, std::string_view doc) { EXPECT_FALSE(doc.empty()) << name; };
#define UTCP_STACK_STAT(name, doc) check(#name, doc), ++stats;
#define UTCP_CONN_STAT(name, doc) check(#name, doc), ++stats;
#include "utcp/defs/stats_icmp.def"
#include "utcp/defs/stats_ip.def"
#include "utcp/defs/stats_rx.def"
#include "utcp/defs/stats_tcp.def"
#include "utcp/defs/stats_tx.def"
#include "utcp/defs/stats_udp.def"
#undef UTCP_STACK_STAT
#undef UTCP_CONN_STAT
  EXPECT_EQ(stats, stack_stat_names().size() + conn_counter_names().size());
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) check(#name, doc);
#define UTCP_STACK_KNOB(type, name, value, doc) check(#name, doc);
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tcp.def"
#include "utcp/defs/config_tx.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
}

TEST(Defs, TestKnobsAreDeclared) {
  std::vector<std::string> knobs;
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) knobs.emplace_back(#name);
#define UTCP_STACK_KNOB(type, name, value, doc)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tcp.def"
#include "utcp/defs/config_tx.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
#define CHECK_KNOB(name, type) EXPECT_TRUE(contains(knobs, #name)) << #name;
  DESIGN_TCP_KNOBS(CHECK_KNOB)
#undef CHECK_KNOB
  EXPECT_EQ(std::set<std::string>(knobs.begin(), knobs.end()).size(), knobs.size());
  // Test knobs are off in both profiles.
  for (const auto profile : {utcp::ProfileId::rfc, utcp::ProfileId::linux_compat}) {
    const TcpConfig c = utcp::tcp_config(profile);
    EXPECT_EQ(c.test_isn, std::nullopt);
    EXPECT_EQ(c.test_fixed_pacing_rate, std::nullopt);
    EXPECT_EQ(c.test_renege_ppm, 0u);
    EXPECT_EQ(c.test_fault, utcp::TestFault::none);
  }
}

// DESIGN §3.9 StackConfig, UdpConfig and IcmpConfig fields.
#define DESIGN_STACK_CONFIG(X)                                                    \
  X(StackConfig, local_addr) X(StackConfig, mtu) X(StackConfig, ip_ttl)           \
  X(StackConfig, seed) X(StackConfig, tcp) X(StackConfig, udp) X(StackConfig, icmp) \
  X(StackConfig, pool_buffers) X(StackConfig, tx_queue_packets)                   \
  X(StackConfig, max_connections) X(StackConfig, chunk_limit) X(StackConfig, trace_mask) \
  X(StackConfig, tx_headroom) X(StackConfig, assert_time_monotonic)               \
  X(UdpConfig, rcv_buf) X(UdpConfig, ephemeral_ports)                             \
  X(IcmpConfig, echo_reply) X(IcmpConfig, rate_per_s) X(IcmpConfig, burst)

TEST(Defs, StackConfigFields) {
  std::size_t listed = 0;
#define COUNT_FIELD(type, name)                                           \
  static_assert(std::is_member_object_pointer_v<decltype(&utcp::type::name)>); \
  ++listed;
  DESIGN_STACK_CONFIG(COUNT_FIELD)
#undef COUNT_FIELD
  std::size_t stack_knobs = 0;
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc)
#define UTCP_STACK_KNOB(type, name, value, doc) ++stack_knobs;
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tcp.def"
#include "utcp/defs/config_tx.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
  EXPECT_EQ(listed, utcp::test::field_count<StackConfig>() - stack_knobs +
                        utcp::test::field_count<utcp::UdpConfig>() +
                        utcp::test::field_count<utcp::IcmpConfig>());
}

// DESIGN §10.2, in declaration order.
TEST(Defs, TraceEventFields) {
  const std::vector<std::string> want{
      "t",         "conn_id",   "kind",      "tx",        "state",    "ca",
      "seq",       "ack",       "len",       "wnd",       "cwnd",     "ssthresh",
      "in_flight", "snd_wnd",   "srtt_ns",   "rttvar_ns", "rto_ns",   "delivered",
      "pacing_rate", "delivery_rate", "snd_una_off", "snd_nxt_off"};
  std::vector<std::string> got;
  utcp::for_each_field(TraceEvent{}, [&](std::string_view name, const auto&) { got.emplace_back(name); });
  EXPECT_EQ(got, want);
  EXPECT_EQ(utcp::test::field_count<TraceEvent>(), want.size());
  static_assert(std::is_trivially_copyable_v<TraceEvent>);
}

TEST(Defs, TraceKinds) {
  const std::vector<std::string> kinds{"state", "tx",  "rx",    "ack",      "rtt",  "rto",
                                       "cwnd",  "recovery", "timer", "icmp", "drop"};
  ASSERT_EQ(static_cast<std::size_t>(utcp::trace_kind_count), kinds.size());
  for (int i = 0; i < utcp::trace_kind_count; ++i) {
    const auto k = static_cast<TraceKind>(i);
    EXPECT_EQ(utcp::to_string(k), kinds[static_cast<std::size_t>(i)]);
    EXPECT_EQ(utcp::trace_bit(k), 1u << i);
  }
  EXPECT_EQ(utcp::to_string(static_cast<TraceKind>(utcp::trace_kind_count)), "?");
  EXPECT_EQ(utcp::trace_mask_all, (1u << utcp::trace_kind_count) - 1);
}

TEST(Defs, TxKinds) {
  const std::vector<std::string> kinds{"syn",         "synack", "data",       "fin",
                                       "ack",         "rst",    "fast_rexmit", "rexmit",
                                       "rto_rexmit",  "pmtu_rexmit", "zwp",   "tlp",
                                       "challenge_ack"};
  ASSERT_EQ(static_cast<std::size_t>(utcp::tx_kind_count), kinds.size());
  for (int i = 0; i < utcp::tx_kind_count; ++i) {
    EXPECT_EQ(utcp::to_string(static_cast<TxKind>(i)), kinds[static_cast<std::size_t>(i)]);
  }
  EXPECT_EQ(utcp::to_string(static_cast<TxKind>(utcp::tx_kind_count)), "?");
}

// DESIGN §10.1 table, in row order.
TEST(Defs, TcpInfoFields) {
  const std::vector<std::string> want{
      "cc_name",       "state",          "ca_state",      "snd_wscale",    "rcv_wscale",
      "rto",           "ato",            "srtt",          "rttvar",        "min_rtt",
      "cwnd",          "ssthresh",       "snd_mss",       "rcv_mss",       "adv_mss",
      "pmtu",          "bytes_sent",     "bytes_retrans", "bytes_acked",   "bytes_received",
      "segs_out",      "segs_in",        "data_segs_out", "data_segs_in",  "pacing_rate",
      "delivery_rate", "delivered",      "app_limited",   "busy_time",     "rwnd_limited",
      "sndbuf_limited", "unacked",       "sacked",        "lost",          "retrans",
      "total_retrans", "dsack_dups",     "reordering",    "reord_seen",    "rcv_rtt",
      "rcv_space",     "rcv_ssthresh",   "snd_wnd",       "rcv_wnd",       "notsent_bytes",
      "last_data_sent", "last_data_recv", "last_ack_recv"};
  std::vector<std::string> got;
  utcp::for_each_field(TcpInfo{}, [&](std::string_view name, const auto&) { got.emplace_back(name); });
  EXPECT_EQ(got, want);
  EXPECT_EQ(utcp::test::field_count<TcpInfo>(), want.size());
}

TEST(Defs, TcpInfoCcName) {
  TcpInfo i;
  EXPECT_EQ(i.cc_name_view(), "");
  i.set_cc_name("newreno");
  EXPECT_EQ(i.cc_name_view(), "newreno");
  i.set_cc_name("a-name-longer-than-fifteen-bytes");
  EXPECT_EQ(i.cc_name_view().size(), 15u);
}

}  // namespace
