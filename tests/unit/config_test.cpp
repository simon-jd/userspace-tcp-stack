// The two TCP profiles against the table of DESIGN §3.9, row by row.
#include "utcp/config.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>

#include "support/field_count.hpp"

namespace {

using namespace utcp;  // NOLINT(google-build-using-namespace): the rows read as the table

using OptU8 = std::optional<std::uint8_t>;
using OptU16 = std::optional<std::uint16_t>;
using OptU32 = std::optional<std::uint32_t>;

constexpr std::uint32_t KiB = 1024;
constexpr std::uint32_t MiB = 1024 * 1024;

// ROW(field, rfc, linux_compat): one entry per TcpConfig field outside the
// def-file knobs, in declaration order. Values with a top-level comma are
// parenthesised.
#define CONFIG_ROWS(ROW)                                                          \
  ROW(rto_min, 1s, 200ms)                                                         \
  ROW(rto_initial, 1s, 1s)                                                        \
  ROW(rto_max, 60s, 120s)                                                         \
  ROW(rto_after_syn_rexmit, 3s, 3s)                                               \
  ROW(rtt_estimator, RttEstimatorKind::rfc6298, RttEstimatorKind::linux)          \
  ROW(rtt_sample_rule, RttSampleRule::linux, RttSampleRule::linux)                \
  ROW(initial_cwnd, OptU32{}, OptU32{10u})                                        \
  ROW(iw_after_syn_loss, IwAfterSynLoss::after_any, IwAfterSynLoss::after_more_than_one) \
  ROW(initial_ssthresh, cwnd_infinite, cwnd_infinite)                             \
  ROW(idle_restart, IdleRestart::rfc5681, IdleRestart::linux)                     \
  ROW(cwnd_growth_needs_cwnd_limited, true, true)                                 \
  ROW(recovery_reduction, RecoveryReduction::rfc6675, RecoveryReduction::prr)     \
  ROW(rack_tlp, true, true)                                                       \
  ROW(dupthresh, 3u, 3u)                                                          \
  ROW(adaptive_reordering, false, true)                                           \
  ROW(max_reordering, 300u, 300u)                                                 \
  ROW(cc, CcAlgo::newreno, CcAlgo::newreno)                                       \
  ROW(hystart, Hystart::hystart_pp, Hystart::hystart_classic)                     \
  ROW(hystart_low_window, 16u, 16u)                                               \
  ROW(hystart_ack_delta, 2ms, 2ms)                                                \
  ROW(pacing, Pacing::cc_requested, Pacing::cc_requested)                         \
  ROW(pacing_ss_ratio, 200u, 200u)                                                \
  ROW(pacing_ca_ratio, 120u, 120u)                                                \
  ROW(gso_max_size, 65536u - 320u - 1u, 65536u - 320u - 1u)                       \
  ROW(delack_max, 200ms, 200ms)                                                   \
  ROW(delack_ato, DelackAto::fixed, DelackAto::adaptive)                          \
  ROW(delack_ato_min, 40ms, 40ms)                                                 \
  ROW(ack_every_full_segments, 2u, 2u)                                            \
  ROW(quickack, Quickack::rfc, Quickack::linux)                                   \
  ROW(quickack_max, 16u, 16u)                                                     \
  ROW(nagle, Nagle::rfc896, Nagle::minshall)                                      \
  ROW(nodelay, false, false)                                                      \
  ROW(sender_sws, true, true)                                                     \
  ROW(zero_window_probe, ZeroWindowProbe::linux_zero_length, ZeroWindowProbe::linux_zero_length) \
  ROW(mss_clamp, OptU16{}, OptU16{})                                              \
  ROW(sack, true, true)                                                           \
  ROW(timestamps, true, true)                                                     \
  ROW(window_scaling, true, true)                                                 \
  ROW(dsack, true, true)                                                          \
  ROW(ts_offset_random, true, true)                                               \
  ROW(paws_disordered_ack, PawsDisorderedAck::strict, PawsDisorderedAck::linux)   \
  ROW(rcv_wscale, OptU8{}, OptU8{})                                               \
  ROW(snd_buf_init, 4 * MiB, 16 * KiB)                                            \
  ROW(snd_buf_max, 4 * MiB, 4 * MiB)                                              \
  ROW(rcv_buf_init, 4 * MiB, 128 * KiB)                                           \
  ROW(rcv_buf_max, 4 * MiB, 32 * MiB)                                             \
  ROW(rcv_window_growth, RcvWindowGrowth::free_space, RcvWindowGrowth::linux)     \
  ROW(syn_window, SynWindow::rfc, SynWindow::linux)                               \
  ROW(window_update_after_read, WindowUpdateAfterRead::rfc, WindowUpdateAfterRead::linux) \
  ROW(syn_retries, 7, 6)                                                          \
  ROW(syn_linear_timeouts, 0, 4)                                                  \
  ROW(synack_retries, 5, 5)                                                       \
  ROW(data_retries, 15, 15)                                                       \
  ROW(time_wait, 240s, 60s)                                                       \
  ROW(rst_in_time_wait, RstInTimeWait::ignore, RstInTimeWait::accept)             \
  ROW(orphan_fin_wait2_timeout, 240s, 60s)                                        \
  ROW(oow_ack_interval, 500ms, 500ms)                                             \
  ROW(ephemeral_ports, (PortRange{1024, 65535}), (PortRange{32768, 60999}))       \
  ROW(default_snd_mss, 536, 536)                                                  \
  ROW(min_snd_mss, 48, 48)                                                        \
  ROW(min_pmtu, 552, 552)                                                         \
  ROW(pmtu_expiry, 10min, 10min)

#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) +1
#define UTCP_STACK_KNOB(type, name, value, doc)
constexpr std::size_t tcp_knob_count = 0
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
    ;
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB

#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc)
#define UTCP_STACK_KNOB(type, name, value, doc) +1
constexpr std::size_t stack_knob_count = 0
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
    ;
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB

#define COUNT_ROW(field, rfc_value, linux_value) +1
constexpr std::size_t row_count = 0 CONFIG_ROWS(COUNT_ROW);
#undef COUNT_ROW

TEST(Config, RfcProfileMatchesTheDesignTable) {
  const TcpConfig c = tcp_config(ProfileId::rfc);
#define CHECK_RFC(field, rfc_value, linux_value) EXPECT_EQ(c.field, rfc_value) << #field;
  CONFIG_ROWS(CHECK_RFC)
#undef CHECK_RFC
}

TEST(Config, LinuxCompatProfileMatchesTheDesignTable) {
  const TcpConfig c = tcp_config(ProfileId::linux_compat);
#define CHECK_LINUX(field, rfc_value, linux_value) EXPECT_EQ(c.field, linux_value) << #field;
  CONFIG_ROWS(CHECK_LINUX)
#undef CHECK_LINUX
}

TEST(Config, KnobsHaveTheirDeclaredProfileValues) {
  const TcpConfig rfc = tcp_config(ProfileId::rfc);
  const TcpConfig lin = tcp_config(ProfileId::linux_compat);
  const StackConfig stack;
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc)        \
  EXPECT_EQ(rfc.name, static_cast<type>(rfc_value)) << #name;         \
  EXPECT_EQ(lin.name, static_cast<type>(linux_value)) << #name;
#define UTCP_STACK_KNOB(type, name, value, doc) \
  EXPECT_EQ(stack.name, static_cast<type>(value)) << #name;
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
}

// The table covers every field: a new TcpConfig field needs a row here or a
// def-file knob.
TEST(Config, RowsCoverEveryTcpConfigField) {
  EXPECT_EQ(row_count + tcp_knob_count, utcp::test::field_count<TcpConfig>());
  std::set<std::string> names;
#define NAME_ROW(field, rfc_value, linux_value) EXPECT_TRUE(names.insert(#field).second) << #field;
  CONFIG_ROWS(NAME_ROW)
#undef NAME_ROW
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) \
  EXPECT_TRUE(names.insert(#name).second) << #name;
#define UTCP_STACK_KNOB(type, name, value, doc)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
  EXPECT_EQ(names.size(), row_count + tcp_knob_count);
}

// The in-class defaults are the linux_compat profile.
TEST(Config, DefaultConstructedIsLinuxCompat) {
  EXPECT_EQ(TcpConfig{}, tcp_config(ProfileId::linux_compat));
  EXPECT_FALSE(TcpConfig{} == tcp_config(ProfileId::rfc));
}

TEST(Config, ProfilesDifferOnlyInTheirRows) {
  TcpConfig c = tcp_config(ProfileId::linux_compat);
  const TcpConfig rfc = tcp_config(ProfileId::rfc);
#define COPY_ROW(field, rfc_value, linux_value) c.field = rfc.field;
  CONFIG_ROWS(COPY_ROW)
#undef COPY_ROW
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) c.name = rfc.name;
#define UTCP_STACK_KNOB(type, name, value, doc)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
  EXPECT_EQ(c, rfc);
}

TEST(Config, StackUdpAndIcmpDefaults) {
  const StackConfig s;
  EXPECT_EQ(s.local_addr, Ipv4Addr{});
  EXPECT_EQ(s.mtu, 1500);
  EXPECT_EQ(s.ip_ttl, 64);
  EXPECT_EQ(s.seed, Seed{});
  EXPECT_EQ(s.tcp, tcp_config(ProfileId::linux_compat));
  EXPECT_EQ(s.pool_buffers, 4096u);
  EXPECT_EQ(s.tx_queue_packets, 1024u);
  EXPECT_EQ(s.max_connections, 65536u);
  EXPECT_EQ(s.chunk_limit, 1u << 20);
  EXPECT_EQ(s.trace_mask, 0u);
  EXPECT_EQ(s.tx_headroom, 0);
  EXPECT_FALSE(s.assert_time_monotonic);
  EXPECT_EQ(utcp::test::field_count<StackConfig>(), 14 + stack_knob_count);

  EXPECT_EQ(s.udp.rcv_buf, 256 * KiB);
  EXPECT_EQ(s.udp.ephemeral_ports, std::nullopt);  // follows TCP
  EXPECT_EQ(utcp::udp_ephemeral_ports(s), s.tcp.ephemeral_ports);
  EXPECT_EQ(utcp::test::field_count<UdpConfig>(), 2u);

  EXPECT_TRUE(s.icmp.echo_reply);
  EXPECT_EQ(s.icmp.rate_per_s, 1000u);
  EXPECT_EQ(s.icmp.burst, 50u);
  EXPECT_EQ(utcp::test::field_count<IcmpConfig>(), 3u);
}

// §3.9: UDP ephemeral ports "as TCP", whichever profile TCP uses; an
// explicit UdpConfig range wins.
TEST(Config, UdpEphemeralPortsFollowTheTcpProfile) {
  StackConfig s;
  s.tcp = tcp_config(ProfileId::rfc);
  EXPECT_EQ(utcp::udp_ephemeral_ports(s), (utcp::PortRange{1024, 65535}));
  s.tcp = tcp_config(ProfileId::linux_compat);
  EXPECT_EQ(utcp::udp_ephemeral_ports(s), (utcp::PortRange{32768, 60999}));
  s.udp.ephemeral_ports = utcp::PortRange{40000, 40009};
  EXPECT_EQ(utcp::udp_ephemeral_ports(s), (utcp::PortRange{40000, 40009}));
}

// RFC 7323 §2.3: smallest s with 65535 * 2^s >= rcv_buf_max, at most 14.
TEST(Config, DefaultReceiveWindowScale) {
  EXPECT_EQ(default_rcv_wscale(0), 0);
  EXPECT_EQ(default_rcv_wscale(65535), 0);
  EXPECT_EQ(default_rcv_wscale(65536), 1);
  EXPECT_EQ(default_rcv_wscale(131070), 1);
  EXPECT_EQ(default_rcv_wscale(131071), 2);
  EXPECT_EQ(default_rcv_wscale(4 * MiB), 7);
  EXPECT_EQ(default_rcv_wscale(32 * MiB), 10);  // as Linux at tcp_rmem max 32 MiB
  EXPECT_EQ(default_rcv_wscale(0xffff'ffffu), 14);

  EXPECT_EQ(effective_rcv_wscale(tcp_config(ProfileId::rfc)), 7);
  EXPECT_EQ(effective_rcv_wscale(tcp_config(ProfileId::linux_compat)), 10);
  TcpConfig c;
  c.rcv_wscale = 3;
  EXPECT_EQ(effective_rcv_wscale(c), 3);
}

// RFC 5681 §3.1: IW = 4 segments up to SMSS 1095, 3 up to 2190, else 2.
TEST(Config, InitialWindow) {
  EXPECT_EQ(rfc5681_initial_cwnd(536), 4u);
  EXPECT_EQ(rfc5681_initial_cwnd(1095), 4u);
  EXPECT_EQ(rfc5681_initial_cwnd(1096), 3u);
  EXPECT_EQ(rfc5681_initial_cwnd(1460), 3u);
  EXPECT_EQ(rfc5681_initial_cwnd(2190), 3u);
  EXPECT_EQ(rfc5681_initial_cwnd(2191), 2u);
  EXPECT_EQ(rfc5681_initial_cwnd(8960), 2u);

  EXPECT_EQ(effective_initial_cwnd(tcp_config(ProfileId::rfc), 1460), 3u);
  EXPECT_EQ(effective_initial_cwnd(tcp_config(ProfileId::linux_compat), 1460), 10u);
  EXPECT_EQ(effective_initial_cwnd(tcp_config(ProfileId::linux_compat), 536), 10u);
}

TEST(Config, PortRangeSize) {
  EXPECT_EQ((PortRange{1024, 65535}).size(), 64512u);
  EXPECT_EQ((PortRange{32768, 60999}).size(), 28232u);
  EXPECT_EQ((PortRange{0, 65535}).size(), 65536u);
  EXPECT_EQ((PortRange{7, 7}).size(), 1u);
  EXPECT_EQ((PortRange{8, 7}).size(), 0u);
}

TEST(Config, NamesRoundTrip) {
  for (const ProfileId p : {ProfileId::rfc, ProfileId::linux_compat}) {
    EXPECT_EQ(profile_from_string(to_string(p)), p);
  }
  EXPECT_EQ(profile_from_string("linux"), ProfileId::linux_compat);
  EXPECT_EQ(profile_from_string("bsd"), std::nullopt);
  for (const CcAlgo a : {CcAlgo::newreno, CcAlgo::cubic, CcAlgo::bbr}) {
    EXPECT_EQ(cc_from_string(to_string(a)), a);
  }
  EXPECT_EQ(cc_from_string("reno"), CcAlgo::newreno);
  EXPECT_EQ(cc_from_string("vegas"), std::nullopt);
}

}  // namespace
