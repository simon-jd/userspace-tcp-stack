// The two TCP profiles against the table of DESIGN §3.9, row by row.
#include "utcp/config.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
  ROW(rack_tlp, false, true)                                                      \
  ROW(dupthresh, 3u, 3u)                                                          \
  ROW(adaptive_reordering, false, true)                                           \
  ROW(max_reordering, 300u, 300u)                                                 \
  ROW(cc, CcAlgo::newreno, CcAlgo::newreno)                                       \
  ROW(cc_flavor, CcFlavor::rfc, CcFlavor::linux)                                  \
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
  EXPECT_FALSE(s.tcp_checksum_offload);
  EXPECT_EQ(s.tcp_gso_buffers, 0u);
  EXPECT_FALSE(s.assert_time_monotonic);
  EXPECT_EQ(s.test_recovery_script, nullptr);
  EXPECT_EQ(utcp::test::field_count<StackConfig>(), 17 + stack_knob_count);

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

// M2-DESIGN §1.2: RFC 8985 §9.2 forbids RFC 6675 recovery with RACK-TLP.
// Both profiles are usable; rfc with PRR (the ablation's PRR row) is too.
TEST(Config, ForbiddenPairingIsRejected) {
  EXPECT_EQ(check_tcp_config(tcp_config(ProfileId::rfc)), std::nullopt);
  EXPECT_EQ(check_tcp_config(tcp_config(ProfileId::linux_compat)), std::nullopt);
  TcpConfig c = tcp_config(ProfileId::rfc);
  c.recovery_reduction = RecoveryReduction::prr;
  EXPECT_EQ(check_tcp_config(c), std::nullopt);
  c = tcp_config(ProfileId::linux_compat);
  c.rack_tlp = false;
  c.recovery_reduction = RecoveryReduction::rfc6675;
  EXPECT_EQ(check_tcp_config(c), std::nullopt);
  c.rack_tlp = true;
  const auto err = check_tcp_config(c);
  ASSERT_TRUE(err.has_value());
  EXPECT_NE(err->find("RFC 8985 §9.2"), std::string::npos) << *err;
  EXPECT_NE(err->find("rack_tlp"), std::string::npos) << *err;
  EXPECT_NE(err->find("rfc6675"), std::string::npos) << *err;
  c = tcp_config(ProfileId::rfc);
  c.rack_tlp = true;
  EXPECT_TRUE(check_tcp_config(c).has_value());
}

// set_config_field knows every TcpConfig field, rows and def-file knobs, in
// declaration order.
TEST(Config, FieldNamesCoverEveryField) {
  const auto names = config_field_names();
  EXPECT_EQ(names.size(), utcp::test::field_count<TcpConfig>());
  EXPECT_EQ(std::set<std::string_view>(names.begin(), names.end()).size(), names.size());
  std::vector<std::string_view> want;
#define NAME_ROW(field, rfc_value, linux_value) want.emplace_back(#field);
  CONFIG_ROWS(NAME_ROW)
#undef NAME_ROW
#define UTCP_TCP_KNOB(type, name, rfc_value, linux_value, doc) want.emplace_back(#name);
#define UTCP_STACK_KNOB(type, name, value, doc)
#include "utcp/defs/config_ip.def"
#include "utcp/defs/config_rx.def"
#include "utcp/defs/config_tx.def"
#include "utcp/defs/config_tcp.def"
#undef UTCP_TCP_KNOB
#undef UTCP_STACK_KNOB
  EXPECT_EQ(std::vector<std::string_view>(names.begin(), names.end()), want);
}

// Every field's text form sets the same value again: copying all fields of
// one profile into the other through text gives that profile, and the text
// of each field reads back unchanged.
TEST(Config, SetConfigFieldRoundTripsEveryField) {
  for (const auto& [from_id, to_id] : {std::pair{ProfileId::rfc, ProfileId::linux_compat},
                                      std::pair{ProfileId::linux_compat, ProfileId::rfc}}) {
    const TcpConfig from = tcp_config(from_id);
    TcpConfig to = tcp_config(to_id);
    for (const std::string_view name : config_field_names()) {
      const auto text = get_config_field(from, name);
      ASSERT_TRUE(text.has_value()) << name;
      const auto r = set_config_field(to, name, *text);
      ASSERT_TRUE(r.has_value()) << name << " = " << *text << ": " << r.error();
      EXPECT_EQ(get_config_field(to, name), text) << name;
    }
    EXPECT_EQ(to, from);
  }
  // Values away from the profiles, so optionals with a value, test knobs
  // and other enumerators are covered too.
  TcpConfig c;
  c.initial_cwnd = std::nullopt;
  c.mss_clamp = 1200;
  c.rcv_wscale = 9;
  c.test_isn = 0xffff0000u;
  c.test_fixed_pacing_rate = 6'250'000;
  c.test_fault = TestFault::double_tlp;
  c.orphan_retries = std::nullopt;
  c.cc = CcAlgo::bbr;
  c.pacing = Pacing::never;
  c.delack_ato_min = 1500us;
  c.pmtu_expiry = 7ns;
  TcpConfig d = tcp_config(ProfileId::rfc);
  for (const std::string_view name : config_field_names()) {
    const auto text = get_config_field(c, name);
    ASSERT_TRUE(text.has_value()) << name;
    ASSERT_TRUE(set_config_field(d, name, *text).has_value()) << name << " = " << *text;
  }
  EXPECT_EQ(d, c);
}

// The accepted text forms, one or more per field type.
TEST(Config, SetConfigFieldParsesEachType) {
  TcpConfig c;
  auto set = [&c](std::string_view name, std::string_view value) {
    const auto r = set_config_field(c, name, value);
    EXPECT_TRUE(r.has_value()) << name << " = " << value << ": " << (r ? "" : r.error());
  };
  set("rto_min", "300ms");  // Duration
  EXPECT_EQ(c.rto_min, 300ms);
  set("rto_max", "2min");
  EXPECT_EQ(c.rto_max, 120s);
  set("hystart_ack_delta", "1500us");
  EXPECT_EQ(c.hystart_ack_delta, 1500us);
  set("delack_ato_min", "40000000ns");
  EXPECT_EQ(c.delack_ato_min, 40ms);
  set("time_wait", "60s");
  EXPECT_EQ(c.time_wait, 60s);
  set("recovery_reduction", "rfc6675");  // enums
  EXPECT_EQ(c.recovery_reduction, RecoveryReduction::rfc6675);
  set("hystart", "hystart_pp");
  EXPECT_EQ(c.hystart, Hystart::hystart_pp);
  set("cc", "reno");
  EXPECT_EQ(c.cc, CcAlgo::newreno);
  set("cc", "cubic");
  EXPECT_EQ(c.cc, CcAlgo::cubic);
  set("cc_flavor", "rfc");
  EXPECT_EQ(c.cc_flavor, CcFlavor::rfc);
  set("test_fault", "ignore_pacing_gate");
  EXPECT_EQ(c.test_fault, TestFault::ignore_pacing_gate);
  set("rack_tlp", "off");  // bool
  EXPECT_FALSE(c.rack_tlp);
  set("rack_tlp", "1");
  EXPECT_TRUE(c.rack_tlp);
  set("sack", "false");
  EXPECT_FALSE(c.sack);
  set("dupthresh", "5");  // integers
  EXPECT_EQ(c.dupthresh, 5u);
  set("syn_retries", "255");
  EXPECT_EQ(c.syn_retries, 255);
  set("min_pmtu", "1280");
  EXPECT_EQ(c.min_pmtu, 1280);
  set("snd_buf_max", "64Mi");  // sizes
  EXPECT_EQ(c.snd_buf_max, 64 * MiB);
  set("rcv_buf_max", "32Mi");
  EXPECT_EQ(c.rcv_buf_max, 32 * MiB);
  set("snd_buf_init", "16Ki");
  EXPECT_EQ(c.snd_buf_init, 16 * KiB);
  set("gso_max_size", "65215");
  EXPECT_EQ(c.gso_max_size, 65215u);
  set("test_fixed_pacing_rate", "50Mbit");  // rates: payload bytes/s
  EXPECT_EQ(c.test_fixed_pacing_rate, std::optional<std::uint64_t>{6'250'000});
  set("test_fixed_pacing_rate", "1Gbit");
  EXPECT_EQ(c.test_fixed_pacing_rate, std::optional<std::uint64_t>{125'000'000});
  set("test_fixed_pacing_rate", "800kbit");
  EXPECT_EQ(c.test_fixed_pacing_rate, std::optional<std::uint64_t>{100'000});
  set("test_fixed_pacing_rate", "1448000");
  EXPECT_EQ(c.test_fixed_pacing_rate, std::optional<std::uint64_t>{1'448'000});
  set("test_fixed_pacing_rate", "none");  // optionals
  EXPECT_EQ(c.test_fixed_pacing_rate, std::nullopt);
  set("initial_cwnd", "none");
  EXPECT_EQ(c.initial_cwnd, std::nullopt);
  set("initial_cwnd", "4");
  EXPECT_EQ(c.initial_cwnd, OptU32{4u});
  set("mss_clamp", "1400");
  EXPECT_EQ(c.mss_clamp, OptU16{1400});
  set("rcv_wscale", "14");
  EXPECT_EQ(c.rcv_wscale, OptU8{14});
  set("ephemeral_ports", "40000-40009");  // PortRange
  EXPECT_EQ(c.ephemeral_ports, (PortRange{40000, 40009}));

  EXPECT_EQ(get_config_field(c, "rto_max"), "2min");
  EXPECT_EQ(get_config_field(c, "hystart_ack_delta"), "1500us");
  EXPECT_EQ(get_config_field(c, "snd_buf_max"), "67108864");
  EXPECT_EQ(get_config_field(c, "ephemeral_ports"), "40000-40009");
  EXPECT_EQ(get_config_field(c, "test_fixed_pacing_rate"), "none");
  EXPECT_EQ(get_config_field(c, "rack_tlp"), "true");
  EXPECT_EQ(get_config_field(c, "no_such_field"), std::nullopt);
}

// Unknown names and values that do not parse or do not fit are errors that
// name the field, and leave the configuration unchanged.
TEST(Config, SetConfigFieldRejectsUnknownNamesAndBadValues) {
  const TcpConfig before = tcp_config(ProfileId::linux_compat);
  TcpConfig c = before;
  const auto unknown = set_config_field(c, "rack", "on");
  ASSERT_FALSE(unknown.has_value());
  EXPECT_NE(unknown.error().find("rack"), std::string::npos);
  const std::pair<std::string_view, std::string_view> bad[] = {
      {"rto_min", "200"},            // a duration needs a unit
      {"rto_min", "200 ms"},
      {"rto_min", "-1ms"},
      {"rto_min", "2h"},
      {"rto_min", "999999999999min"},  // beyond the Duration range
      {"rto_min", ""},
      {"recovery_reduction", "fast"},
      {"recovery_reduction", "PRR"},
      {"cc", "vegas"},
      {"test_fault", "nothing"},
      {"rack_tlp", "yes"},
      {"dupthresh", "3x"},
      {"dupthresh", "64Ki"},        // sizes only on byte fields
      {"dupthresh", "4294967296"},  // above std::uint32_t
      {"dupthresh", "-3"},
      {"dupthresh", "99999999999999999999999"},
      {"syn_retries", "256"},       // above std::uint8_t
      {"mss_clamp", "65536"},
      {"snd_buf_max", "4Gi"},       // above std::uint32_t
      {"snd_buf_max", "64Mbit"},    // rates only on rate fields
      {"snd_buf_max", "64MB"},
      {"test_fixed_pacing_rate", "1bit"},  // not whole bytes/s
      {"test_fixed_pacing_rate", "50Mi"},
      {"test_fixed_pacing_rate", "50mbit"},
      {"initial_cwnd", "nil"},
      {"ephemeral_ports", "1024"},
      {"ephemeral_ports", "1024-70000"},
  };
  for (const auto& [name, value] : bad) {
    const auto r = set_config_field(c, name, value);
    ASSERT_FALSE(r.has_value()) << name << " = '" << value << "'";
    EXPECT_TRUE(r.error().starts_with(std::string(name) + ": ")) << r.error();
    EXPECT_EQ(c, before) << name << " = '" << value << "'";
  }
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
  EXPECT_EQ(to_string(CcFlavor::rfc), "rfc");
  EXPECT_EQ(to_string(CcFlavor::linux), "linux");
}

}  // namespace
