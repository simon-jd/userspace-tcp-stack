// The two TCP parameter profiles, one assignment per row of DESIGN §3.9.
#include "utcp/config.hpp"

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
  c.rack_tlp = true;                         // RFC 8985; tcp_recovery=1, tcp_early_retrans=3
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
  c.adaptive_reordering = false;
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
  c.adaptive_reordering = true;
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

}  // namespace

TcpConfig tcp_config(ProfileId profile) {
  return profile == ProfileId::rfc ? rfc_profile() : linux_profile();
}

}  // namespace utcp
