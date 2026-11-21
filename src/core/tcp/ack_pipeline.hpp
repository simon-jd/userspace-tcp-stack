// The per-ACK pipeline (DESIGN §5.1). Interface declared by m1-found and
// extended by m2-found (M2-DESIGN §1.6, §1.8, §2.1); implemented by m1-tx,
// then m2-found (ack_pipeline.cpp). A contract from M2 on.
#pragma once

#include <cstdint>

#include "core/tcp/cc.hpp"
#include "core/tcp/rate.hpp"
#include "core/tcp/recovery.hpp"
#include "core/tcp/rtt.hpp"
#include "core/tcp/send_queue.hpp"
#include "utcp/config.hpp"
#include "utcp/stats.hpp"

namespace utcp {

// The send-side state of one connection that process_ack updates.
struct AckContext {
  SendQueue& q;
  LossRecovery& recovery;
  RttEstimator& rtt;
  CcConn& cc;
  CongestionControl& algo;
  RateState& rate;
  const TcpConfig& cfg;
  StackStats& stats;   // TcpExtTCPDSACKRecv, TcpExtTCPDelivered, ...
  TcpCounters& ctr;    // dsack_dups, ...
  std::uint32_t snd_wnd;  // bytes, scaled
  bool sack_ok;
  std::uint8_t backoff;
  std::uint8_t rto_count;
  // M2: the inputs of RecoveryCtx's M2 fields (M2-DESIGN §1.6).
  std::uint32_t max_snd_wnd = 0;  // bytes, scaled (Linux max_window): D-SACK length bound
  std::uint32_t ts_offset = 0;    // the connection's TS clock offset (RecoveryCtx::ts_of)
  Duration pacing_delay{0};       // RecoveryCtx::pacing_delay
  // The ACK's rate sample; AckOutcome::rs points here, so it is valid while
  // this context lives.
  RateSample sample{};
  RecoveryTransition on_transition{};
};

// Runs Linux tcp_ack order: the D-SACK block (tcp_dsack_seen: ignored if
// longer than max_snd_wnd, else ceil(len/mss) segments added to dsack_dups,
// and if dsack_dups then stays <= total_retrans the D-SACK is valid: those
// segments count as delivered and the ACK gets ack_dsack, M2-DESIGN §1.6);
// SendQueue::on_sack (tcp_sacktag_write_queue);
// on_cumulative_ack (tcp_clean_rtx_queue), whose per-segment callbacks feed
// LossRecovery::on_delivered and the rate sampler; RTT samples (§4.8: seq_rtt
// from the first newly acked segment unless retransmitted data is acked,
// ca_rtt from the last (S)ACKed one, TSecr fallback) and pkts_acked;
// LossRecovery::on_ack (tcp_fastretrans_alert); delivered and lost counts;
// the rate sample (tcp_rate_gen; AckOutcome::rs); then tcp_cong_control:
// the CC's cong_control if it has one (RateState::app_limited copied back
// from CcConn after it), else LossRecovery::cwnd_reduction in CWR and
// Recovery, else cong_avoid if LossRecovery::may_raise_cwnd, and then the
// pacing rate (M2-DESIGN §1.8). Clips
// in.new_una and the SACK blocks to end() and reports the first ACK that
// covers our FIN (ack_fin_acked); a SACK block must start above the new
// SND.UNA (Linux tcp_is_sackblock_valid). A valid RTT sample (out.seq_rtt >=
// 0) means the engine resets backoff (RFC 6298 §5.7); the timers recovery
// re-armed already assume it. The engine then updates the window, timers and
// state.
AckOutcome process_ack(AckContext& c, const AckInput& in);
// The same, calling `observe` first for each newly delivered TxSeg, in the
// order the pipeline delivers them: SACKed segments (via_sack) before the
// cumulatively acknowledged ones, each group in sequence order (tracing and
// the pipeline-order test).
AckOutcome process_ack(AckContext& c, const AckInput& in, DeliveredFn observe);

}  // namespace utcp
