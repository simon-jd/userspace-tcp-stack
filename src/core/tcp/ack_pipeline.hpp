// The per-ACK pipeline (DESIGN §5.1). Interface declared by m1-found;
// implemented by m1-tx (ack_pipeline.cpp).
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
};

// Runs Linux tcp_ack order: SendQueue::on_sack (tcp_sacktag_write_queue);
// on_cumulative_ack (tcp_clean_rtx_queue), whose per-segment callbacks feed
// LossRecovery::on_delivered and the rate sampler; RTT samples (§4.8: seq_rtt
// from the first newly acked segment unless retransmitted data is acked,
// ca_rtt from the last (S)ACKed one, TSecr fallback) and pkts_acked;
// LossRecovery::on_ack (tcp_fastretrans_alert); delivered and lost counts;
// the rate sample (tcp_rate_gen, M2b); then cong_control, or cong_avoid
// outside cwnd reduction, and the pacing rate (tcp_cong_control). Clips
// in.new_una and the SACK blocks to end() and reports the FIN ACK; a SACK
// block must start above the new SND.UNA (Linux tcp_is_sackblock_valid).
// A valid RTT sample (out.seq_rtt >= 0) means the engine resets backoff
// (RFC 6298 §5.7); the timers recovery re-armed already assume it. The engine
// then updates the window, timers and state.
AckOutcome process_ack(AckContext& c, const AckInput& in);

}  // namespace utcp
