// RTT estimation and the RTO (RFC 6298; Linux tcp_rtt_estimator; DESIGN
// §4.8). Interface declared by m1-found; implemented by m1-tx (rtt.cpp).
//
// Two estimators (TcpConfig::rtt_estimator): rfc6298 (RFC 6298 §2.2-2.3,
// RTO = max(SRTT + max(G, 4 * RTTVAR), rto_min), G = 1 ms) and linux
// (tcp_rtt_estimator line for line in fixed point, RTO = SRTT + rttvar). Both
// are bounded by rto_min and rto_max. Samples follow Linux
// tcp_clean_rtx_queue: seq_rtt feeds SRTT/RTO, ca_rtt feeds min_rtt and the
// CC; the ACK pipeline picks them (§5.1).
#pragma once

#include <cstdint>

#include "utcp/config.hpp"
#include "utcp/retry_model.hpp"
#include "utcp/time.hpp"

namespace utcp {

class RttEstimator {
public:
  explicit RttEstimator(const TcpConfig& cfg);

  [[nodiscard]] bool has_sample() const;
  // An SRTT/RTO sample (seq_rtt), with SND.UNA after the ACK and SND.NXT as
  // stream offsets. The estimator keeps Linux tp->rtt_seq itself: the first
  // sample sets rtt_seq = snd_nxt; a later sample with snd_una > rtt_seq
  // (after(snd_una, rtt_seq)) ends a linux round (rttvar decays by a quarter
  // of its excess over mdev_max, mdev_max resets to rto_min) and sets rtt_seq
  // = snd_nxt again. rfc6298 ignores both offsets.
  void on_srtt_sample(Duration seq_rtt, std::uint64_t snd_una, std::uint64_t snd_nxt);
  // A min_rtt sample (ca_rtt): Linux minmax_running_min over a 300 s window
  // (tcp_update_rtt_min); a maybe-delayed sample above min_rtt is skipped.
  void on_min_rtt_sample(Duration ca_rtt, bool maybe_delayed, Time now);

  [[nodiscard]] Duration srtt() const;
  [[nodiscard]] Duration rttvar() const;
  [[nodiscard]] Duration min_rtt() const;  // windowed min over 300 s; Duration::max() before any sample
  // Without backoff, bounded by rto_min and rto_max; rto_initial before any sample.
  [[nodiscard]] Duration rto() const;
  // min(rto() << backoff, rto_max).
  [[nodiscard]] Duration rto_backed_off(std::uint8_t backoff) const;
  // RFC 6298 §5.7: after a SYN retransmission and no RTT sample, RTO =
  // rto_after_syn_rexmit (3 s).
  void reset_after_syn_rexmit();

private:
  // Implementation state is m1-tx's.
};

// retry_abort_time (Linux tcp_model_timeout, the abort bound of §4.8) is
// declared in utcp/retry_model.hpp and defined in src/core/retry_model.cpp
// (m1-found), because the simulator's ProgressChecker uses it too.

}  // namespace utcp
