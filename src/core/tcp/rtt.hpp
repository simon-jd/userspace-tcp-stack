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
#include "utcp/time.hpp"

namespace utcp {

class RttEstimator {
public:
  explicit RttEstimator(const TcpConfig& cfg);

  [[nodiscard]] bool has_sample() const;
  // An SRTT/RTO sample (seq_rtt). new_round: SND.UNA passed the rtt_seq of
  // the previous round (Linux: after(snd_una, rtt_seq)), which ends a linux
  // round (rttvar decay, mdev_max reset).
  void on_srtt_sample(Duration seq_rtt, bool new_round);
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

// Linux tcp_model_timeout: the time `retries` RTO expiries take with RTO
// starting at rto_base and doubling up to rto_max. Values (m1-tx test 4):
// (15, 200 ms, 120 s) = 924.6 s; (6, 1 s, 120 s) = 127 s; (7, 1 s, 60 s) =
// 183 s; (15, 1 s, 60 s) = 663 s.
[[nodiscard]] Duration retry_abort_time(std::uint8_t retries, Duration rto_base, Duration rto_max);

}  // namespace utcp
