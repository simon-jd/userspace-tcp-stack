#include "core/tcp/rate.hpp"

#include <algorithm>

#include "core/tcp/send_queue.hpp"

namespace utcp {
namespace {

// tcp_skb_sent_after: sent later, or at the same time with a higher end.
constexpr bool sent_after(Time t1, Time t2, std::uint64_t end1, std::uint64_t end2) noexcept {
  return t1 > t2 || (t1 == t2 && end1 > end2);
}

}  // namespace

void rate_on_send(RateState& rs, std::uint32_t packets_out, Time now) {
  // packets_out, not packets_in_flight: after an RTO marks everything lost
  // in-flight is 0, and restarting the interval then would give a spuriously
  // short interval and a high bandwidth sample (tcp_rate_skb_sent).
  if (packets_out == 0) {
    rs.first_tx_time = now;
    rs.delivered_time = now;
    rs.has_sent = true;
  }
}

void rate_on_delivered(RateState& rs, RateAck& ack, const TxSeg& seg, Time now) {
  static_cast<void>(now);
  if (seg.rate_used) {
    return;  // no snapshot, or a SACK already used it
  }
  // Keep the snapshot of the most recently sent delivered segment.
  if (!ack.has_prior || sent_after(seg.last_tx, rs.first_tx_time, seg.end(), ack.prior_end)) {
    ack.has_prior = true;
    ack.prior_delivered = seg.delivered;
    ack.prior_time = seg.delivered_time;
    ack.prior_last_tx = seg.last_tx;
    ack.prior_first_tx_time = seg.first_tx_time;
    ack.prior_end = seg.end();
    ack.is_app_limited = seg.app_limited;
    ack.is_retrans = seg.ever_retrans;
    // Record the send time of the most recently delivered segment: the
    // next send phase starts there.
    rs.first_tx_time = seg.last_tx;
  }
}

RateSample rate_gen(RateState& rs, const RateAck& ack, std::uint32_t acked_sacked,
                    std::uint32_t lost, std::uint32_t prior_in_flight, bool is_sack_reneg,
                    Duration min_rtt, Duration ca_rtt, bool maybe_delayed, Time now) {
  // Clear the app-limited marker once the bubble is delivered.
  if (rs.app_limited != 0 && rs.delivered > rs.app_limited) {
    rs.app_limited = 0;
  }
  if (acked_sacked != 0) {
    rs.delivered_time = now;
  }
  RateSample s;
  s.acked_sacked = acked_sacked;
  s.losses = lost;
  s.prior_in_flight = prior_in_flight;
  s.prior_delivered = ack.prior_delivered;
  s.is_app_limited = ack.is_app_limited;
  s.is_retrans = ack.is_retrans;
  s.rtt = ca_rtt < Duration::zero() ? Duration{-1} : ca_rtt;  // tcp_ack_update_rtt
  s.is_ack_delayed = maybe_delayed;                           // tcp_ack
  // No timing information, or SACK reneging (samples could count packets
  // SACKed before the reneging): invalid.
  if (!ack.has_prior || is_sack_reneg) {
    return s;
  }
  s.delivered = rs.delivered - ack.prior_delivered;
  // Sending and ACKing are separate pipeline phases; use the longer one.
  const Duration send_elapsed = ack.prior_last_tx - ack.prior_first_tx_time;
  const Duration ack_elapsed = now - ack.prior_time;
  s.interval = std::max(send_elapsed, ack_elapsed);
  // An interval below min_rtt (Duration::max() before any sample, as Linux's
  // ~0U) would overestimate the rate.
  if (s.interval < min_rtt) {
    s.interval = Duration{-1};
    return s;
  }
  s.valid = true;
  return s;
}

std::uint64_t rate_delivery_rate(const RateState& rs, std::uint32_t mss) {
  // m2b-rate-pacing: tcp_compute_delivery_rate from the record.
  static_cast<void>(rs);
  static_cast<void>(mss);
  return 0;
}

void rate_check_app_limited(RateState& rs, std::uint64_t unsent_bytes, std::uint32_t mss,
                            bool queued_in_stack, std::uint32_t in_flight, std::uint32_t cwnd,
                            std::uint32_t lost_out, std::uint32_t retrans_out) {
  if (unsent_bytes < mss &&           // less than one packet to send
      !queued_in_stack &&             // nothing waiting in the stack's transmit queue
      in_flight < cwnd &&             // not cwnd-limited
      lost_out <= retrans_out) {      // all lost packets retransmitted
    const std::uint64_t marker = rs.delivered + in_flight;
    rs.app_limited = marker != 0 ? marker : 1;
  }
}

}  // namespace utcp
