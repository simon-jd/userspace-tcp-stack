// Delivery-rate state and samples (DESIGN §5.3, §5.4; Linux tcp_rate.c,
// whose functions Linux 7.0 moved into tcp_input.c, tcp_output.c and tcp.c).
// Interface declared by m1-found and extended by m2-found (M2-DESIGN §2.6);
// implemented by m1-tx, then m2b-rate-pacing (rate.cpp).
//
// M1 keeps the per-connection state and the per-segment snapshots (TxSeg)
// and counts `delivered`; samples are computed from M2b. Linux uses 0 as
// "unset" for delivered_mstamp and first_tx_mstamp; here `has_sent` says
// whether the times are set (§3.1).
#pragma once

#include <cstdint>
#include <limits>

#include "utcp/time.hpp"

namespace utcp {

struct TxSeg;

// RateState::app_limited of a new connection (Linux tcp_init_sock:
// tp->app_limited = ~0U, "a bubble in the pipe until at least the first
// ACK"): segments sent before the first rate_gen are app-limited, and the
// first rate_gen clears it (Linux's after(delivered, ~0U) is true there).
inline constexpr std::uint64_t rate_app_limited_initial = std::numeric_limits<std::uint64_t>::max();

// Per-connection rate state (the tcp_sock fields of tcp_rate.c).
struct RateState {
  std::uint64_t delivered = 0;  // packets delivered so far (tp->delivered)
  Time delivered_time;          // tp->delivered_mstamp: time `delivered` last changed
  Time first_tx_time;           // tp->first_tx_mstamp: start of the current send interval
  bool has_sent = false;        // the two times above are set
  // tp->app_limited: 0 = not application-limited, else the `delivered` value
  // (delivered + in_flight, or 1) below which samples are app-limited (§5.4);
  // rate_app_limited_initial until the first rate_gen.
  std::uint64_t app_limited = rate_app_limited_initial;
  // The record kept for tcpi_delivery_rate (tcp_rate_gen, Linux 7.0
  // tcp_input.c:1791-1797: tp->rate_delivered, rate_interval_us,
  // rate_app_limited). rate_app_limited starts true as in Linux
  // tcp_init_sock, so tcpi_delivery_rate_app_limited is 1 before a sample.
  std::uint64_t rate_delivered = 0;  // packets
  Duration rate_interval{0};
  bool rate_app_limited = true;
};

// One rate sample per ACK (tcp_rate_gen, §5.4).
struct RateSample {
  std::uint64_t prior_delivered = 0;  // `delivered` at the snapshot of the newest delivered segment
  std::uint64_t delivered = 0;        // packets delivered over the interval
  Duration interval{-1};              // max(send_elapsed, ack_elapsed); -1 = none
  Duration rtt{-1};                   // RTT of the newest delivered segment; -1 = none
  bool valid = false;                 // false without a prior snapshot, while reneging, or
                                      // with interval < min_rtt
  std::uint32_t acked_sacked = 0;     // packets newly cumulatively ACKed or SACKed
  std::uint32_t losses = 0;           // packets newly marked lost
  std::uint32_t prior_in_flight = 0;
  bool is_app_limited = false;
  bool is_retrans = false;            // the newest delivered segment was retransmitted
  bool is_ack_delayed = false;        // AckFlag ack_maybe_delayed (tcp_ack, FLAG_ACK_MAYBE_DELAYED)

  bool operator==(const RateSample&) const = default;
};

// Per-ACK working state of the sampler (Linux keeps it in struct rate_sample
// while tcp_rate_skb_delivered runs).
struct RateAck {
  bool has_prior = false;      // a delivered segment carried a snapshot (rs->prior_mstamp != 0)
  std::uint64_t prior_delivered = 0;
  Time prior_time;             // snapshot delivered_time of the newest delivered segment
  Time prior_last_tx;          // its last_tx
  Time prior_first_tx_time;    // its first_tx_time
  std::uint64_t prior_end = 0;  // its end offset (ties by end offset, §5.4)
  bool is_app_limited = false;
  bool is_retrans = false;
};

// tcp_rate_skb_sent, part 1: before a data segment is (re)sent with
// `packets_out` segments outstanding. packets_out == 0 (not in-flight, which
// is 0 after an RTO marks all lost) restarts the interval:
// first_tx_time = delivered_time = now.
void rate_on_send(RateState& rs, std::uint32_t packets_out, Time now);

// tcp_rate_skb_delivered: segment `seg` was newly cumulatively ACKed or SACKed
// (from the SendQueue DeliveredFn callbacks). Keeps the snapshot of the most
// recently sent delivered segment and advances first_tx_time. Marking a
// SACKed segment's snapshot used (TxSeg::rate_used) is SendQueue's.
void rate_on_delivered(RateState& rs, RateAck& ack, const TxSeg& seg, Time now);

// tcp_rate_gen: the sample for one ACK, with RateState::delivered already
// counting this ACK. `lost` is the packets newly marked lost, `ca_rtt` the
// ACK's ca_rtt (-1: none) and `maybe_delayed` its ack_maybe_delayed flag:
// they become rs.rtt (tcp_ack_update_rtt sets rs->rtt_us = ca_rtt_us) and
// rs.is_ack_delayed (tcp_ack), whether or not the sample is valid. Also
// keeps the delivery-rate record (RateState::rate_*; m2b-rate-pacing).
RateSample rate_gen(RateState& rs, const RateAck& ack, std::uint32_t acked_sacked,
                    std::uint32_t lost, std::uint32_t prior_in_flight, bool is_sack_reneg,
                    Duration min_rtt, Duration ca_rtt, bool maybe_delayed, Time now);

// tcpi_delivery_rate from the record (Linux tcp_compute_delivery_rate,
// tcp.c:396): rate_delivered * mss * 10^6 / rate_interval_us bytes/s, 0
// without a record; the interval in whole microseconds as Linux keeps it.
[[nodiscard]] std::uint64_t rate_delivery_rate(const RateState& rs, std::uint32_t mss);

// tcp_rate_check_app_limited, from tcp_send (§5.4): marks the connection
// application-limited when less than one MSS is unsent, no packet of the
// connection waits in the stack transmit queue, in flight < cwnd and
// lost_out <= retrans_out.
void rate_check_app_limited(RateState& rs, std::uint64_t unsent_bytes, std::uint32_t mss,
                            bool queued_in_stack, std::uint32_t in_flight, std::uint32_t cwnd,
                            std::uint32_t lost_out, std::uint32_t retrans_out);

}  // namespace utcp
