// Delivery-rate state and samples (DESIGN §5.3, §5.4; Linux tcp_rate.c).
// Interface declared by m1-found; implemented by m1-tx (rate.cpp).
//
// M1 keeps the per-connection state and the per-segment snapshots (TxSeg)
// and counts `delivered`; samples are computed from M2b. Linux uses 0 as
// "unset" for delivered_mstamp and first_tx_mstamp; here `has_sent` says
// whether the times are set (§3.1).
#pragma once

#include <cstdint>

#include "utcp/time.hpp"

namespace utcp {

struct TxSeg;

// Per-connection rate state (the tcp_sock fields of tcp_rate.c).
struct RateState {
  std::uint64_t delivered = 0;  // packets delivered so far (tp->delivered)
  Time delivered_time;          // tp->delivered_mstamp: time `delivered` last changed
  Time first_tx_time;           // tp->first_tx_mstamp: start of the current send interval
  bool has_sent = false;        // the two times above are set
  // tp->app_limited: 0 = not application-limited, else the `delivered` value
  // (delivered + in_flight, or 1) below which samples are app-limited (§5.4).
  std::uint64_t app_limited = 0;
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
  bool is_ack_delayed = false;

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

// tcp_rate_gen: the sample for one ACK. `delivered_now` is RateState::
// delivered after this ACK, `lost` the packets newly marked lost.
RateSample rate_gen(RateState& rs, const RateAck& ack, std::uint32_t acked_sacked,
                    std::uint32_t lost, std::uint32_t prior_in_flight, bool is_sack_reneg,
                    Duration min_rtt, Time now);

// tcp_rate_check_app_limited, from tcp_send (§5.4): marks the connection
// application-limited when less than one MSS is unsent, no packet of the
// connection waits in the stack transmit queue, in flight < cwnd and
// lost_out <= retrans_out.
void rate_check_app_limited(RateState& rs, std::uint64_t unsent_bytes, std::uint32_t mss,
                            bool queued_in_stack, std::uint32_t in_flight, std::uint32_t cwnd,
                            std::uint32_t lost_out, std::uint32_t retrans_out);

}  // namespace utcp
