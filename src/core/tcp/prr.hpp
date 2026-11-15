// Proportional Rate Reduction, Linux variant (M2-DESIGN §1.8; RFC 9937;
// Linux 7.0 tcp_init_cwnd_reduction and tcp_cwnd_reduction, tcp_input.c:2970,
// 2984). Owned by LossRecovery (recovery.cpp), which calls it from the CC step
// of process_ack and from the REO timer.
#pragma once

#include <cstdint>
#include <optional>

namespace utcp {

struct PrrState {             // Linux tp->prior_cwnd, prr_delivered, prr_out
  std::uint32_t prior_cwnd = 0;  // cwnd when the reduction started
  std::uint32_t delivered = 0;   // packets delivered since then (RFC 9937 prr_delivered)
  std::uint32_t out = 0;         // packets sent since then (RFC 9937 prr_out)
};

// tcp_init_cwnd_reduction's PRR part: the reduction starts at `cwnd`.
void prr_init(PrrState& p, std::uint32_t cwnd);

// tcp_cwnd_reduction: the cwnd for one ACK of a reduction (CWR or Recovery),
// or nothing when the ACK delivered nothing (or the reduction was never
// started, prior_cwnd 0; Linux WARN_ON_ONCE). `in_flight` is
// tcp_packets_in_flight after this ACK's loss marking, `newly_lost` the
// packets this ACK marked lost, `una_advanced` FLAG_SND_UNA_ADVANCED.
//
//   delta < 0 (in flight above ssthresh): proportional part,
//     sndcnt = ceil(ssthresh * prr.delivered / prior_cwnd) - prr.out
//   else: conservation with the SafeACK slow start,
//     sndcnt = max(prr.delivered - prr.out, delivered) (+1 if SND.UNA
//     advanced and nothing new was lost), at most delta
//   sndcnt is at least 0, and at least 1 while prr.out is 0 (the first
//   retransmission).
//   cwnd = in_flight + sndcnt.
//
// RFC 9937 divides by RecoverFS; Linux, and so the stack, by prior_cwnd
// (M2-DESIGN §1.8 "RFC 9937 differences").
[[nodiscard]] std::optional<std::uint32_t> prr_cwnd(PrrState& p, std::uint32_t ssthresh,
                                                    std::uint32_t in_flight,
                                                    std::uint32_t newly_acked_sacked,
                                                    std::uint32_t newly_lost, bool una_advanced);

}  // namespace utcp
