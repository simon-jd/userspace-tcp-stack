// The RFC 6675 scoreboard rules of the rfc profile (M2-DESIGN §1.4): IsLost
// marking, the DupAcks count, HighRxt/RescueRxt and NextSeg rules 3 and 4.
// Used by LossRecovery (recovery.cpp) when SACK is on and rack_tlp is off.
//
// TxSeg.sacked/lost are the scoreboard and pipe is packets_in_flight
// (send_queue.hpp), which equals RFC 6675 SetPipe once `lost` equals IsLost.
// Offsets are stream offsets, as everywhere in the send path.
#pragma once

#include <cstdint>
#include <optional>

#include "core/tcp/send_queue.hpp"

namespace utcp {

class Rfc6675Scoreboard {
public:
  // A new connection or the end of a recovery: DupAcks 0, no HighRxt or
  // RescueRxt. The IsLost prefix (lost_below) is kept: it only grows.
  void reset_recovery();

  // RFC 6675 §5: a cumulative ACK resets DupAcks; an ACK that SACKs new data
  // counts as a DupAck (§2), even if it also moves SND.UNA or the window.
  // Counted only outside loss recovery (`counting`).
  void on_ack(bool una_advanced, std::uint32_t newly_sacked, bool counting);
  [[nodiscard]] std::uint32_t dupacks() const { return dupacks_; }

  // IsLost (RFC 6675 §4): S is lost once DupThresh SACKed segments, or more
  // than (DupThresh - 1) * SMSS SACKed bytes, lie above it. The IsLost
  // segments form a prefix of the queue below the highest SACK, so this walks
  // down from the highest SACKed segment until the count is reached and marks
  // every non-SACKed, not yet lost segment below that point (and above the
  // prefix already marked). Returns the number of segments it marked.
  std::uint32_t mark_lost(SendQueue& q, std::uint32_t dupthresh, std::uint32_t smss);

  // IsLost(S) for the TxSeg starting at `off` evaluated from scratch (tests
  // and checks; mark_lost is the incremental form).
  [[nodiscard]] static bool is_lost(const SendQueue& q, std::uint64_t off, std::uint32_t dupthresh,
                                    std::uint32_t smss);

  // RFC 6675 §5 (4.3): on entering recovery with the head's end offset, HighRxt
  // = RescueRxt = that end (the fast retransmit covers it).
  void on_enter_recovery(std::uint64_t head_end);

  // NextSeg rules 3 and 4 (RFC 6675 §4), asked by the engine once rules 1-2
  // have nothing left: rule 3, the lowest unSACKed segment at or above HighRxt
  // that ends at or below the highest SACK and has no retransmission in
  // flight; else rule 4, once per recovery while SND.UNA > RescueRxt (or
  // RescueRxt unset), the highest unSACKed segment. `una` is SND.UNA with our
  // FIN counted (as `recover`), `wnd_end` SND.UNA + SND.WND: a segment that
  // starts at or beyond it is not named, except the head.
  [[nodiscard]] std::optional<std::uint64_t> next_seg(const SendQueue& q, std::uint64_t una,
                                                      std::uint64_t wnd_end);

  // A retransmission in Recovery (RFC 6675 §5 (C.3), (C.4)): the rescue named
  // by next_seg sets RescueRxt = `recover` and leaves HighRxt; any other
  // raises HighRxt to the segment's end.
  void on_retransmit(const TxSeg& seg, std::uint64_t recover);

  [[nodiscard]] std::uint64_t high_rxt() const { return high_rxt_; }
  [[nodiscard]] std::optional<std::uint64_t> rescue_rxt() const { return rescue_rxt_; }
  [[nodiscard]] std::uint64_t lost_below() const { return lost_below_; }

private:
  std::uint64_t lost_below_ = 0;  // end of the IsLost prefix marked so far
  std::uint64_t high_rxt_ = 0;    // HighRxt (one past its highest octet)
  std::optional<std::uint64_t> rescue_rxt_;    // RescueRxt
  std::optional<std::uint64_t> rescue_named_;  // offset next_seg returned under rule 4
  std::uint32_t dupacks_ = 0;
};

}  // namespace utcp
