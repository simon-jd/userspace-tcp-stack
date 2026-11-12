// SACK and D-SACK block generation (RFC 2018 §4, RFC 2883 §4; DESIGN §4.10).
// Interface declared by m1-found; implemented by m1-rx (sack_gen.cpp).
//
// Ranges are payload stream offsets; SYN/FIN sequence space never produces a
// block (§3.2). The engine converts blocks to sequence numbers for the wire.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "core/tcp/recv_buffer.hpp"
#include "utcp/types.hpp"

namespace utcp {

class SackGenerator {
public:
  SackGenerator() = default;

  // A segment covering `seg` arrived and was inserted into `rb`: remembers the
  // block containing it as the most recent (RFC 2018 §4, first block).
  void on_arrival(Range seg, const RecvBuffer& rb);
  // Duplicate payload `dup` arrived (InsertResult::duplicate): the next ACK
  // carries it as a D-SACK block (RFC 2883 §4.1).
  void on_duplicate(Range dup, const RecvBuffer& rb);

  // Writes at most max_blocks blocks to `out` and returns the count. Order: the
  // D-SACK block if pending, followed by the out-of-order block containing it
  // if any; the block containing the most recently received segment; the
  // other blocks in order of most recent report. Blocks are recomputed against
  // the current ranges of `rb` (merged, clipped above RCV.NXT) and truncated
  // to max_blocks (3 with timestamps, 4 without).
  std::size_t fill(const RecvBuffer& rb, std::span<Range> out, std::size_t max_blocks) const;

  // An ACK carrying the blocks of the last fill() was sent: a D-SACK is
  // reported once (RFC 2883 §4).
  void on_ack_sent();

  // A D-SACK block waits for the next ACK (AckPolicy sends it at once).
  [[nodiscard]] bool dsack_pending() const;

private:
  // Implementation state is m1-rx's.
};

}  // namespace utcp
