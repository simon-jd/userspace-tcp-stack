// SACK and D-SACK block generation (RFC 2018 §4, RFC 2883 §4; DESIGN §4.10).
// Interface declared by m1-found; implemented by m1-rx (sack_gen.cpp).
//
// Ranges are payload stream offsets; SYN/FIN sequence space never produces a
// block (§3.2). The engine converts blocks to sequence numbers for the wire.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "core/tcp/recv_buffer.hpp"
#include "utcp/types.hpp"

namespace utcp {

class SackGenerator {
public:
  SackGenerator() = default;

  // A data segment went through RecvBuffer::insert; `seg` is the result's
  // `stored` range (empty when the segment was dropped or nothing of it was
  // in the window). Called for every data segment, before on_duplicate.
  // Remembers the block containing `seg` as the most recent (RFC 2018 §4,
  // first block), duplicate out-of-order segments included (Linux
  // tcp_data_queue_ofo goes to tcp_sack_new_ofo_skb for them). Only a `seg`
  // that lies inside one out-of-order range changes the order: in-order data
  // advanced the ACK (RFC 2018 §4 exempts it), and a dropped segment is
  // reported nowhere (Linux tcp_data_queue_ofo returns on a failed
  // tcp_try_rmem_schedule before tcp_sack_new_ofo_skb), even if it overlaps
  // a held range. A pending D-SACK that does not lie in `seg` came from an
  // earlier segment and is forgotten (RFC 2883 §4 rule 1; Linux
  // tcp_data_queue clears rx_opt.dsack for every data segment).
  void on_arrival(Range seg, const RecvBuffer& rb);
  // Duplicate payload `dup` arrived (InsertResult::duplicate): the next ACK
  // carries it as a D-SACK block (RFC 2883 §4.1). It replaces a D-SACK still
  // pending (Linux tcp_dsack_set). The engine calls it only with D-SACK on.
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
  // Out-of-order blocks, most recently reported first, each as it was when
  // last refreshed. Blocks only grow by merging or disappear (absorbed into
  // the in-order data, or dropped by reneging), so an entry is matched to the
  // current range that overlaps it. Allocated on the first out-of-order
  // segment; at most max_ooo_ranges entries.
  std::vector<Range> recent_;
  std::optional<Range> dsack_;
};

}  // namespace utcp
