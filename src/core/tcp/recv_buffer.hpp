// Receive buffer: in-place reassembly over a ByteRing (DESIGN §4.10).
// Interface declared by m1-found; implemented by m1-rx (recv_buffer.cpp).
//
// Offsets are 64-bit stream offsets of payload bytes (offset 0 is the byte at
// IRS + 1); SYN and FIN have no offset (§3.2), the FIN position is recorded
// with set_fin. Out-of-order data is written at its final position in the
// ring and an interval set tracks the filled ranges above contiguous_end().
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/buffer/byte_ring.hpp"
#include "core/buffer/chunk_pool.hpp"
#include "utcp/types.hpp"

namespace utcp {

// At most this many disjoint ranges are held above contiguous_end(); a
// segment that would create one more is dropped (counted, §4.10).
inline constexpr std::size_t max_ooo_ranges = 64;

struct InsertResult {
  std::uint64_t contiguous_end = 0;  // after the insert (RCV.NXT as an offset)
  bool advanced = false;             // contiguous_end moved
  bool out_of_order = false;         // the segment started above the old contiguous_end
  // Advanced up to or into data held out of order (at least one range of
  // ooo_ranges() before the insert joined the in-order data).
  bool filled_hole = false;
  // The lowest run of segment bytes that were already received (below the old
  // contiguous_end or inside an old range): the D-SACK candidate (RFC 2883 §4).
  std::optional<Range> duplicate;
  // [max(off, read_offset()), clipped end): the part of the segment held
  // after the insert; empty (Range{}) when the segment was dropped or nothing
  // of it lies in [read_offset(), min(limit, FIN offset)).
  Range stored;
  // Bytes of the segment not stored for lack of a chunk or because they would
  // have created range number max_ooo_ranges + 1 (the engine counts
  // TcpExtTCPOFODrop or TcpExtTCPRcvQDrop).
  std::uint64_t dropped = 0;
  bool range_limit = false;          // dropped because of the range limit
};

class RecvBuffer {
public:
  // `capacity`: buffer size in payload bytes; nothing is allocated until data
  // arrives (chunks come from `pool`).
  RecvBuffer(std::uint32_t capacity, ChunkPool& pool);

  // Stores the segment's payload at stream offset `off`. Bytes at or above
  // `limit` (rcv_adv as an offset: the highest right edge ever advertised,
  // RFC 7323 §2.4) are clipped, as are bytes at or above a known FIN offset.
  // Bytes already held are kept (the first copy wins). A segment that would
  // create range number max_ooo_ranges + 1 is dropped whole.
  // Precondition (checked): limit <= right_edge().
  InsertResult insert(std::uint64_t off, std::span<const std::byte> data, std::uint64_t limit);

  // Forgets every range above contiguous_end() (reneging: the test knob of
  // §7.2, and a future memory-pressure prune).
  void drop_out_of_order();

  // The peer's FIN follows the byte at off - 1. A later different offset is
  // ignored (the first FIN wins), and so is an offset below a byte already
  // held (the peer's data contradicts it).
  void set_fin(std::uint64_t off);
  [[nodiscard]] std::optional<std::uint64_t> fin_offset() const;
  // contiguous_end() reached the FIN offset.
  [[nodiscard]] bool fin_reached() const;

  // Copies in-order bytes to `out` and consumes them; returns the count.
  std::size_t read(std::span<std::byte> out);
  [[nodiscard]] std::uint64_t readable() const;  // contiguous_end() - read_offset()

  [[nodiscard]] std::uint64_t read_offset() const;     // first unread byte
  [[nodiscard]] std::uint64_t contiguous_end() const;  // RCV.NXT as an offset
  [[nodiscard]] std::uint64_t right_edge() const;      // read_offset() + capacity()
  [[nodiscard]] std::uint32_t capacity() const;
  // Sorted, disjoint, above contiguous_end(); at most max_ooo_ranges.
  [[nodiscard]] std::span<const Range> ooo_ranges() const;

  // Autotuning (§4.10); never shrinks. Precondition (checked):
  // new_capacity >= capacity().
  void grow(std::uint32_t new_capacity);

  // Memory held by the ring (debug_usage, §12).
  [[nodiscard]] std::uint32_t chunks_held() const;
  // Ranges sorted and disjoint, every held byte has a chunk; aborts on failure.
  void check_invariants() const;

private:
  // Implementation state is m1-rx's.
};

}  // namespace utcp
