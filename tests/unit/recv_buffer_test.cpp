// RecvBuffer (src/core/tcp/recv_buffer.hpp, DESIGN §4.10): directed cases and
// a differential test against tests/support/naive_reassembler.hpp.
#include "core/tcp/recv_buffer.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "support/naive_reassembler.hpp"

namespace {

using utcp::ChunkPool;
using utcp::InsertResult;
using utcp::max_ooo_ranges;
using utcp::Range;
using utcp::RecvBuffer;

constexpr std::uint64_t cs = ChunkPool::chunk_size;

// The byte at stream offset `off` of copy `copy` (copies differ, so a test
// can tell which one was kept).
std::byte byte_at(std::uint64_t off, unsigned copy = 0) {
  return static_cast<std::byte>((off * 7 + off / 251 + copy * 101) & 0xff);
}

std::vector<std::byte> bytes(std::uint64_t off, std::size_t len, unsigned copy = 0) {
  std::vector<std::byte> v(len);
  for (std::size_t i = 0; i < len; ++i) {
    v[i] = byte_at(off + i, copy);
  }
  return v;
}

InsertResult put(RecvBuffer& rb, std::uint64_t off, std::size_t len, std::uint64_t limit,
                 unsigned copy = 0) {
  const InsertResult r = rb.insert(off, bytes(off, len, copy), limit);
  rb.check_invariants();
  return r;
}

InsertResult put(RecvBuffer& rb, std::uint64_t off, std::size_t len) {
  return put(rb, off, len, rb.right_edge());
}

std::vector<std::byte> read_all(RecvBuffer& rb) {
  std::vector<std::byte> out(static_cast<std::size_t>(rb.readable()));
  EXPECT_EQ(rb.read(out), out.size());
  rb.check_invariants();
  return out;
}

std::vector<Range> ranges(const RecvBuffer& rb) {
  const auto s = rb.ooo_ranges();
  return {s.begin(), s.end()};
}

TEST(RecvBuffer, NothingAllocatedBeforeData) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  EXPECT_EQ(rb.chunks_held(), 0u);
  EXPECT_EQ(pool.in_use(), 0u);
  EXPECT_EQ(rb.read_offset(), 0u);
  EXPECT_EQ(rb.contiguous_end(), 0u);
  EXPECT_EQ(rb.right_edge(), 64u * 1024);
  EXPECT_EQ(rb.capacity(), 64u * 1024);
  EXPECT_TRUE(rb.ooo_ranges().empty());
  EXPECT_FALSE(rb.fin_offset());
}

TEST(RecvBuffer, InOrder) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  InsertResult r = put(rb, 0, 1000);
  EXPECT_EQ(r.contiguous_end, 1000u);
  EXPECT_TRUE(r.advanced);
  EXPECT_FALSE(r.out_of_order);
  EXPECT_FALSE(r.filled_hole);
  EXPECT_FALSE(r.ooo_held);
  EXPECT_FALSE(r.duplicate);
  EXPECT_EQ(r.stored, (Range{0, 1000}));
  EXPECT_EQ(r.dropped, 0u);
  r = put(rb, 1000, 5000);  // spans two chunk boundaries
  EXPECT_EQ(r.contiguous_end, 6000u);
  EXPECT_EQ(rb.readable(), 6000u);
  EXPECT_EQ(rb.chunks_held(), 2u);
  EXPECT_EQ(read_all(rb), bytes(0, 6000));
  EXPECT_EQ(rb.read_offset(), 6000u);
  EXPECT_EQ(rb.right_edge(), 6000u + 64 * 1024);
  EXPECT_EQ(rb.chunks_held(), 0u);  // every chunk returned once read
  EXPECT_EQ(pool.in_use(), 0u);
}

TEST(RecvBuffer, PartialReadsKeepTheRest) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, 10'000);
  std::vector<std::byte> out(4097);
  EXPECT_EQ(rb.read(out), 4097u);
  EXPECT_EQ(out, bytes(0, 4097));
  EXPECT_EQ(rb.chunks_held(), 2u);  // chunk 0 returned, chunk 1 still has unread bytes
  EXPECT_EQ(read_all(rb), bytes(4097, 10'000 - 4097));
  std::vector<std::byte> none(10);
  EXPECT_EQ(rb.read(none), 0u);
}

TEST(RecvBuffer, OutOfOrderThenHoleFill) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, 100);
  InsertResult r = put(rb, 300, 100);
  EXPECT_TRUE(r.out_of_order);
  EXPECT_FALSE(r.advanced);
  EXPECT_TRUE(r.ooo_held);
  EXPECT_EQ(r.contiguous_end, 100u);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{300, 400}}));
  r = put(rb, 500, 100);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{300, 400}, {500, 600}}));
  r = put(rb, 100, 50);  // part of the first gap
  EXPECT_TRUE(r.advanced);
  EXPECT_FALSE(r.filled_hole);
  EXPECT_TRUE(r.ooo_held);
  r = put(rb, 150, 150);  // reaches [300, 400)
  EXPECT_TRUE(r.advanced);
  EXPECT_TRUE(r.filled_hole);
  EXPECT_TRUE(r.ooo_held);  // [500, 600) still out of order
  EXPECT_EQ(r.contiguous_end, 400u);
  r = put(rb, 400, 100);  // fills the last gap
  EXPECT_TRUE(r.filled_hole);
  EXPECT_FALSE(r.ooo_held);
  EXPECT_EQ(r.contiguous_end, 600u);
  EXPECT_TRUE(rb.ooo_ranges().empty());
  EXPECT_EQ(read_all(rb), bytes(0, 600));
}

TEST(RecvBuffer, OverlappingSegmentsMergeAndKeepTheFirstCopy) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 1000, 100, rb.right_edge(), 1);
  put(rb, 1300, 100, rb.right_edge(), 1);
  // Overlaps both ranges and the gap between them, and extends on both sides.
  const InsertResult r = put(rb, 900, 600, rb.right_edge(), 2);
  EXPECT_TRUE(r.out_of_order);
  EXPECT_EQ(r.duplicate, (Range{1000, 1100}));  // the lowest duplicate run only
  EXPECT_EQ(r.stored, (Range{900, 1500}));
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{900, 1500}}));
  put(rb, 0, 900, rb.right_edge(), 3);
  const auto got = read_all(rb);
  ASSERT_EQ(got.size(), 1500u);
  for (std::uint64_t o = 0; o < 1500; ++o) {
    const bool first_copy = (o >= 1000 && o < 1100) || (o >= 1300 && o < 1400);
    const unsigned copy = o < 900 ? 3 : first_copy ? 1 : 2;
    ASSERT_EQ(got[o], byte_at(o, copy)) << o;
  }
}

TEST(RecvBuffer, AdjacentSegmentsMerge) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 200, 100);
  put(rb, 400, 100);
  put(rb, 300, 100);  // touches both
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{200, 500}}));
  put(rb, 100, 100);  // touches from below
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{100, 500}}));
}

TEST(RecvBuffer, FullyDuplicate) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, 1000);
  put(rb, 2000, 500);
  // In-order data not read yet.
  InsertResult r = put(rb, 200, 300, rb.right_edge(), 9);
  EXPECT_EQ(r.duplicate, (Range{200, 500}));
  EXPECT_FALSE(r.advanced);
  EXPECT_FALSE(r.out_of_order);
  // Out-of-order data.
  r = put(rb, 2100, 100, rb.right_edge(), 9);
  EXPECT_EQ(r.duplicate, (Range{2100, 2200}));
  EXPECT_TRUE(r.out_of_order);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{2000, 2500}}));
  // Data already read: nothing of it lies in the window.
  std::vector<std::byte> out(1000);
  ASSERT_EQ(rb.read(out), 1000u);
  EXPECT_EQ(out, bytes(0, 1000));  // the first copy
  r = put(rb, 0, 500, rb.right_edge(), 9);
  EXPECT_EQ(r.duplicate, (Range{0, 500}));
  EXPECT_EQ(r.stored, Range{});
  EXPECT_EQ(r.dropped, 0u);
}

TEST(RecvBuffer, PartlyDuplicateIsReportedAsDuplicate) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, 100);
  InsertResult r = put(rb, 50, 100);  // [50, 100) already in order
  EXPECT_EQ(r.duplicate, (Range{50, 100}));
  EXPECT_TRUE(r.advanced);
  EXPECT_EQ(r.stored, (Range{50, 150}));
  EXPECT_EQ(r.contiguous_end, 150u);
  put(rb, 300, 100);
  r = put(rb, 250, 100);  // [300, 350) held out of order
  EXPECT_EQ(r.duplicate, (Range{300, 350}));
  EXPECT_TRUE(r.out_of_order);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{250, 400}}));
}

TEST(RecvBuffer, ClipsAtTheLimit) {
  ChunkPool pool(64);
  RecvBuffer rb(10'000, pool);
  InsertResult r = put(rb, 0, 3000, 2000);
  EXPECT_EQ(r.stored, (Range{0, 2000}));
  EXPECT_EQ(r.contiguous_end, 2000u);
  EXPECT_EQ(r.dropped, 0u);  // clipping is not a drop
  r = put(rb, 5000, 1000, 5500);
  EXPECT_EQ(r.stored, (Range{5000, 5500}));
  r = put(rb, 6000, 100, 5500);  // wholly above the limit
  EXPECT_EQ(r.stored, Range{});
  EXPECT_TRUE(r.out_of_order);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{5000, 5500}}));
  r = put(rb, 9000, 2000, rb.right_edge());  // the right edge itself
  EXPECT_EQ(r.stored, (Range{9000, 10'000}));
  EXPECT_EQ(rb.right_edge(), 10'000u);
}

TEST(RecvBufferDeathTest, LimitAboveTheRightEdgeAborts) {
  ChunkPool pool(4);
  RecvBuffer rb(1000, pool);
  const auto data = bytes(0, 10);
  EXPECT_DEATH(rb.insert(0, data, 1001), "limit <= right_edge");
}

TEST(RecvBuffer, FinBeforeThePrecedingData) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 100, 50);
  rb.set_fin(120);  // below held data: contradicts it, ignored
  EXPECT_FALSE(rb.fin_offset());
  rb.set_fin(200);  // FIN arrives before [0, 100) and [150, 200)
  EXPECT_EQ(rb.fin_offset(), 200u);
  rb.set_fin(300);  // the first FIN wins
  EXPECT_EQ(rb.fin_offset(), 200u);
  EXPECT_FALSE(rb.fin_reached());
  InsertResult r = put(rb, 150, 100);  // clipped at the FIN
  EXPECT_EQ(r.stored, (Range{150, 200}));
  EXPECT_FALSE(rb.fin_reached());
  r = put(rb, 0, 100);
  EXPECT_TRUE(r.filled_hole);
  EXPECT_EQ(r.contiguous_end, 200u);
  EXPECT_TRUE(rb.fin_reached());
  EXPECT_EQ(read_all(rb), bytes(0, 200));
  EXPECT_TRUE(rb.fin_reached());
}

TEST(RecvBuffer, FinAtTheEndOfTheHighestRangeIsAccepted) {
  // The common case: the last segment and its FIN arrive while earlier data
  // is missing; the engine calls set_fin(segment end) right after storing it.
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 100, 50);
  rb.set_fin(150);
  EXPECT_EQ(rb.fin_offset(), 150u);
  EXPECT_FALSE(rb.fin_reached());
  const InsertResult r = put(rb, 0, 100);
  EXPECT_TRUE(r.filled_hole);
  EXPECT_TRUE(rb.fin_reached());
  EXPECT_EQ(read_all(rb), bytes(0, 150));

  // Several ranges: the end of the highest counts, one byte less does not.
  ChunkPool pool2(64);
  RecvBuffer rb2(64 * 1024, pool2);
  put(rb2, 300, 100);
  put(rb2, 600, 100);
  rb2.set_fin(699);  // below the held byte 699
  EXPECT_FALSE(rb2.fin_offset());
  rb2.set_fin(700);
  EXPECT_EQ(rb2.fin_offset(), 700u);
  put(rb2, 0, 600);
  EXPECT_TRUE(rb2.fin_reached());
}

TEST(RecvBuffer, FinBelowInOrderDataIsIgnored) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, 100);
  rb.set_fin(50);
  EXPECT_FALSE(rb.fin_offset());
  std::vector<std::byte> out(100);
  ASSERT_EQ(rb.read(out), 100u);
  rb.set_fin(99);  // also after the data was read
  EXPECT_FALSE(rb.fin_offset());
  rb.set_fin(100);
  EXPECT_TRUE(rb.fin_reached());
}

TEST(RecvBuffer, SixtyFifthRangeIsDroppedAndCounted) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  for (std::uint64_t i = 0; i < max_ooo_ranges; ++i) {
    const InsertResult r = put(rb, 100 + 200 * i, 100);
    ASSERT_FALSE(r.range_limit) << i;
  }
  ASSERT_EQ(rb.ooo_ranges().size(), max_ooo_ranges);
  const auto before = ranges(rb);
  const std::uint32_t chunks = rb.chunks_held();

  InsertResult r = put(rb, 50'000, 1000);  // a 65th range
  EXPECT_TRUE(r.range_limit);
  EXPECT_EQ(r.dropped, 1000u);
  EXPECT_EQ(r.stored, Range{});
  EXPECT_TRUE(r.out_of_order);
  EXPECT_EQ(ranges(rb), before);
  EXPECT_EQ(rb.chunks_held(), chunks);

  // A segment that overlaps a held range merges with it: no new range.
  r = put(rb, 12'750, 200);  // [12'700, 12'800) is held
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(r.duplicate, (Range{12'750, 12'800}));
  EXPECT_EQ(rb.ooo_ranges().back(), (Range{12'700, 12'950}));
  EXPECT_EQ(rb.ooo_ranges().size(), max_ooo_ranges);

  r = put(rb, 150, 100);  // extends the first range: no new range
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(r.stored, (Range{150, 250}));
  r = put(rb, 250, 50);  // joins the first two ranges: 63 left
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(rb.ooo_ranges().size(), max_ooo_ranges - 1);
  r = put(rb, 50'000, 1000);  // now fits
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(rb.ooo_ranges().size(), max_ooo_ranges);
  r = put(rb, 0, 100);  // in-order data is never limited
  EXPECT_FALSE(r.range_limit);
  EXPECT_TRUE(r.filled_hole);
}

TEST(RecvBuffer, ChunkPoolExhaustionDropsTheSegmentAndIsReported) {
  ChunkPool pool(2);
  RecvBuffer rb(64 * 1024, pool);
  InsertResult r = put(rb, 0, 2 * cs);  // both chunks
  EXPECT_EQ(r.stored, (Range{0, 2 * cs}));
  EXPECT_EQ(pool.in_use(), 2u);

  // In order, needs a third chunk: dropped whole (TcpExtTCPRcvQDrop).
  r = put(rb, 2 * cs, 100);
  EXPECT_FALSE(r.out_of_order);
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(r.dropped, 100u);
  EXPECT_EQ(r.stored, Range{});
  EXPECT_FALSE(r.advanced);
  EXPECT_EQ(rb.contiguous_end(), 2 * cs);
  // Out of order (TcpExtTCPOFODrop).
  r = put(rb, 5 * cs, 100);
  EXPECT_TRUE(r.out_of_order);
  EXPECT_EQ(r.dropped, 100u);
  EXPECT_TRUE(rb.ooo_ranges().empty());
  EXPECT_EQ(pool.in_use(), 2u);
  // A segment that spans a held chunk and a missing one is dropped whole too.
  r = put(rb, 2 * cs - 10, 20);
  EXPECT_EQ(r.dropped, 10u);
  EXPECT_EQ(r.duplicate, (Range{2 * cs - 10, 2 * cs}));
  EXPECT_FALSE(r.advanced);

  // Reading returns a chunk; the next segment fits.
  std::vector<std::byte> out(cs);
  ASSERT_EQ(rb.read(out), cs);
  EXPECT_EQ(pool.in_use(), 1u);
  r = put(rb, 2 * cs, 100);
  EXPECT_EQ(r.dropped, 0u);
  EXPECT_EQ(r.contiguous_end, 2 * cs + 100);
  EXPECT_EQ(pool.in_use(), 2u);
}

TEST(RecvBuffer, DroppedSegmentReportsNoDuplicateUnlessItBeganBelowRcvNxt) {
  // Linux tcp_data_queue_ofo drops a segment it has no memory for before
  // tcp_dsack_set; a partial packet below RCV.NXT has its D-SACK set first.
  ChunkPool pool(2);
  RecvBuffer rb(1u << 20, pool);
  put(rb, 3 * cs + 100, 100);  // chunk 3
  put(rb, cs + 100, 100);      // chunk 1: the pool is used up
  // Overlaps the held [3 cs + 100, 3 cs + 200) and needs chunk 4; the range
  // begins below the segment, so nothing is pruned.
  InsertResult r = put(rb, 3 * cs + 150, cs - 50);
  EXPECT_TRUE(r.out_of_order);
  EXPECT_EQ(r.dropped, cs - 100);
  EXPECT_EQ(r.pruned, 0u);
  EXPECT_EQ(r.stored, Range{});
  EXPECT_FALSE(r.duplicate);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{cs + 100, cs + 200}, {3 * cs + 100, 3 * cs + 200}}));
  // Wholly inside a held range: no chunk needed, stored, a duplicate.
  r = put(rb, 3 * cs + 150, 20);
  EXPECT_EQ(r.dropped, 0u);
  EXPECT_EQ(r.duplicate, (Range{3 * cs + 150, 3 * cs + 170}));
}

TEST(RecvBuffer, DuplicateOfPrunedDataIsNotReported) {
  // [cs + 100, 2 cs + 100) holds both chunks. The segment needs chunk 0 and
  // overlaps that range, which begins above it: the range is pruned, the
  // segment is stored, and the bytes it shared with the range are not a
  // duplicate any more (Linux finds no overlap in the pruned queue).
  ChunkPool pool(2);
  RecvBuffer rb(1u << 20, pool);
  put(rb, cs + 100, cs);
  InsertResult r = put(rb, cs - 50, 200);
  EXPECT_EQ(r.pruned, cs);
  EXPECT_EQ(r.dropped, 0u);
  EXPECT_EQ(r.stored, (Range{cs - 50, cs + 150}));
  EXPECT_FALSE(r.duplicate);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{cs - 50, cs + 150}}));

  // The range holding the duplicate survives (a higher one is pruned): the
  // duplicate stays.
  ChunkPool pool3(3);
  RecvBuffer rb3(1u << 20, pool3);
  put(rb3, 0, 100);                     // chunk 0, unread
  put(rb3, 2 * cs + 100, 100);          // chunk 2
  put(rb3, 3 * cs + 100, 100);          // chunk 3
  r = put(rb3, 2 * cs - 50, 200);       // needs chunk 1
  EXPECT_EQ(r.pruned, 100u);            // [3 cs + 100, 3 cs + 200)
  EXPECT_EQ(r.stored, (Range{2 * cs - 50, 2 * cs + 150}));
  EXPECT_EQ(r.duplicate, (Range{2 * cs + 100, 2 * cs + 150}));
}

TEST(RecvBuffer, DropOutOfOrderEmptiesTheRangesAboveContiguousEnd) {
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, 1000);
  put(rb, 3 * cs, 1000);
  put(rb, 6 * cs, 1000);
  EXPECT_EQ(rb.ooo_ranges().size(), 2u);
  EXPECT_EQ(pool.in_use(), 3u);
  rb.drop_out_of_order();
  rb.check_invariants();
  EXPECT_TRUE(rb.ooo_ranges().empty());
  EXPECT_EQ(rb.contiguous_end(), 1000u);
  EXPECT_EQ(pool.in_use(), 1u);  // the chunks of the dropped ranges are back
  // The data can arrive again and is stored again.
  const InsertResult r = put(rb, 3 * cs, 1000);
  EXPECT_FALSE(r.duplicate);
  EXPECT_EQ(rb.ooo_ranges().size(), 1u);
  put(rb, 1000, 3 * cs - 1000);
  EXPECT_EQ(read_all(rb), bytes(0, 3 * cs + 1000));
  rb.drop_out_of_order();  // nothing out of order: no effect
  EXPECT_EQ(rb.contiguous_end(), 3 * cs + 1000);
}

TEST(RecvBuffer, GrowWithDataInTheRing) {
  ChunkPool pool(64);
  RecvBuffer rb(10'000, pool);
  put(rb, 0, 6000);
  put(rb, 8000, 2000);
  std::vector<std::byte> out(1000);
  ASSERT_EQ(rb.read(out), 1000u);
  EXPECT_EQ(rb.right_edge(), 11'000u);
  rb.grow(30'000);
  rb.check_invariants();
  EXPECT_EQ(rb.capacity(), 30'000u);
  EXPECT_EQ(rb.right_edge(), 31'000u);
  const InsertResult r = put(rb, 10'000, 21'000);  // up to the new edge
  EXPECT_EQ(r.stored, (Range{10'000, 31'000}));
  EXPECT_EQ(r.duplicate, std::nullopt);
  put(rb, 6000, 2000);
  EXPECT_EQ(rb.contiguous_end(), 31'000u);
  EXPECT_EQ(read_all(rb), bytes(1000, 30'000));
  rb.grow(30'000);  // same size: fine
}

TEST(RecvBufferDeathTest, GrowNeverShrinks) {
  ChunkPool pool(4);
  RecvBuffer rb(1000, pool);
  EXPECT_DEATH(rb.grow(999), "new_capacity >= capacity_");
}

TEST(RecvBuffer, ZeroLengthAndEmptyWindowInserts) {
  ChunkPool pool(4);
  RecvBuffer rb(1000, pool);
  InsertResult r = rb.insert(0, {}, 1000);
  EXPECT_EQ(r.stored, Range{});
  EXPECT_FALSE(r.advanced);
  r = put(rb, 0, 100, 0);  // zero window: limit at RCV.NXT
  EXPECT_EQ(r.stored, Range{});
  EXPECT_FALSE(r.advanced);
  EXPECT_EQ(r.dropped, 0u);
  EXPECT_EQ(rb.chunks_held(), 0u);
}

TEST(RecvBuffer, MovedBufferKeepsItsData) {
  ChunkPool pool(16);
  RecvBuffer a(64 * 1024, pool);
  put(a, 0, 5000);
  put(a, 9000, 100);
  RecvBuffer b = std::move(a);
  b.check_invariants();
  EXPECT_EQ(b.ooo_ranges().size(), 1u);
  EXPECT_EQ(read_all(b), bytes(0, 5000));
}

TEST(RecvBuffer, RangeLimitAllowsSegmentsTouchingARange) {
  // 64 ranges [200 i + 100, 200 i + 200); a segment that only touches a range
  // (ends at its begin or begins at its end) merges with it: no new range.
  ChunkPool pool(64);
  RecvBuffer rb(64 * 1024, pool);
  for (std::uint64_t i = 0; i < max_ooo_ranges; ++i) {
    ASSERT_FALSE(put(rb, 100 + 200 * i, 100).range_limit) << i;
  }
  ASSERT_EQ(rb.ooo_ranges().size(), max_ooo_ranges);

  InsertResult r = put(rb, 400, 50);  // begins at the end of [300, 400)
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(r.stored, (Range{400, 450}));
  EXPECT_EQ(rb.ooo_ranges()[1], (Range{300, 450}));
  r = put(rb, 650, 50);  // ends at the begin of [700, 800)
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(rb.ooo_ranges()[3], (Range{650, 800}));
  r = put(rb, 12'800, 200);  // begins at the end of the highest range
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(rb.ooo_ranges().back(), (Range{12'700, 13'000}));
  r = put(rb, 50, 50);  // ends at the begin of the lowest range
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(rb.ooo_ranges().front(), (Range{50, 200}));
  EXPECT_EQ(rb.ooo_ranges().size(), max_ooo_ranges);

  r = put(rb, 13'001, 10);  // a one-byte gap above the highest range: a 65th
  EXPECT_TRUE(r.range_limit);
  r = put(rb, 49, 1);  // ends at the begin of the lowest range: merges
  EXPECT_FALSE(r.range_limit);
  r = put(rb, 47, 1);  // one-byte gaps on both sides: a 65th
  EXPECT_TRUE(r.range_limit);
  r = put(rb, 200, 100);  // touches two ranges: they merge, 63 left
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(rb.ooo_ranges().size(), max_ooo_ranges - 1);
  EXPECT_EQ(rb.ooo_ranges().front(), (Range{49, 450}));
}

TEST(RecvBuffer, InOrderSegmentPrunesOutOfOrderDataForChunks) {
  // The connection's own out-of-order data holds every chunk. The segment at
  // RCV.NXT prunes the highest range (Linux tcp_prune_ofo_queue) instead of
  // being dropped on every retransmission.
  ChunkPool pool(4);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, cs);
  read_all(rb);
  for (std::uint64_t c = 2; c <= 5; ++c) {
    put(rb, c * cs, 100);
  }
  ASSERT_EQ(pool.in_use(), 4u);
  ASSERT_EQ(rb.ooo_ranges().size(), 4u);

  InsertResult r = put(rb, cs, 1000);
  EXPECT_EQ(r.pruned, 100u);  // [5 cs, 5 cs + 100) only: one chunk was enough
  EXPECT_EQ(r.dropped, 0u);
  EXPECT_TRUE(r.advanced);
  EXPECT_EQ(r.stored, (Range{cs, cs + 1000}));
  EXPECT_EQ(rb.contiguous_end(), cs + 1000);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{2 * cs, 2 * cs + 100}, {3 * cs, 3 * cs + 100},
                                            {4 * cs, 4 * cs + 100}}));
  EXPECT_EQ(pool.in_use(), 4u);

  // The rest of the hole: the data in chunk 2 joins, nothing more is pruned.
  r = put(rb, cs + 1000, cs - 1000);
  EXPECT_EQ(r.pruned, 0u);
  EXPECT_TRUE(r.filled_hole);
  EXPECT_EQ(rb.contiguous_end(), 2 * cs + 100);
}

TEST(RecvBuffer, PruningStopsBelowTheIncomingSegment) {
  ChunkPool pool(4);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, 100);  // chunk 0, unread
  put(rb, 2 * cs, 100);
  put(rb, 4 * cs, 100);
  put(rb, 6 * cs, 100);
  ASSERT_EQ(pool.in_use(), 4u);

  // Out of order above every range: it would land last, nothing is pruned
  // (Linux: "If incoming skb would land last in ofo queue, stop pruning").
  InsertResult r = put(rb, 8 * cs, 100);
  EXPECT_EQ(r.pruned, 0u);
  EXPECT_EQ(r.dropped, 100u);
  EXPECT_EQ(rb.ooo_ranges().size(), 3u);

  // Out of order between ranges: only the ranges above it go.
  r = put(rb, 3 * cs, 100);
  EXPECT_EQ(r.pruned, 100u);
  EXPECT_EQ(r.dropped, 0u);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{2 * cs, 2 * cs + 100}, {3 * cs, 3 * cs + 100},
                                            {4 * cs, 4 * cs + 100}}));
  // A range that begins at the segment's offset may go; pruning does not
  // reach below it, and the segment is dropped when that is not enough.
  r = put(rb, 4 * cs, cs + 100);  // needs chunk 5
  EXPECT_EQ(r.pruned, 100u);      // [4 cs, 4 cs + 100) went; chunk 4 is free now
  EXPECT_EQ(r.dropped, cs + 100);  // chunks 4 and 5 needed, one free
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{2 * cs, 2 * cs + 100}, {3 * cs, 3 * cs + 100}}));
  EXPECT_EQ(pool.in_use(), 3u);
}

TEST(RecvBuffer, PruningGoesOnUntilAChunkComesBack) {
  // The two highest ranges share chunk 2: pruning the top one frees nothing,
  // the next one frees the chunk.
  ChunkPool pool(2);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, cs + 100, 100);      // chunk 1
  put(rb, 2 * cs + 100, 100);  // chunk 2
  put(rb, 2 * cs + 300, 100);  // chunk 2
  ASSERT_EQ(pool.in_use(), 2u);
  const InsertResult r = put(rb, 0, 100);  // needs chunk 0
  EXPECT_EQ(r.pruned, 200u);
  EXPECT_EQ(r.dropped, 0u);
  EXPECT_EQ(r.contiguous_end, 100u);
  EXPECT_EQ(ranges(rb), (std::vector<Range>{{cs + 100, cs + 200}}));
  EXPECT_EQ(pool.in_use(), 2u);
  EXPECT_EQ(read_all(rb), bytes(0, 100));
}

TEST(RecvBuffer, PrunedDataIsDroppedWhenTheSegmentStillDoesNotFit) {
  // Linux prunes the whole out-of-order queue before it gives up; so does
  // this. The segment needs chunks 1, 2 and 3 once the ranges in chunks 1
  // and 2 are gone, and only 2 are free.
  ChunkPool pool(3);
  RecvBuffer rb(64 * 1024, pool);
  put(rb, 0, 100);             // chunk 0, unread
  put(rb, cs + 100, 100);      // chunk 1
  put(rb, 2 * cs + 100, 100);  // chunk 2
  const InsertResult r = put(rb, 100, 3 * cs);
  EXPECT_EQ(r.pruned, 200u);
  EXPECT_EQ(r.dropped, 3 * cs);
  EXPECT_FALSE(r.advanced);
  EXPECT_EQ(r.stored, Range{});
  EXPECT_TRUE(rb.ooo_ranges().empty());
  EXPECT_EQ(pool.in_use(), 1u);
  EXPECT_EQ(read_all(rb), bytes(0, 100));
}

// Differential test (m1-rx acceptance 2): 1e6 random insert, read and FIN
// operations from fixed seeds (five tests of 200'000, so each ctest entry
// stays well inside the timeout under ASan), compared with the naive
// reference after every step. Reneging and grow operations and empty steps
// are mixed in but not counted: a seed runs until it has done its 200'000
// insert, read and FIN operations (about 227'000 steps). A FIN is rare; once
// the stream has reached it and been read, a fresh buffer starts (another
// connection). A third of the segments start at or below contiguous_end; the
// small-segment seeds keep the range limit busy.
struct DiffParams {
  std::uint64_t seed;
  std::uint32_t capacity;
  std::uint64_t operations;  // insert, read and FIN operations to run
  bool small_segments;
};

struct DiffCounts {
  std::uint64_t steps = 0;
  std::uint64_t inserts = 0;
  std::uint64_t reads = 0;
  std::uint64_t fins = 0;   // set_fin calls, including ignored later FINs
  std::uint64_t drops = 0;  // drop_out_of_order calls
  std::uint64_t grows = 0;  // grow calls (none once at the size cap)
  std::uint64_t advances = 0;
  std::uint64_t filled_holes = 0;
  std::uint64_t range_limits = 0;
  std::uint64_t duplicates = 0;
  std::uint64_t stream_bytes = 0;  // bytes read
  std::uint64_t connections = 0;   // streams read up to their FIN
  std::uint64_t fins_at_top = 0;   // FINs accepted at the end of the highest range
  std::size_t max_ranges = 0;
};

void run_differential(const DiffParams& p, DiffCounts& n) {
  std::mt19937_64 gen(p.seed);
  ChunkPool pool(1u << 14);  // never short of chunks here
  std::optional<RecvBuffer> rb;
  std::optional<utcp::test::NaiveReassembler> ref;
  std::uint64_t limit = 0;  // like rcv_adv: never decreases
  const auto start = [&] {
    rb.reset();
    rb.emplace(p.capacity, pool);
    ref.emplace(p.capacity);
    limit = 0;
  };
  start();
  std::vector<std::byte> a;
  std::vector<std::byte> b;
  const std::uint64_t max_len = p.small_segments ? 24 : 3000;
  for (std::uint64_t step = 0; n.inserts + n.reads + n.fins < p.operations; ++step) {
    n.steps = step + 1;
    const std::uint64_t cap = rb->capacity();
    const std::uint64_t ce = rb->contiguous_end();
    const std::uint64_t ro = rb->read_offset();
    limit = std::max(limit, rb->right_edge() - gen() % (cap / 4 + 1));
    const auto op = gen() % 100'000;
    if (op < 70'000) {
      std::uint64_t off = 0;
      switch (gen() % 3) {
        case 0:  // at or below contiguous_end, often reaching past it
          off = ce - std::min<std::uint64_t>(ce, gen() % (p.small_segments ? 32 : 2000));
          break;
        case 1:  // just above it
          off = ce + 1 + gen() % (p.small_segments ? 4096 : cap / 8 + 1);
          break;
        default:  // anywhere from below the read offset to past the right edge
          off = ro - std::min<std::uint64_t>(ro, 300) + gen() % (cap + 500);
          break;
      }
      const std::size_t len = gen() % 16 == 0 ? gen() % 3 : 1 + gen() % std::min<std::uint64_t>(cap / 3 + 1, max_len);
      const auto data = bytes(off, len, static_cast<unsigned>(gen() % 3));
      const InsertResult x = rb->insert(off, data, limit);
      const InsertResult y = ref->insert(off, data, limit);
      ++n.inserts;
      ASSERT_EQ(x.contiguous_end, y.contiguous_end) << step;
      ASSERT_EQ(x.advanced, y.advanced) << step;
      ASSERT_EQ(x.out_of_order, y.out_of_order) << step;
      ASSERT_EQ(x.filled_hole, y.filled_hole) << step;
      ASSERT_EQ(x.ooo_held, y.ooo_held) << step;
      ASSERT_EQ(x.duplicate, y.duplicate) << step;
      ASSERT_EQ(x.stored, y.stored) << step;
      ASSERT_EQ(x.dropped, y.dropped) << step;
      ASSERT_EQ(x.range_limit, y.range_limit) << step;
      ASSERT_EQ(x.pruned, 0u) << step;
      n.advances += x.advanced ? 1 : 0;
      n.filled_holes += x.filled_hole ? 1 : 0;
      n.range_limits += x.range_limit ? 1 : 0;
      n.duplicates += x.duplicate ? 1 : 0;
    } else if (op < 88'000) {
      const std::size_t len = gen() % (cap / 2 + 2);
      a.assign(len, std::byte{0});
      b.assign(len, std::byte{0});
      const std::size_t got = rb->read(a);
      ++n.reads;
      ASSERT_EQ(got, ref->read(b)) << step;
      ASSERT_EQ(a, b) << step;
      n.stream_bytes += got;
    } else if (op < 88'025) {
      // About 1 in 4'000 steps; the first FIN wins. A quarter exactly at
      // the end of the highest byte held (the last segment and its FIN),
      // half above it (accepted), a quarter anywhere (often contradicted by
      // held data and ignored).
      const auto ooo = rb->ooo_ranges();
      const std::uint64_t top = ooo.empty() ? ce : ooo.back().end;
      const auto kind = gen() % 4;
      const std::uint64_t at = kind == 0   ? ro + gen() % (cap + 1)
                               : kind == 1 ? top
                                           : top + gen() % (p.small_segments ? 2048 : cap + 1);
      const bool first = !rb->fin_offset();
      rb->set_fin(at);
      ref->set_fin(at);
      ++n.fins;
      if (first && kind == 1 && !ooo.empty() && rb->fin_offset() == at) {
        ++n.fins_at_top;
      }
    } else if (op < 88'500) {
      rb->drop_out_of_order();
      ref->drop_out_of_order();
      ++n.drops;
    } else if (op < 89'000) {
      if (cap < 4 * p.capacity) {
        const auto grown = static_cast<std::uint32_t>(cap + gen() % (cap / 2 + 1));
        rb->grow(grown);
        ref->grow(grown);
        ++n.grows;
      }
    }
    // else: nothing this step (the other operations keep their shares; the
    // loop runs until the insert, read and FIN count reaches p.operations)
    rb->check_invariants();
    ASSERT_EQ(rb->contiguous_end(), ref->contiguous_end()) << step;
    ASSERT_EQ(rb->read_offset(), ref->read_offset()) << step;
    ASSERT_EQ(rb->readable(), ref->readable()) << step;
    ASSERT_EQ(rb->right_edge(), ref->right_edge()) << step;
    ASSERT_EQ(rb->fin_offset(), ref->fin_offset()) << step;
    ASSERT_EQ(rb->fin_reached(), ref->fin_reached()) << step;
    ASSERT_EQ(ranges(*rb), ref->ooo_ranges()) << step;
    // Memory: chunks for the held window only.
    ASSERT_LE(rb->chunks_held(), rb->capacity() / cs + 2) << step;
    n.max_ranges = std::max(n.max_ranges, rb->ooo_ranges().size());
    if (rb->fin_reached() && rb->readable() == 0) {
      ++n.connections;
      start();
    }
  }
  // The rest of the stream reads back the same.
  a.assign(static_cast<std::size_t>(rb->readable()), std::byte{0});
  b.assign(a.size(), std::byte{0});
  ASSERT_EQ(rb->read(a), ref->read(b));
  ASSERT_EQ(a, b);
}

void differential(const DiffParams& p) {
  DiffCounts n;
  run_differential(p, n);
  if (testing::Test::HasFatalFailure()) {
    return;
  }
  // The operation counts go into the gtest XML output (--gtest_output=xml).
  const auto record = [](const char* key, std::uint64_t value) {
    testing::Test::RecordProperty(key, std::to_string(value));
  };
  record("steps", n.steps);
  record("inserts", n.inserts);
  record("reads", n.reads);
  record("fins", n.fins);
  record("drops", n.drops);
  record("grows", n.grows);
  EXPECT_EQ(n.inserts + n.reads + n.fins, p.operations);
  EXPECT_GT(n.inserts, p.operations / 2);
  EXPECT_GT(n.reads, p.operations / 10);
  // The run exercised what it compares: the stream moved, holes were
  // filled, FINs were reached and read, and the small-segment seeds sat at
  // the range limit (their stream moves a few bytes per segment).
  if (p.small_segments) {
    EXPECT_GT(n.advances, 10'000u);
    EXPECT_GT(n.filled_holes, 500u);
    EXPECT_GT(n.duplicates, 20'000u);
    EXPECT_GT(n.stream_bytes, 5u * p.capacity);
    EXPECT_GE(n.connections, 1u);
    EXPECT_EQ(n.max_ranges, utcp::max_ooo_ranges);
    EXPECT_GT(n.range_limits, 10'000u);
  } else {
    EXPECT_GT(n.advances, 20'000u);
    EXPECT_GT(n.filled_holes, 5'000u);
    EXPECT_GT(n.duplicates, 50'000u);
    EXPECT_GT(n.stream_bytes, 100u * p.capacity);
    EXPECT_GE(n.connections, 3u);
    EXPECT_GE(n.max_ranges, 8u);
  }
  // A FIN at exactly the end of the highest out-of-order range (the last
  // segment and its FIN while earlier data is missing) was accepted.
  EXPECT_GE(n.fins_at_top, 1u);
}

// 5 x 200'000 = 1e6 insert, read and FIN operations.
TEST(RecvBuffer, DifferentialSeed1) { differential({1, 3000, 200'000, false}); }
TEST(RecvBuffer, DifferentialSeed2) { differential({2, 3 * 4096 + 17, 200'000, false}); }
TEST(RecvBuffer, DifferentialSeed3SmallSegments) { differential({3, 16 * 1024, 200'000, true}); }
TEST(RecvBuffer, DifferentialSeed4) { differential({4, 64 * 1024, 200'000, false}); }
TEST(RecvBuffer, DifferentialSeed5SmallSegments) {
  differential({5, 3 * 4096 + 17, 200'000, true});
}

}  // namespace
