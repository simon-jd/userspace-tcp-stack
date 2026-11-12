// RecvBuffer (src/core/tcp/recv_buffer.hpp, DESIGN §4.10): directed cases and
// a differential test against tests/support/naive_reassembler.hpp.
#include "core/tcp/recv_buffer.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
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

// Differential test (m1-rx acceptance 2): 1e6 random insert, read, FIN,
// reneging and grow operations from fixed seeds, compared with the naive
// reference after every step.
struct DiffParams {
  std::uint64_t seed;
  std::uint32_t capacity;
  int steps;
};

void run_differential(const DiffParams& p) {
  std::mt19937_64 gen(p.seed);
  ChunkPool pool(1u << 14);  // never short of chunks here
  RecvBuffer rb(p.capacity, pool);
  utcp::test::NaiveReassembler ref(p.capacity);
  std::uint64_t limit = 0;  // like rcv_adv: never decreases
  std::vector<std::byte> a;
  std::vector<std::byte> b;
  for (int step = 0; step < p.steps; ++step) {
    const std::uint64_t cap = rb.capacity();
    limit = std::max(limit, rb.right_edge() - gen() % (cap / 4 + 1));
    const auto op = gen() % 1000;
    if (op < 640) {
      // Offsets from somewhat below the read offset to past the right edge;
      // many segments near contiguous_end, like a real sender.
      const std::uint64_t back = std::min<std::uint64_t>(rb.read_offset(), 300);
      std::uint64_t off = 0;
      if (gen() % 2 == 0) {
        off = rb.contiguous_end() + gen() % (cap / 8 + 1);
        off = off > back ? off - gen() % (back + 1) : off;
      } else {
        off = rb.read_offset() - back + gen() % (cap + back + 200);
      }
      const std::size_t len = gen() % 8 == 0 ? gen() % 3 : 1 + gen() % std::min<std::uint64_t>(cap / 3 + 1, 3000);
      const auto data = bytes(off, len, static_cast<unsigned>(gen() % 3));
      const InsertResult x = rb.insert(off, data, limit);
      const InsertResult y = ref.insert(off, data, limit);
      ASSERT_EQ(x.contiguous_end, y.contiguous_end) << step;
      ASSERT_EQ(x.advanced, y.advanced) << step;
      ASSERT_EQ(x.out_of_order, y.out_of_order) << step;
      ASSERT_EQ(x.filled_hole, y.filled_hole) << step;
      ASSERT_EQ(x.ooo_held, y.ooo_held) << step;
      ASSERT_EQ(x.duplicate, y.duplicate) << step;
      ASSERT_EQ(x.stored, y.stored) << step;
      ASSERT_EQ(x.dropped, y.dropped) << step;
      ASSERT_EQ(x.range_limit, y.range_limit) << step;
    } else if (op < 900) {
      const std::size_t n = gen() % (cap / 2 + 2);
      a.assign(n, std::byte{0});
      b.assign(n, std::byte{0});
      const std::size_t got = rb.read(a);
      ASSERT_EQ(got, ref.read(b)) << step;
      ASSERT_EQ(a, b) << step;
    } else if (op < 980) {
      const std::uint64_t off = rb.contiguous_end() + gen() % (cap + 1);
      const std::uint64_t at = gen() % 4 == 0 ? rb.read_offset() + gen() % (cap + 1) : off;
      rb.set_fin(at);
      ref.set_fin(at);
    } else if (op < 990) {
      rb.drop_out_of_order();
      ref.drop_out_of_order();
    } else if (cap < 4 * p.capacity) {
      const auto grown = static_cast<std::uint32_t>(cap + gen() % (cap / 2 + 1));
      rb.grow(grown);
      ref.grow(grown);
    }
    rb.check_invariants();
    ASSERT_EQ(rb.contiguous_end(), ref.contiguous_end()) << step;
    ASSERT_EQ(rb.read_offset(), ref.read_offset()) << step;
    ASSERT_EQ(rb.readable(), ref.readable()) << step;
    ASSERT_EQ(rb.right_edge(), ref.right_edge()) << step;
    ASSERT_EQ(rb.fin_offset(), ref.fin_offset()) << step;
    ASSERT_EQ(rb.fin_reached(), ref.fin_reached()) << step;
    ASSERT_EQ(ranges(rb), ref.ooo_ranges()) << step;
    // Memory: chunks for the held window only.
    ASSERT_LE(rb.chunks_held(), rb.capacity() / cs + 2) << step;
  }
  // The rest of the stream reads back the same.
  a.assign(static_cast<std::size_t>(rb.readable()), std::byte{0});
  b.assign(a.size(), std::byte{0});
  ASSERT_EQ(rb.read(a), ref.read(b));
  ASSERT_EQ(a, b);
}

TEST(RecvBuffer, DifferentialAgainstNaiveReassembler) {
  // 4 x 250'000 = 1e6 operations.
  for (const DiffParams& p : {DiffParams{1, 3000, 250'000}, DiffParams{2, 3 * 4096 + 17, 250'000},
                              DiffParams{3, 16 * 1024, 250'000}, DiffParams{4, 64 * 1024, 250'000}}) {
    SCOPED_TRACE(p.seed);
    run_differential(p);
    if (HasFatalFailure()) {
      return;
    }
  }
}

}  // namespace
