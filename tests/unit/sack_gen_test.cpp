// SackGenerator (src/core/tcp/sack_gen.hpp, DESIGN §4.10): the examples of
// RFC 2018 §3 and RFC 2883 §4.1-4.2, and properties of the block choice.
//
// Offsets stand for sequence numbers (the examples' numbers are used as
// stream offsets directly). Every arrival is followed by the ACK it
// triggers; "ACK dropped" in the RFC tables means the ACK was sent and lost,
// so it still uses up a D-SACK.
#include "core/tcp/sack_gen.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/recv_buffer.hpp"

namespace {

using utcp::ChunkPool;
using utcp::InsertResult;
using utcp::Range;
using utcp::RecvBuffer;
using utcp::SackGenerator;

struct Ack {
  std::uint64_t ack = 0;
  std::vector<Range> blocks;
};

class Receiver {
public:
  // The first `in_order` bytes are already received and acknowledged.
  explicit Receiver(std::uint64_t in_order = 0) {
    if (in_order > 0) {
      arrive(0, in_order);
    }
  }

  // Segment [b, e) arrives as the engine would handle it; returns the ACK it
  // triggers (at most max_blocks blocks: 3 with timestamps, 4 without).
  Ack arrive(std::uint64_t b, std::uint64_t e, std::size_t max_blocks = 4) {
    const std::vector<std::byte> data(static_cast<std::size_t>(e - b), std::byte{0x5a});
    last = rb.insert(b, data, rb.right_edge());
    sg.on_arrival(Range{b, e}, rb);
    if (last.duplicate) {
      sg.on_duplicate(*last.duplicate, rb);
    }
    return send_ack(max_blocks);
  }

  [[nodiscard]] std::vector<Range> blocks(std::size_t max_blocks = 4) const {
    std::array<Range, 4> out{};
    const std::size_t n = sg.fill(rb, out, max_blocks);
    return {out.begin(), out.begin() + static_cast<std::ptrdiff_t>(n)};
  }

  Ack send_ack(std::size_t max_blocks = 4) {
    Ack a{rb.contiguous_end(), blocks(max_blocks)};
    sg.on_ack_sent();
    return a;
  }

  ChunkPool pool{512};
  RecvBuffer rb{1u << 20, pool};
  SackGenerator sg;
  InsertResult last;
};

void expect_ack(const Ack& got, std::uint64_t ack, const std::vector<Range>& blocks) {
  EXPECT_EQ(got.ack, ack);
  EXPECT_EQ(got.blocks, blocks);
}

// RFC 2018 §3: left window edge 5000, a burst of eight 500-byte segments.
TEST(SackGen, Rfc2018Case1LastFourDropped) {
  Receiver r(5000);
  for (std::uint64_t s = 5000; s < 7000; s += 500) {
    expect_ack(r.arrive(s, s + 500), s + 500, {});
  }
}

TEST(SackGen, Rfc2018Case2FirstDropped) {
  Receiver r(5000);
  for (std::uint64_t s = 5500; s < 9000; s += 500) {
    SCOPED_TRACE(s);
    expect_ack(r.arrive(s, s + 500), 5000, {{5500, s + 500}});
  }
}

TEST(SackGen, Rfc2018Case3EverySecondDropped) {
  for (const std::size_t max_blocks : {std::size_t{3}, std::size_t{4}}) {
    SCOPED_TRACE(max_blocks);
    Receiver r(5000);
    expect_ack(r.arrive(5000, 5500, max_blocks), 5500, {});
    expect_ack(r.arrive(6000, 6500, max_blocks), 5500, {{6000, 6500}});
    expect_ack(r.arrive(7000, 7500, max_blocks), 5500, {{7000, 7500}, {6000, 6500}});
    expect_ack(r.arrive(8000, 8500, max_blocks), 5500,
               {{8000, 8500}, {7000, 7500}, {6000, 6500}});
    // The 4th packet arrives out of order.
    expect_ack(r.arrive(6500, 7000, max_blocks), 5500, {{6000, 7500}, {8000, 8500}});
    // The 2nd packet arrives.
    expect_ack(r.arrive(5500, 6000, max_blocks), 7500, {{8000, 8500}});
  }
}

// RFC 2883 §4.1: the receiver has received 0-4000 (cumulative ACK 4000).
TEST(SackGen, Rfc2883Example1DuplicateSegment) {
  Receiver r(3000);
  expect_ack(r.arrive(3000, 3500), 3500, {});  // ACK dropped
  expect_ack(r.arrive(3500, 4000), 4000, {});  // ACK dropped
  expect_ack(r.arrive(3000, 3500), 4000, {{3000, 3500}});
}

TEST(SackGen, Rfc2883Example2OutOfOrderAndDuplicate) {
  Receiver r(3000);
  r.arrive(3000, 3500);
  r.arrive(3500, 4000);
  // 4000-4499 dropped.
  expect_ack(r.arrive(4500, 5000), 4000, {{4500, 5000}});  // ACK dropped
  expect_ack(r.arrive(3000, 3500), 4000, {{3000, 3500}, {4500, 5000}});
}

TEST(SackGen, Rfc2883Example3DuplicateOfOutOfOrderSegment) {
  Receiver r(3500);
  expect_ack(r.arrive(3500, 4000), 4000, {});
  // 4000-4499 dropped.
  expect_ack(r.arrive(4500, 5000), 4000, {{4500, 5000}});
  expect_ack(r.arrive(5000, 5500), 4000, {{4500, 5500}});
  expect_ack(r.arrive(5000, 5500), 4000, {{5000, 5500}, {4500, 5500}});
}

// RFC 2883 §4.2: partial duplicates.
TEST(SackGen, Rfc2883Example4SingleDuplicateSubsegment) {
  Receiver r(500);
  expect_ack(r.arrive(500, 1000), 1000, {});
  // 1000-1499 delayed, 1500-1999 dropped.
  expect_ack(r.arrive(2000, 2500), 1000, {{2000, 2500}});
  expect_ack(r.arrive(1000, 1500), 1500, {{2000, 2500}});
  expect_ack(r.arrive(1000, 2000), 2500, {{1000, 1500}});
}

TEST(SackGen, Rfc2883Example5DuplicatesBelowTheCumulativeAck) {
  Receiver r(500);
  expect_ack(r.arrive(500, 1000), 1000, {});
  // 1000-1499 delayed, 1500-1999 dropped, 2000-2499 delayed, 2500-2999 dropped.
  expect_ack(r.arrive(3000, 3500), 1000, {{3000, 3500}});
  expect_ack(r.arrive(1000, 1500), 1500, {{3000, 3500}});
  expect_ack(r.arrive(2000, 2500), 1500, {{2000, 2500}, {3000, 3500}});
  expect_ack(r.arrive(1000, 2500), 2500, {{1000, 1500}, {3000, 3500}});
}

// The table as corrected by RFC 2883 errata 365 (verified): the second
// received part of the 1500-2999 retransmission is 2500-2999 (the original
// table lists 2000-2499, a segment it marks as dropped).
TEST(SackGen, Rfc2883Example6DuplicatesAboveTheCumulativeAck) {
  Receiver r(500);
  expect_ack(r.arrive(500, 1000), 1000, {});
  // 1000-1499 dropped, 1500-1999 delayed, 2000-2499 dropped, 2500-2999
  // delayed, 3000-3499 dropped.
  expect_ack(r.arrive(3500, 4000), 1000, {{3500, 4000}});
  // 1000-1499 dropped again; 1500-2999 arrives in parts.
  expect_ack(r.arrive(1500, 2000), 1000, {{1500, 2000}, {3500, 4000}});
  expect_ack(r.arrive(2500, 3000), 1000, {{2500, 3000}, {1500, 2000}, {3500, 4000}});
  expect_ack(r.arrive(1500, 3000), 1000, {{1500, 2000}, {1500, 3000}, {3500, 4000}});
}

TEST(SackGen, AtMostThreeBlocksWithTimestampsAndFourWithout) {
  Receiver r(100);
  for (std::uint64_t i = 1; i <= 6; ++i) {
    r.arrive(1000 * i, 1000 * i + 100);
  }
  EXPECT_EQ(r.blocks(3), (std::vector<Range>{{6000, 6100}, {5000, 5100}, {4000, 4100}}));
  EXPECT_EQ(r.blocks(4).size(), 4u);
  EXPECT_EQ(r.blocks(4).back(), (Range{3000, 3100}));
  // A D-SACK counts as one of the blocks.
  expect_ack(r.arrive(5000, 5100, 3), 100, {{5000, 5100}, {5000, 5100}, {6000, 6100}});
  // A smaller output span limits the count too.
  std::array<Range, 2> two{};
  EXPECT_EQ(r.sg.fill(r.rb, two, 4), 2u);
  EXPECT_EQ(r.sg.fill(r.rb, two, 0), 0u);
}

TEST(SackGen, DsackIsReportedInExactlyOneAck) {
  Receiver r(1000);
  r.arrive(2000, 2500);
  r.arrive(1500, 1600);
  const Ack a = r.arrive(2000, 2100);  // duplicate of out-of-order data
  EXPECT_EQ(a.blocks.front(), (Range{2000, 2100}));
  EXPECT_EQ(a.blocks[1], (Range{2000, 2500}));  // the block holding it
  EXPECT_FALSE(r.sg.dsack_pending());
  expect_ack(r.send_ack(), 1000, {{2000, 2500}, {1500, 1600}});
  // Duplicate below RCV.NXT: fill() may be called more than once before the
  // ACK goes out; on_ack_sent ends it.
  r.arrive(1000, 1100);  // advances RCV.NXT
  const InsertResult dup = r.rb.insert(1000, std::vector<std::byte>(50), r.rb.right_edge());
  ASSERT_EQ(dup.duplicate, (Range{1000, 1050}));
  r.sg.on_arrival(Range{1000, 1050}, r.rb);
  r.sg.on_duplicate(*dup.duplicate, r.rb);
  EXPECT_TRUE(r.sg.dsack_pending());
  EXPECT_EQ(r.blocks().front(), (Range{1000, 1050}));
  EXPECT_EQ(r.blocks().front(), (Range{1000, 1050}));
  r.sg.on_ack_sent();
  EXPECT_FALSE(r.sg.dsack_pending());
  EXPECT_EQ(r.blocks(), (std::vector<Range>{{2000, 2500}, {1500, 1600}}));
}

TEST(SackGen, DsackOfAnEarlierSegmentIsForgotten) {
  // RFC 2883 §4 rule 1: a D-SACK reports the most recent packet only.
  Receiver r(1000);
  r.arrive(3000, 3500);
  const InsertResult dup = r.rb.insert(500, std::vector<std::byte>(100), r.rb.right_edge());
  r.sg.on_arrival(Range{500, 600}, r.rb);
  r.sg.on_duplicate(*dup.duplicate, r.rb);
  EXPECT_TRUE(r.sg.dsack_pending());
  // No ACK went out before the next segment.
  expect_ack(r.arrive(4000, 4100), 1000, {{4000, 4100}, {3000, 3500}});
  // An empty duplicate range is ignored.
  r.sg.on_duplicate(Range{}, r.rb);
  EXPECT_FALSE(r.sg.dsack_pending());
}

TEST(SackGen, NoBlocksWithoutOutOfOrderData) {
  Receiver r;
  EXPECT_TRUE(r.blocks().empty());
  r.arrive(0, 1000);
  EXPECT_TRUE(r.blocks().empty());
}

TEST(SackGen, RenegedDataIsNotReported) {
  // RFC 2018 §8: blocks report only data still held.
  Receiver r(1000);
  r.arrive(2000, 2100);
  r.arrive(3000, 3100);
  r.rb.drop_out_of_order();
  EXPECT_TRUE(r.blocks().empty());
  expect_ack(r.arrive(5000, 5100), 1000, {{5000, 5100}});
}

TEST(SackGen, PrunedDataIsNotReported) {
  // RecvBuffer pruned the highest range to find a chunk for in-order data
  // (InsertResult::pruned, Linux tcp_prune_ofo_queue): its block goes, like
  // reneged data.
  ChunkPool pool(3);
  RecvBuffer rb(1u << 20, pool);
  SackGenerator sg;
  const auto arrive = [&](std::uint64_t b, std::uint64_t e) {
    const std::vector<std::byte> data(static_cast<std::size_t>(e - b));
    const InsertResult r = rb.insert(b, data, rb.right_edge());
    sg.on_arrival(Range{b, e}, rb);
    return r;
  };
  arrive(4096, 4196);    // chunk 1
  arrive(8192, 8292);    // chunk 2
  arrive(12288, 12388);  // chunk 3
  std::array<Range, 4> out{};
  ASSERT_EQ(sg.fill(rb, out, 4), 3u);
  EXPECT_EQ(out[0], (Range{12288, 12388}));
  const InsertResult r = arrive(0, 100);  // needs chunk 0
  ASSERT_EQ(r.pruned, 100u);
  ASSERT_EQ(sg.fill(rb, out, 4), 2u);
  EXPECT_EQ(out[0], (Range{8192, 8292}));
  EXPECT_EQ(out[1], (Range{4096, 4196}));
}

TEST(SackGen, BlocksNeverReportedAreAppendedLowestFirst) {
  // Data the engine stored without telling the generator still appears.
  Receiver r(100);
  r.rb.insert(3000, std::vector<std::byte>(100), r.rb.right_edge());
  r.rb.insert(1000, std::vector<std::byte>(100), r.rb.right_edge());
  expect_ack(r.arrive(5000, 5100), 100, {{5000, 5100}, {1000, 1100}, {3000, 3100}});
}

// Random out-of-order arrivals: the first block always holds the newest
// segment, every block is one current out-of-order range, no block repeats,
// and every range is reported while they fit.
TEST(SackGen, FirstBlockAlwaysContainsTheNewestSegment) {
  std::mt19937_64 gen(2018);
  for (int round = 0; round < 20; ++round) {
    Receiver r;
    for (int step = 0; step < 500; ++step) {
      const std::uint64_t base = r.rb.contiguous_end();
      const std::uint64_t off = base + gen() % 40'000;
      const std::uint64_t len = 1 + gen() % 1500;
      const std::size_t max_blocks = 3 + gen() % 2;
      const Ack a = r.arrive(off, off + len, max_blocks);
      ASSERT_LE(a.blocks.size(), max_blocks);
      const auto ooo = r.rb.ooo_ranges();
      if (r.last.stored.empty() || r.last.advanced) {
        continue;  // in-order or dropped: no first-block rule
      }
      const bool dsack = r.last.duplicate.has_value();
      ASSERT_FALSE(a.blocks.empty()) << step;
      const Range first = a.blocks[dsack ? 1 : 0];
      ASSERT_TRUE(first.begin <= r.last.stored.begin && r.last.stored.end <= first.end) << step;
      for (std::size_t i = dsack ? 1 : 0; i < a.blocks.size(); ++i) {
        ASSERT_TRUE(std::ranges::find(ooo, a.blocks[i]) != ooo.end()) << step;
        for (std::size_t j = (dsack ? 1 : 0); j < i; ++j) {
          ASSERT_NE(a.blocks[i], a.blocks[j]) << step;
        }
      }
      // While there are no more blocks than fit, every block is reported.
      if (ooo.size() <= max_blocks - (dsack ? 1 : 0)) {
        ASSERT_EQ(a.blocks.size(), ooo.size() + (dsack ? 1 : 0)) << step;
      }
    }
  }
}

}  // namespace
