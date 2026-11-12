// Checks of the reference model itself (tests/support/naive_reassembler.hpp),
// so that m1-rx's differential test compares against a known-good model.
#include "support/naive_reassembler.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace utcp::test {
namespace {

std::vector<std::byte> pattern(std::uint64_t off, std::size_t len) {
  std::vector<std::byte> v(len);
  for (std::size_t i = 0; i < len; ++i) {
    v[i] = static_cast<std::byte>((off + i) * 7);
  }
  return v;
}

InsertResult put(NaiveReassembler& n, std::uint64_t off, std::size_t len, std::uint64_t limit) {
  return n.insert(off, pattern(off, len), limit);
}

TEST(NaiveReassembler, InOrderOutOfOrderAndHoleFill) {
  NaiveReassembler n(1000);
  InsertResult r = put(n, 0, 100, 1000);
  EXPECT_EQ(r.contiguous_end, 100u);
  EXPECT_TRUE(r.advanced);
  EXPECT_FALSE(r.out_of_order);
  EXPECT_FALSE(r.filled_hole);
  EXPECT_EQ(r.stored, (Range{0, 100}));

  r = put(n, 200, 50, 1000);
  EXPECT_TRUE(r.out_of_order);
  EXPECT_FALSE(r.advanced);
  EXPECT_EQ(n.ooo_ranges(), (std::vector<Range>{{200, 250}}));

  r = put(n, 100, 50, 1000);  // part of the gap: does not reach [200, 250)
  EXPECT_TRUE(r.advanced);
  EXPECT_FALSE(r.filled_hole);
  r = put(n, 150, 50, 1000);  // reaches it
  EXPECT_TRUE(r.filled_hole);
  EXPECT_EQ(r.contiguous_end, 250u);
  EXPECT_TRUE(n.ooo_ranges().empty());

  std::array<std::byte, 300> out{};
  EXPECT_EQ(n.read(out), 250u);
  const auto want = pattern(0, 250);
  EXPECT_TRUE(std::equal(want.begin(), want.end(), out.begin()));
  EXPECT_EQ(n.read_offset(), 250u);
  EXPECT_EQ(n.right_edge(), 1250u);
}

TEST(NaiveReassembler, DuplicatesAndClipping) {
  NaiveReassembler n(1000);
  put(n, 0, 100, 1000);
  put(n, 300, 100, 1000);
  InsertResult r = put(n, 50, 100, 1000);  // [50, 100) already received
  EXPECT_EQ(r.duplicate, (Range{50, 100}));
  r = put(n, 250, 200, 1000);  // [300, 400) held: the first duplicate run
  EXPECT_EQ(r.duplicate, (Range{300, 400}));
  EXPECT_EQ(n.ooo_ranges(), (std::vector<Range>{{250, 450}}));
  r = put(n, 900, 200, 1000);  // clipped at the limit
  EXPECT_EQ(r.stored, (Range{900, 1000}));
  EXPECT_EQ(n.ooo_ranges().back(), (Range{900, 1000}));
  r = put(n, 1000, 10, 1000);  // nothing in the window
  EXPECT_EQ(r.stored, Range{});
  EXPECT_EQ(r.dropped, 0u);
}

TEST(NaiveReassembler, FinRules) {
  NaiveReassembler n(1000);
  put(n, 100, 50, 1000);
  n.set_fin(120);  // below held data: ignored
  EXPECT_EQ(n.fin_offset(), std::nullopt);
  n.set_fin(200);  // FIN before the data that precedes it
  n.set_fin(300);  // the first FIN wins
  EXPECT_EQ(n.fin_offset(), 200u);
  const InsertResult r = put(n, 150, 100, 1000);  // clipped at the FIN
  EXPECT_EQ(r.stored, (Range{150, 200}));
  EXPECT_FALSE(n.fin_reached());
  put(n, 0, 100, 1000);
  EXPECT_TRUE(n.fin_reached());
  EXPECT_EQ(n.readable(), 200u);
}

TEST(NaiveReassembler, RangeLimitAndDropOutOfOrder) {
  NaiveReassembler n(10'000);
  for (std::uint64_t i = 0; i < max_ooo_ranges; ++i) {
    put(n, 10 + 20 * i, 10, 10'000);
  }
  EXPECT_EQ(n.ooo_ranges().size(), max_ooo_ranges);
  InsertResult r = put(n, 5000, 10, 10'000);  // range 65: dropped whole
  EXPECT_TRUE(r.range_limit);
  EXPECT_EQ(r.dropped, 10u);
  EXPECT_EQ(r.stored, Range{});
  r = put(n, 20, 5, 10'000);  // extends a range: fine
  EXPECT_FALSE(r.range_limit);
  EXPECT_EQ(n.ooo_ranges().size(), max_ooo_ranges);

  n.drop_out_of_order();
  EXPECT_TRUE(n.ooo_ranges().empty());
  EXPECT_EQ(n.contiguous_end(), 0u);
  n.grow(20'000);
  EXPECT_EQ(n.right_edge(), 20'000u);
}

}  // namespace
}  // namespace utcp::test
