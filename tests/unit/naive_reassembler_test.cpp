// Checks of the reference model itself (tests/support/naive_reassembler.hpp),
// so that m1-rx's differential test compares against a known-good model.
#include "support/naive_reassembler.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
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

// Whether a contradicting FIN is ignored must not depend on whether the
// application has read the data yet.
TEST(NaiveReassembler, FinBelowInOrderDataIsIgnoredAlsoAfterRead) {
  for (const bool read_first : {false, true}) {
    NaiveReassembler n(1000);
    put(n, 0, 100, 1000);
    if (read_first) {
      std::array<std::byte, 100> out{};
      ASSERT_EQ(n.read(out), 100u);
    }
    n.set_fin(50);
    EXPECT_EQ(n.fin_offset(), std::nullopt) << read_first;
    EXPECT_FALSE(n.fin_reached()) << read_first;
    n.set_fin(100);  // right after the in-order data: accepted
    EXPECT_EQ(n.fin_offset(), 100u) << read_first;
    EXPECT_TRUE(n.fin_reached()) << read_first;
  }
}

// The previous byte-map form of the model (std::map from offset to byte),
// with the same rules, as a check that the flat window gives the same results.
class MapModel {
public:
  explicit MapModel(std::uint32_t capacity) : capacity_(capacity) {}
  InsertResult insert(std::uint64_t off, std::span<const std::byte> data, std::uint64_t limit) {
    const std::uint64_t old_end = contiguous_end();
    const std::vector<Range> old_ranges = ooo_ranges();
    const std::uint64_t seg_end = off + data.size();
    InsertResult r;
    r.out_of_order = off > old_end;
    const auto received = [&](std::uint64_t o) { return o < old_end || bytes_.contains(o); };
    for (std::uint64_t o = off; o < seg_end; ++o) {
      if (received(o)) {
        std::uint64_t e = o;
        while (e < seg_end && received(e)) {
          ++e;
        }
        r.duplicate = Range{o, e};
        break;
      }
    }
    std::uint64_t hi = std::min(seg_end, limit);
    if (fin_) {
      hi = std::min(hi, *fin_);
    }
    const std::uint64_t lo = std::max(off, read_off_);
    if (lo < hi) {
      std::map<std::uint64_t, std::byte> trial = bytes_;
      for (std::uint64_t o = lo; o < hi; ++o) {
        trial.try_emplace(o, std::byte{});
      }
      std::uint64_t e = read_off_;
      while (trial.contains(e)) {
        ++e;
      }
      if (ranges_of(trial, e).size() > max_ooo_ranges) {
        r.range_limit = true;
        for (std::uint64_t o = lo; o < hi; ++o) {
          r.dropped += bytes_.contains(o) ? 0 : 1;
        }
      } else {
        for (std::uint64_t o = lo; o < hi; ++o) {
          bytes_.try_emplace(o, data[static_cast<std::size_t>(o - off)]);
        }
        r.stored = Range{lo, hi};
      }
    }
    r.contiguous_end = contiguous_end();
    r.advanced = r.contiguous_end != old_end;
    r.filled_hole = r.advanced && std::ranges::any_of(old_ranges, [&](const Range& g) {
                      return g.begin <= r.contiguous_end;
                    });
    return r;
  }
  void drop_out_of_order() { bytes_.erase(bytes_.lower_bound(contiguous_end()), bytes_.end()); }
  void set_fin(std::uint64_t off) {
    if (fin_ || off < contiguous_end() || (!bytes_.empty() && bytes_.rbegin()->first >= off)) {
      return;
    }
    fin_ = off;
  }
  [[nodiscard]] std::optional<std::uint64_t> fin_offset() const { return fin_; }
  std::size_t read(std::span<std::byte> out) {
    std::size_t n = 0;
    while (n < out.size()) {
      const auto it = bytes_.find(read_off_);
      if (it == bytes_.end()) {
        break;
      }
      out[n++] = it->second;
      bytes_.erase(it);
      ++read_off_;
    }
    return n;
  }
  [[nodiscard]] std::uint64_t contiguous_end() const {
    std::uint64_t e = read_off_;
    while (bytes_.contains(e)) {
      ++e;
    }
    return e;
  }
  [[nodiscard]] std::uint64_t right_edge() const { return read_off_ + capacity_; }
  [[nodiscard]] std::vector<Range> ooo_ranges() const { return ranges_of(bytes_, contiguous_end()); }

private:
  static std::vector<Range> ranges_of(const std::map<std::uint64_t, std::byte>& m,
                                      std::uint64_t from) {
    std::vector<Range> out;
    for (auto it = m.lower_bound(from); it != m.end(); ++it) {
      if (!out.empty() && out.back().end == it->first) {
        ++out.back().end;
      } else {
        out.push_back(Range{it->first, it->first + 1});
      }
    }
    return out;
  }
  std::uint32_t capacity_;
  std::uint64_t read_off_ = 0;
  std::map<std::uint64_t, std::byte> bytes_;
  std::optional<std::uint64_t> fin_;
};

bool same(const InsertResult& a, const InsertResult& b) {
  return a.contiguous_end == b.contiguous_end && a.advanced == b.advanced &&
         a.out_of_order == b.out_of_order && a.filled_hole == b.filled_hole &&
         a.duplicate == b.duplicate && a.stored == b.stored && a.dropped == b.dropped &&
         a.range_limit == b.range_limit;
}

TEST(NaiveReassembler, MatchesTheByteMapForm) {
  std::mt19937_64 gen(2018);
  for (const std::uint32_t capacity : {64u, 300u, 2000u}) {
    NaiveReassembler n(capacity);
    MapModel m(capacity);
    for (int step = 0; step < 3000; ++step) {
      const auto op = gen() % 100;
      // Offsets from a little below the read offset to past the right edge.
      const std::uint64_t back = std::min<std::uint64_t>(n.read_offset(), 10);
      if (op < 70) {
        const std::uint64_t off = n.read_offset() - back + gen() % (capacity + 20);
        const std::size_t len = gen() % 4 == 0 ? gen() % 3 : gen() % (capacity / 4 + 2);
        const std::uint64_t limit = n.right_edge() - gen() % 8 % (capacity / 8 + 1);
        const auto bytes = pattern(off, len);
        ASSERT_TRUE(same(n.insert(off, bytes, limit), m.insert(off, bytes, limit))) << step;
      } else if (op < 88) {
        std::vector<std::byte> a(gen() % (capacity / 2 + 1)), b(a.size());
        ASSERT_EQ(n.read(a), m.read(b)) << step;
        ASSERT_EQ(a, b) << step;
      } else if (op < 96) {
        const std::uint64_t off = n.read_offset() - back + gen() % (capacity + 1);
        n.set_fin(off);
        m.set_fin(off);
      } else {
        n.drop_out_of_order();
        m.drop_out_of_order();
      }
      ASSERT_EQ(n.contiguous_end(), m.contiguous_end()) << step;
      ASSERT_EQ(n.ooo_ranges(), m.ooo_ranges()) << step;
      ASSERT_EQ(n.fin_offset(), m.fin_offset()) << step;
      ASSERT_EQ(n.right_edge(), m.right_edge()) << step;
    }
  }
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
