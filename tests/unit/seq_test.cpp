#include "utcp/seq.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <random>

namespace {

using utcp::Seq32;
using utcp::seq_at;
using utcp::unwrap;

TEST(Seq, ArithmeticIsModular) {
  const Seq32 a{0xffff'fff0u};
  EXPECT_EQ((a + 0x20).raw(), 0x10u);
  EXPECT_EQ((Seq32{5} - 10).raw(), 0xffff'fffbu);
  EXPECT_EQ(Seq32{0x10} - a, 0x20u);
  EXPECT_EQ(a - Seq32{0x10}, 0xffff'ffe0u);
  Seq32 b = a;
  b += 0x30;
  EXPECT_EQ(b.raw(), 0x20u);
  b -= 0x21;
  EXPECT_EQ(b.raw(), 0xffff'ffffu);
  EXPECT_EQ(Seq32{}, Seq32{0});
}

TEST(Seq, BeforeAfterNearby) {
  const Seq32 a{1000};
  EXPECT_TRUE(before(a, a + 1));
  EXPECT_TRUE(after(a + 1, a));
  EXPECT_FALSE(before(a, a));
  EXPECT_FALSE(after(a, a));
  EXPECT_TRUE(before_eq(a, a));
  EXPECT_TRUE(after_eq(a, a));
  EXPECT_TRUE(before_eq(a, a + 1));
  EXPECT_FALSE(after_eq(a, a + 1));
}

TEST(Seq, DistanceBoundaryTwoToThe31) {
  for (const std::uint32_t start : {0u, 1000u, 0x7fff'ffffu, 0x8000'0000u, 0xffff'ffffu}) {
    SCOPED_TRACE(start);
    const Seq32 a{start};
    // 2^31 - 1 ahead is still after.
    EXPECT_TRUE(before(a, a + 0x7fff'ffffu));
    EXPECT_FALSE(before(a + 0x7fff'ffffu, a));
    EXPECT_TRUE(after(a + 0x7fff'ffffu, a));
    // Exactly 2^31: each is "before" the other (RFC 1982 leaves it undefined).
    EXPECT_TRUE(before(a, a + 0x8000'0000u));
    EXPECT_TRUE(before(a + 0x8000'0000u, a));
    // 2^31 + 1 ahead is behind.
    EXPECT_TRUE(after(a, a + 0x8000'0001u));
    EXPECT_FALSE(before(a, a + 0x8000'0001u));
  }
}

TEST(Seq, AcrossTheWrap) {
  const Seq32 a{0xffff'fff0u};
  const Seq32 b{0x0000'0010u};
  EXPECT_TRUE(before(a, b));
  EXPECT_TRUE(after(b, a));
  EXPECT_EQ(b - a, 0x20u);
  EXPECT_TRUE(before(Seq32{0xffff'ffffu}, Seq32{0}));
  EXPECT_TRUE(after(Seq32{0}, Seq32{0xffff'ffffu}));
}

TEST(SeqUnwrap, NearBase) {
  const Seq32 base{0x1234'5678u};
  EXPECT_EQ(unwrap(base, base, 0), 0);
  EXPECT_EQ(unwrap(base + 100, base, 0), 100);
  EXPECT_EQ(unwrap(base + 100, base, 50), 100);
  // A SYN at ISN = base - 1 has no offset: -1.
  EXPECT_EQ(unwrap(base - 1, base, 0), -1);
  EXPECT_EQ(seq_at(base, 100), base + 100);
}

TEST(SeqUnwrap, BaseNearTheSequenceWrap) {
  // ISN + 1 just below 2^32: offsets cross the 32-bit sequence wrap early.
  const Seq32 base{0xffff'f000u};
  const Seq32 s = seq_at(base, 0x2000);
  EXPECT_EQ(s.raw(), 0x1000u);
  EXPECT_EQ(unwrap(s, base, 0), 0x2000);
  EXPECT_EQ(unwrap(s, base, 0x1fff), 0x2000);
}

TEST(SeqUnwrap, ReferenceJustBelowAndAboveTwoToThe32) {
  const Seq32 base{0x0000'1000u};
  const std::uint64_t wrap = std::uint64_t{1} << 32;
  // Reference just below 2^32, segment just above.
  EXPECT_EQ(unwrap(seq_at(base, wrap + 0x100), base, wrap - 0x100),
            static_cast<std::int64_t>(wrap + 0x100));
  // Reference just above 2^32, segment just below (a retransmission).
  EXPECT_EQ(unwrap(seq_at(base, wrap - 0x10), base, wrap + 0x10),
            static_cast<std::int64_t>(wrap - 0x10));
  // Several wraps in.
  const std::uint64_t far = 5 * wrap + 7;
  EXPECT_EQ(unwrap(seq_at(base, far), base, far - 1000), static_cast<std::int64_t>(far));
}

TEST(SeqUnwrap, WindowEdges) {
  const Seq32 base{77};
  const std::uint64_t ref = std::uint64_t{3} << 32;
  const std::uint64_t half = std::uint64_t{1} << 31;
  EXPECT_EQ(unwrap(seq_at(base, ref + half - 1), base, ref),
            static_cast<std::int64_t>(ref + half - 1));
  EXPECT_EQ(unwrap(seq_at(base, ref - half), base, ref), static_cast<std::int64_t>(ref - half));
  // ref + 2^31 is outside [ref - 2^31, ref + 2^31): it maps to ref - 2^31.
  EXPECT_EQ(unwrap(seq_at(base, ref + half), base, ref), static_cast<std::int64_t>(ref - half));
}

TEST(SeqUnwrap, RandomRoundTrip) {
  std::mt19937_64 gen(1);
  for (int i = 0; i < 100'000; ++i) {
    const Seq32 base{static_cast<std::uint32_t>(gen())};
    const std::uint64_t off = gen() >> 20;
    // ref - off in (-2^31, 2^31], so off is in [ref - 2^31, ref + 2^31).
    const auto delta = static_cast<std::int64_t>(gen() % (std::uint64_t{1} << 32)) -
                       (std::int64_t{1} << 31) + 1;
    const std::int64_t ref_signed = static_cast<std::int64_t>(off) + delta;
    if (ref_signed < 0) {
      continue;
    }
    ASSERT_EQ(unwrap(seq_at(base, off), base, static_cast<std::uint64_t>(ref_signed)),
              static_cast<std::int64_t>(off))
        << "base " << base.raw() << " off " << off << " ref " << ref_signed;
  }
}

}  // namespace
