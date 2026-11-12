#include "core/buffer/byte_ring.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <set>
#include <span>
#include <vector>

#include "core/buffer/chunk_pool.hpp"

namespace {

using utcp::ByteRing;
using utcp::ChunkPool;

constexpr std::uint64_t cs = ChunkPool::chunk_size;

std::vector<std::byte> pattern(std::size_t n, unsigned seed) {
  std::vector<std::byte> v(n);
  for (std::size_t i = 0; i < n; ++i) {
    v[i] = static_cast<std::byte>((i * 131 + seed * 7 + 3) & 0xff);
  }
  return v;
}

std::vector<std::byte> read(const ByteRing& r, std::uint64_t off, std::size_t n) {
  std::vector<std::byte> out(n);
  r.read_at(off, out);
  return out;
}

TEST(ByteRing, WriteAndReadAcrossChunks) {
  ChunkPool pool(16);
  ByteRing r(pool, 64 * 1024);
  const auto data = pattern(10'000, 1);
  EXPECT_EQ(r.write_at(0, data), data.size());
  EXPECT_EQ(r.chunks_held(), 3u);
  EXPECT_EQ(r.bytes_held(), 3 * cs);
  EXPECT_EQ(r.high_water(), 10'000u);
  EXPECT_EQ(read(r, 0, 10'000), data);
  EXPECT_EQ(read(r, 4090, 20), std::vector<std::byte>(data.begin() + 4090, data.begin() + 4110));
  EXPECT_EQ(pool.in_use(), 3u);
}

TEST(ByteRing, ChunksTakenOnFirstWriteAndReturnedWhenConsumed) {
  ChunkPool pool(16);
  ByteRing r(pool, 64 * 1024);
  EXPECT_EQ(r.chunks_held(), 0u);
  r.write_at(0, pattern(100, 2));
  EXPECT_EQ(pool.in_use(), 1u);
  r.write_at(100, pattern(cs, 3));  // spills into chunk 1
  EXPECT_EQ(pool.in_use(), 2u);
  r.consume(cs - 1);  // chunk 0 still holds one live byte
  EXPECT_EQ(pool.in_use(), 2u);
  r.consume(1);
  EXPECT_EQ(pool.in_use(), 1u);
  EXPECT_EQ(r.begin(), cs);
  // Consuming everything returns the partly used last chunk as well.
  r.consume(100);
  EXPECT_EQ(r.begin(), r.high_water());
  EXPECT_EQ(pool.in_use(), 0u);
  EXPECT_EQ(r.chunks_held(), 0u);
  // A write into the rest of that chunk takes a new one.
  r.write_at(r.begin(), pattern(10, 4));
  EXPECT_EQ(pool.in_use(), 1u);
  EXPECT_EQ(read(r, cs + 100, 10), pattern(10, 4));
}

TEST(ByteRing, FarAheadWriteTakesOnlyItsChunk) {
  ChunkPool pool(16);
  ByteRing r(pool, 4 * 1024 * 1024, 12345);
  const std::uint64_t far = 12345 + 3 * 1024 * 1024 + 17;
  EXPECT_EQ(r.write_at(far, pattern(64, 5)), 64u);
  EXPECT_EQ(r.chunks_held(), 1u);
  EXPECT_TRUE(r.has_chunk(far));
  EXPECT_FALSE(r.has_chunk(12345));
  EXPECT_EQ(read(r, far, 64), pattern(64, 5));
  // Fill the start later; the gap stays without chunks.
  EXPECT_EQ(r.write_at(12345, pattern(10, 6)), 10u);
  EXPECT_EQ(r.chunks_held(), 2u);
  r.consume(10);
  EXPECT_EQ(r.chunks_held(), 2u);  // chunk with 12345..12355 still straddles begin
  r.consume(far - r.begin());
  EXPECT_EQ(r.chunks_held(), 1u);
  EXPECT_EQ(read(r, far, 64), pattern(64, 5));
}

TEST(ByteRing, PoolExhaustionWritesAPrefix) {
  ChunkPool pool(2);
  ByteRing r(pool, 64 * 1024, 100);
  const auto data = pattern(3 * cs, 7);
  // Offsets 100.. span chunks 0, 1, 2, 3; only two chunks exist.
  const std::size_t n = r.write_at(100, data);
  EXPECT_EQ(n, 2 * cs - 100);
  EXPECT_EQ(r.high_water(), 2 * cs);
  EXPECT_EQ(pool.failures(), 1u);
  EXPECT_EQ(read(r, 100, n), std::vector<std::byte>(data.begin(), data.begin() + static_cast<long>(n)));
  // Out of chunks, a write far ahead stores nothing.
  EXPECT_EQ(r.write_at(10 * cs, data), 0u);
}

TEST(ByteRing, ReleaseFrom) {
  ChunkPool pool(16);
  ByteRing r(pool, 64 * 1024);
  r.write_at(0, pattern(100, 8));
  r.write_at(3 * cs + 5, pattern(2 * cs, 9));  // chunks 3, 4, 5
  EXPECT_EQ(r.chunks_held(), 4u);
  r.release_from(4 * cs + 1);  // chunk 4 keeps a byte below the cut; chunk 5 goes
  EXPECT_EQ(r.chunks_held(), 3u);
  EXPECT_EQ(r.high_water(), 4 * cs + 1);
  r.release_from(50);  // chunk 0 straddles 50: kept
  EXPECT_EQ(r.chunks_held(), 1u);
  EXPECT_EQ(r.high_water(), 50u);
  const auto head = pattern(100, 8);
  EXPECT_EQ(read(r, 0, 50), std::vector<std::byte>(head.begin(), head.begin() + 50));
  r.release_from(0);
  EXPECT_EQ(r.chunks_held(), 0u);
  EXPECT_EQ(pool.in_use(), 0u);
}

TEST(ByteRing, MoveKeepsTheData) {
  ChunkPool pool(16);
  ByteRing a(pool, 64 * 1024);
  a.write_at(0, pattern(5000, 10));
  ByteRing b(std::move(a));
  EXPECT_EQ(a.chunks_held(), 0u);
  EXPECT_EQ(b.chunks_held(), 2u);
  EXPECT_EQ(read(b, 0, 5000), pattern(5000, 10));
  ByteRing c(pool, 1024);
  c.write_at(0, pattern(10, 11));
  c = std::move(b);  // returns c's chunk
  EXPECT_EQ(pool.in_use(), 2u);
  EXPECT_EQ(read(c, 0, 5000), pattern(5000, 10));
}

TEST(ByteRing, TableWrapsAround) {
  // A steady stream through a small window moves the circular chunk table's
  // head around many times.
  ChunkPool pool(8);
  ByteRing r(pool, 3 * cs);
  std::uint64_t off = 0;
  for (unsigned i = 0; i < 2000; ++i) {
    const auto data = pattern(1000 + i % 3000, i);
    ASSERT_EQ(r.write_at(off, data), data.size());
    ASSERT_EQ(read(r, off, data.size()), data);
    off += data.size();
    r.consume(off - r.begin());
    ASSERT_EQ(r.chunks_held(), 0u);
    ASSERT_EQ(pool.in_use(), 0u);
  }
}

TEST(ByteRingDeathTest, WindowIsChecked) {
  ChunkPool pool(4);
  ByteRing r(pool, 1000, 500);
  const auto data = pattern(10, 12);
  EXPECT_DEATH(r.write_at(499, data), "UTCP_CHECK");
  EXPECT_DEATH(r.write_at(1491, data), "UTCP_CHECK");
  EXPECT_EQ(r.write_at(1490, data), 10u);
}

// Reference model: a byte map plus the chunk-holding rules stated in
// byte_ring.hpp, kept deliberately simple (a set of chunk numbers and linear
// scans). Bytes are stored per offset modulo the window size with the offset
// as a tag, so memory stays bounded while the stream advances.
class Model {
public:
  Model(std::uint64_t capacity, std::uint32_t pool_limit)
      : capacity_(capacity),
        pool_limit_(pool_limit),
        tag_(capacity + cs, ~std::uint64_t{0}),
        val_(capacity + cs, -1) {}

  std::size_t write(std::uint64_t off, std::span<const std::byte> data) {
    std::size_t n = 0;
    while (n < data.size()) {
      const std::uint64_t pos = off + n;
      const std::uint64_t k = pos / cs;
      if (!held_.contains(k)) {
        if (held_.size() >= pool_limit_) {
          break;
        }
        held_.insert(k);
      }
      const std::size_t piece = std::min<std::size_t>(data.size() - n, cs - pos % cs);
      for (std::size_t i = 0; i < piece; ++i) {
        set(pos + i, std::to_integer<int>(data[n + i]));
      }
      n += piece;
    }
    high_ = std::max(high_, off + n);
    return n;
  }

  void consume(std::uint64_t n) {
    begin_ += n;
    if (begin_ >= high_) {
      high_ = begin_;
      drop_chunks_if([](std::uint64_t) { return true; });
    } else {
      drop_chunks_if([&](std::uint64_t k) { return (k + 1) * cs <= begin_; });
    }
  }

  void release_from(std::uint64_t off) {
    off = std::max(off, begin_);
    if (off == begin_) {
      high_ = begin_;
      drop_chunks_if([](std::uint64_t) { return true; });
      return;
    }
    drop_chunks_if([&](std::uint64_t k) { return k * cs >= off; });
    for (std::uint64_t o = off; o < std::min<std::uint64_t>(high_, (off / cs + 1) * cs); ++o) {
      set(o, -1);
    }
    high_ = std::min(high_, off);
  }

  // Byte value, or -1 if not readable.
  [[nodiscard]] int at(std::uint64_t off) const {
    if (off < begin_ || off >= high_) {
      return -1;
    }
    const std::size_t i = index(off);
    return tag_[i] == off ? val_[i] : -1;
  }

  [[nodiscard]] std::uint64_t begin() const { return begin_; }
  [[nodiscard]] std::uint64_t limit() const { return begin_ + capacity_; }
  [[nodiscard]] std::uint64_t high() const { return high_; }
  [[nodiscard]] std::size_t chunks() const { return held_.size(); }

private:
  [[nodiscard]] std::size_t index(std::uint64_t off) const {
    return static_cast<std::size_t>(off % tag_.size());
  }

  void set(std::uint64_t off, int v) {
    const std::size_t i = index(off);
    tag_[i] = off;
    val_[i] = static_cast<std::int16_t>(v);
  }

  template <class Pred>
  void drop_chunks_if(Pred pred) {
    for (auto it = held_.begin(); it != held_.end();) {
      if (pred(*it)) {
        for (std::uint64_t o = *it * cs; o < (*it + 1) * cs; ++o) {
          if (tag_[index(o)] == o) {
            val_[index(o)] = -1;
          }
        }
        it = held_.erase(it);
      } else {
        ++it;
      }
    }
  }

  std::uint64_t capacity_;
  std::uint32_t pool_limit_;
  std::uint64_t begin_ = 0;
  std::uint64_t high_ = 0;
  std::set<std::uint64_t> held_;
  std::vector<std::uint64_t> tag_;  // offset whose byte is in this entry
  std::vector<std::int16_t> val_;   // byte value, -1 if not stored
};

TEST(ByteRing, DifferentialAgainstByteMap) {
  constexpr std::uint64_t capacity = 96 * 1024;  // 24 chunks of window
  constexpr std::uint32_t pool_limit = 12;       // so writes far ahead can exhaust the pool
  ChunkPool pool(pool_limit);
  ByteRing ring(pool, capacity);
  Model model(capacity, pool_limit);
  std::mt19937_64 gen(20261111);
  auto uniform = [&](std::uint64_t lo, std::uint64_t hi) {  // [lo, hi]
    return lo + gen() % (hi - lo + 1);
  };
  int exhausted = 0;
  int far_writes = 0;

  for (int step = 0; step < 100'000; ++step) {
    const auto op = gen() % 100;
    if (op < 45) {
      // Write: usually near the readable end, sometimes far ahead in the window.
      const std::uint64_t room = model.limit() - model.begin();
      std::uint64_t off = 0;
      if (gen() % 4 == 0) {
        off = model.begin() + uniform(0, room - 1);
        ++far_writes;
      } else {
        off = std::min(model.high() + uniform(0, 64), model.limit() - 1);
        if (gen() % 3 == 0 && model.high() > model.begin()) {
          off = model.begin() + uniform(0, model.high() - model.begin() - 1);  // overwrite
        }
      }
      const std::size_t len =
          static_cast<std::size_t>(std::min<std::uint64_t>(uniform(1, 3000), model.limit() - off));
      const auto data = pattern(len, static_cast<unsigned>(step));
      const std::size_t want = model.write(off, data);
      const std::size_t got = ring.write_at(off, data);
      ASSERT_EQ(got, want) << "step " << step;
      exhausted += got < len ? 1 : 0;
    } else if (op < 75) {
      // Read a run of readable bytes.
      if (model.high() <= model.begin()) {
        continue;
      }
      std::uint64_t off = model.begin() + uniform(0, model.high() - model.begin() - 1);
      if (model.at(off) < 0) {
        continue;
      }
      std::vector<std::byte> want;
      const std::size_t max_len = static_cast<std::size_t>(uniform(1, 5000));
      while (want.size() < max_len && model.at(off + want.size()) >= 0) {
        want.push_back(static_cast<std::byte>(model.at(off + want.size())));
      }
      ASSERT_EQ(read(ring, off, want.size()), want) << "step " << step;
    } else if (op < 97) {
      const std::uint64_t span = model.high() > model.begin() ? model.high() - model.begin() : 0;
      const std::uint64_t n = gen() % 10 == 0 ? span : uniform(0, std::min<std::uint64_t>(span, 8000));
      model.consume(n);
      ring.consume(n);
    } else {
      const std::uint64_t off = model.begin() + uniform(0, capacity);
      model.release_from(off);
      ring.release_from(off);
    }
    ASSERT_EQ(ring.begin(), model.begin()) << "step " << step;
    ASSERT_EQ(ring.high_water(), model.high()) << "step " << step;
    ASSERT_EQ(ring.chunks_held(), model.chunks()) << "step " << step;
    ASSERT_EQ(pool.in_use(), model.chunks()) << "step " << step;
  }
  // The run must have covered the interesting cases.
  EXPECT_GT(exhausted, 100);
  EXPECT_GT(far_writes, 1000);
  EXPECT_GT(ring.begin(), 50 * capacity);  // the table wrapped many times
}

}  // namespace
