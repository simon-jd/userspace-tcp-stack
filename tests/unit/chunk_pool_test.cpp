#include "core/buffer/chunk_pool.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <vector>

namespace {

using utcp::ChunkPool;

TEST(ChunkPool, GrowsOnDemandUpToTheLimit) {
  ChunkPool pool(3);
  EXPECT_EQ(pool.allocated(), 0u);
  const auto a = pool.alloc();
  const auto b = pool.alloc();
  const auto c = pool.alloc();
  ASSERT_TRUE(a && b && c);
  EXPECT_EQ(pool.allocated(), 3u);
  EXPECT_EQ(pool.in_use(), 3u);
  EXPECT_FALSE(pool.alloc().has_value());
  EXPECT_EQ(pool.failures(), 1u);

  pool.free(*b);
  EXPECT_EQ(pool.free_count(), 1u);
  EXPECT_EQ(pool.in_use(), 2u);
  const auto d = pool.alloc();
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(*d, *b);  // LIFO reuse, no new heap chunk
  EXPECT_EQ(pool.allocated(), 3u);
  pool.free(*a);
  pool.free(*c);
  pool.free(*d);
  EXPECT_EQ(pool.in_use(), 0u);
}

TEST(ChunkPool, ReuseIsLastInFirstOut) {
  ChunkPool pool(8);
  std::vector<ChunkPool::ChunkId> ids;
  for (int i = 0; i < 4; ++i) {
    ids.push_back(*pool.alloc());
  }
  pool.free(ids[1]);
  pool.free(ids[3]);
  EXPECT_EQ(*pool.alloc(), ids[3]);
  EXPECT_EQ(*pool.alloc(), ids[1]);
  for (const auto id : ids) {
    pool.free(id);
  }
}

TEST(ChunkPool, NewChunksAreZeroFilled) {
  ChunkPool pool(1);
  const auto id = pool.alloc();
  ASSERT_TRUE(id.has_value());
  const std::byte* p = pool.data(*id);
  for (std::uint32_t i = 0; i < ChunkPool::chunk_size; ++i) {
    ASSERT_EQ(p[i], std::byte{0});
  }
  pool.free(*id);
}

TEST(ChunkPoolDeathTest, DoubleFreeAndLeaksAbort) {
  EXPECT_DEATH(
      {
        ChunkPool pool(2);
        const auto id = pool.alloc();
        pool.free(*id);
        pool.free(*id);
      },
      "UTCP_CHECK");
  EXPECT_DEATH(
      {
        auto pool = std::make_unique<ChunkPool>(2);
        static_cast<void>(pool->alloc());
        pool.reset();
      },
      "UTCP_CHECK");
}

}  // namespace
