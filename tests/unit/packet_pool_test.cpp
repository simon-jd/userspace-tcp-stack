#include "utcp/packet.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <optional>
#include <utility>
#include <vector>

namespace {

using utcp::PacketBuf;
using utcp::PacketPool;

TEST(PacketPool, AllocToExhaustionThenReuse) {
  PacketPool pool(4, 2048);
  EXPECT_EQ(pool.count(), 4u);
  EXPECT_EQ(pool.available(), 4u);
  std::vector<PacketBuf> held;
  for (int i = 0; i < 4; ++i) {
    auto b = pool.alloc(100, 0);
    ASSERT_TRUE(b.has_value());
    held.push_back(std::move(*b));
  }
  EXPECT_EQ(pool.available(), 0u);
  EXPECT_FALSE(pool.alloc(1, 0).has_value());

  // Fresh buffers come out in index order.
  for (std::size_t i = 1; i < held.size(); ++i) {
    EXPECT_EQ(held[i].bytes().data(), held[0].bytes().data() + i * 2048);
  }

  // Free one; the next alloc reuses it (LIFO).
  std::byte* const freed = held[2].bytes().data();
  held.erase(held.begin() + 2);
  EXPECT_EQ(pool.available(), 1u);
  auto again = pool.alloc(10, 0);
  ASSERT_TRUE(again.has_value());
  EXPECT_EQ(again->bytes().data(), freed);
  EXPECT_EQ(pool.available(), 0u);
  held.clear();
  again.reset();
  EXPECT_EQ(pool.available(), 4u);
}

TEST(PacketPool, SizeClassBound) {
  PacketPool pool(2, 2048);
  EXPECT_FALSE(pool.alloc(2049, 0).has_value());
  EXPECT_FALSE(pool.alloc(2000, 49).has_value());
  EXPECT_FALSE(pool.alloc(0xffff'ffffu, 0xffff'ffffu).has_value());  // no 32-bit overflow
  auto b = pool.alloc(2000, 48);
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(b->headroom(), 48u);
  EXPECT_EQ(b->tailroom(), 2000u);
  EXPECT_EQ(pool.available(), 1u);
}

TEST(PacketPool, BuildBackToFront) {
  PacketPool pool(1, 2048);
  auto b = pool.alloc(1460, 60);
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(b->size(), 0u);
  EXPECT_EQ(b->capacity(), 2048u);

  std::byte* payload = b->append(4);
  std::memcpy(payload, "data", 4);
  std::byte* tcp = b->prepend(20);
  std::memset(tcp, 0x22, 20);
  std::byte* ip = b->prepend(20);
  std::memset(ip, 0x45, 20);
  EXPECT_EQ(b->size(), 44u);
  EXPECT_EQ(b->headroom(), 20u);
  EXPECT_EQ(b->bytes().data(), ip);
  EXPECT_EQ(b->bytes()[0], std::byte{0x45});
  EXPECT_EQ(b->bytes()[20], std::byte{0x22});
  EXPECT_EQ(b->bytes()[40], std::byte{'d'});

  b->truncate(40);
  EXPECT_EQ(b->size(), 40u);
  const PacketBuf& cb = *b;
  EXPECT_EQ(cb.bytes().size(), 40u);
}

TEST(PacketPool, ThirtyTwoBitOffsets) {
  // The M4 64 KiB class plus a virtio_net_hdr does not fit 16-bit offsets.
  PacketPool pool(1, 65536 + 64);
  auto b = pool.alloc(65536, 64);
  ASSERT_TRUE(b.has_value());
  b->append(65536);
  b->prepend(64);
  EXPECT_EQ(b->size(), 65536u + 64u);
  EXPECT_EQ(b->headroom(), 0u);
  EXPECT_EQ(b->tailroom(), 0u);
}

TEST(PacketPool, MoveTransfersOwnership) {
  PacketPool pool(2, 256);
  auto a = pool.alloc(10, 0);
  ASSERT_TRUE(a.has_value());
  PacketBuf x = std::move(*a);
  EXPECT_FALSE(a->valid());
  EXPECT_TRUE(x.valid());
  EXPECT_TRUE(a->bytes().empty());
  EXPECT_EQ(pool.available(), 1u);

  auto c = pool.alloc(10, 0);
  ASSERT_TRUE(c.has_value());
  x = std::move(*c);  // returns x's old buffer
  EXPECT_EQ(pool.available(), 1u);
  x.reset();
  EXPECT_FALSE(x.valid());
  EXPECT_EQ(pool.available(), 2u);

  utcp::TxPacket tx{std::move(*pool.alloc(10, 0)), 0, false};
  EXPECT_EQ(pool.available(), 1u);
  utcp::TxPacket moved = std::move(tx);
  EXPECT_EQ(pool.available(), 1u);
}

TEST(PacketPoolDeathTest, BoundsAreChecked) {
  PacketPool pool(1, 128);
  auto b = pool.alloc(64, 16);
  ASSERT_TRUE(b.has_value());
  EXPECT_DEATH(b->prepend(17), "UTCP_CHECK");
  EXPECT_DEATH(b->append(113), "UTCP_CHECK");
  EXPECT_DEATH(b->truncate(1), "UTCP_CHECK");
  b->append(112);
  b->prepend(16);
  EXPECT_EQ(b->size(), 128u);
}

TEST(PacketPoolDeathTest, PoolOutlivesBuffers) {
  EXPECT_DEATH(
      {
        auto pool = std::make_unique<PacketPool>(1, 64);
        auto b = pool->alloc(1, 0);
        pool.reset();
      },
      "UTCP_CHECK");
}

#if defined(__SANITIZE_ADDRESS__)
#define UTCP_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UTCP_TEST_ASAN 1
#endif
#endif

#ifdef UTCP_TEST_ASAN
TEST(PacketPoolDeathTest, UseAfterReturnIsReportedUnderAsan) {
  EXPECT_DEATH(
      {
        PacketPool pool(2, 64);
        std::byte* p = nullptr;
        {
          auto b = pool.alloc(8, 0);
          p = b->append(8);
        }
        volatile std::byte v = p[0];
        static_cast<void>(v);
      },
      "use-after-poison");
}
#endif

}  // namespace
