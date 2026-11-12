#include "core/tx_queue.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "utcp/packet.hpp"

namespace {

using utcp::BlockedFifo;
using utcp::PacketPool;
using utcp::TxPacket;
using utcp::TxQueue;

TxPacket packet(PacketPool& pool, std::uint8_t tag) {
  auto buf = pool.alloc(1, 0);
  EXPECT_TRUE(buf.has_value());
  *buf->append(1) = static_cast<std::byte>(tag);
  return TxPacket{std::move(*buf), 0, false};
}

std::uint8_t tag(const TxPacket& p) { return std::to_integer<std::uint8_t>(p.buf.bytes()[0]); }

TEST(TxQueue, FifoInProductionOrder) {
  PacketPool pool(16, 64);
  TxQueue q(4);
  EXPECT_TRUE(q.empty());
  for (std::uint8_t i = 0; i < 4; ++i) {
    q.push(packet(pool, i), std::nullopt);
  }
  EXPECT_TRUE(q.full());
  EXPECT_EQ(pool.available(), 12u);
  for (std::uint8_t i = 0; i < 2; ++i) {
    const auto p = q.pop();
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(tag(*p), i);
  }
  // Wrap around the ring.
  q.push(packet(pool, 4), std::nullopt);
  q.push(packet(pool, 5), std::nullopt);
  q.check_invariants();
  for (std::uint8_t i = 2; i < 6; ++i) {
    EXPECT_EQ(tag(*q.pop()), i);
  }
  EXPECT_FALSE(q.pop().has_value());
  EXPECT_EQ(pool.available(), 16u);  // every popped packet was dropped
  q.check_invariants();
}

TEST(TxQueue, CountsPacketsPerOwner) {
  PacketPool pool(16, 64);
  TxQueue q(8);
  q.push(packet(pool, 0), 3u);
  q.push(packet(pool, 1), std::nullopt);
  q.push(packet(pool, 2), 3u);
  q.push(packet(pool, 3), 7u);
  EXPECT_EQ(q.queued_for(3), 2u);
  EXPECT_EQ(q.queued_for(7), 1u);
  EXPECT_EQ(q.queued_for(0), 0u);
  EXPECT_EQ(q.queued_for(1000), 0u);
  q.check_invariants();
  q.pop();
  EXPECT_EQ(q.queued_for(3), 1u);
  q.pop();
  q.pop();
  EXPECT_EQ(q.queued_for(3), 0u);
  EXPECT_EQ(q.queued_for(7), 1u);
  q.pop();
  EXPECT_EQ(q.queued_for(7), 0u);
  q.check_invariants();
}

// A freed slot's queued packets stay queued but count for no owner.
TEST(TxQueue, DisownForgetsAFreedSlotsPackets) {
  PacketPool pool(16, 64);
  TxQueue q(4);
  q.push(packet(pool, 0), 3u);
  q.push(packet(pool, 1), 5u);
  q.pop();
  q.push(packet(pool, 2), 3u);
  q.push(packet(pool, 3), 3u);
  q.push(packet(pool, 4), 5u);  // the ring wraps
  EXPECT_EQ(q.queued_for(3), 2u);
  q.disown(3);
  EXPECT_EQ(q.queued_for(3), 0u);
  EXPECT_EQ(q.queued_for(5), 2u);
  q.disown(3);    // again: no-op
  q.disown(999);  // never used: no-op
  q.check_invariants();
  EXPECT_EQ(tag(*q.pop()), 1u);
  q.push(packet(pool, 5), 3u);  // the next connection in slot 3
  EXPECT_EQ(q.queued_for(3), 1u);
  EXPECT_EQ(q.queued_for(5), 1u);
  q.check_invariants();
  // Disowned packets still leave in order.
  for (std::uint8_t i = 2; i < 6; ++i) {
    EXPECT_EQ(tag(*q.pop()), i);
  }
  EXPECT_EQ(q.queued_for(3), 0u);
  EXPECT_EQ(q.queued_for(5), 0u);
  q.check_invariants();
}

TEST(TxQueueDeathTest, PushOnFullAborts) {
  PacketPool pool(4, 64);
  TxQueue q(1);
  q.push(packet(pool, 0), std::nullopt);
  EXPECT_DEATH(q.push(packet(pool, 1), std::nullopt), "UTCP_CHECK");
}

TEST(TxQueue, BlockedFifoKeepsOrderAndDeduplicates) {
  BlockedFifo f;
  EXPECT_TRUE(f.empty());
  for (const std::uint32_t s : {5u, 2u, 9u, 2u, 5u}) {
    f.push(s);
  }
  EXPECT_EQ(f.size(), 3u);
  EXPECT_TRUE(f.contains(9));
  EXPECT_FALSE(f.contains(3));
  EXPECT_FALSE(f.contains(100000));
  f.check_invariants();
  EXPECT_EQ(f.pop(), 5u);
  f.push(5);  // back of the queue now
  EXPECT_EQ(f.pop(), 2u);
  EXPECT_EQ(f.pop(), 9u);
  EXPECT_EQ(f.pop(), 5u);
  EXPECT_EQ(f.pop(), std::nullopt);
  f.check_invariants();
}

// pop_before(mark) hands out only the slots pushed before the mark.
TEST(TxQueue, BlockedFifoPopBeforeMark) {
  BlockedFifo f;
  EXPECT_EQ(f.pushes(), 0u);
  f.push(4);
  f.push(6);
  f.push(4);  // already queued: not a push
  EXPECT_EQ(f.pushes(), 2u);
  const std::uint64_t mark = f.pushes();
  EXPECT_EQ(f.pop_before(mark), 4u);
  f.push(4);  // back of the queue, after the mark
  f.push(8);
  EXPECT_EQ(f.pop_before(mark), 6u);
  EXPECT_EQ(f.pop_before(mark), std::nullopt);
  EXPECT_EQ(f.size(), 2u);
  f.check_invariants();
  EXPECT_EQ(f.pop_before(f.pushes()), 4u);
  EXPECT_EQ(f.pop_before(f.pushes()), 8u);
  EXPECT_EQ(f.pop_before(f.pushes()), std::nullopt);
  // Erase and growth keep the push order.
  for (std::uint32_t s = 0; s < 40; ++s) {
    f.push(s);
  }
  EXPECT_TRUE(f.erase(0));
  const std::uint64_t mark2 = f.pushes();
  f.push(0);
  std::vector<std::uint32_t> got;
  while (const auto s = f.pop_before(mark2)) {
    got.push_back(*s);
  }
  EXPECT_EQ(got.size(), 39u);
  EXPECT_EQ(got.front(), 1u);
  EXPECT_EQ(got.back(), 39u);
  EXPECT_EQ(f.pop(), 0u);
  f.check_invariants();
}

TEST(TxQueue, BlockedFifoGrowsAndErases) {
  BlockedFifo f;
  for (std::uint32_t s = 0; s < 100; ++s) {
    f.push(s * 3);
  }
  EXPECT_EQ(f.size(), 100u);
  EXPECT_TRUE(f.erase(30));
  EXPECT_FALSE(f.erase(30));
  EXPECT_FALSE(f.erase(31));
  EXPECT_FALSE(f.contains(30));
  f.check_invariants();
  std::vector<std::uint32_t> out;
  while (const auto s = f.pop()) {
    out.push_back(*s);
  }
  ASSERT_EQ(out.size(), 99u);
  std::uint32_t want = 0;
  for (const std::uint32_t s : out) {
    if (want == 30) {
      want += 3;
    }
    EXPECT_EQ(s, want);
    want += 3;
  }
  // Erase across the ring's wrap point.
  for (std::uint32_t s = 0; s < 10; ++s) {
    f.push(s);
  }
  for (int i = 0; i < 8; ++i) {
    f.pop();
  }
  for (std::uint32_t s = 10; s < 20; ++s) {
    f.push(s);
  }
  EXPECT_TRUE(f.erase(9));
  EXPECT_TRUE(f.erase(15));
  f.check_invariants();
  std::vector<std::uint32_t> rest;
  while (const auto s = f.pop()) {
    rest.push_back(*s);
  }
  EXPECT_EQ(rest, (std::vector<std::uint32_t>{8, 10, 11, 12, 13, 14, 16, 17, 18, 19}));
}

}  // namespace
