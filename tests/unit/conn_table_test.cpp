#include "core/tcp/conn_table.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <vector>

#include "core/util/siphash.hpp"

namespace {

using utcp::ConnTable;
using utcp::Endpoint;
using utcp::FourTuple;
using utcp::Ipv4Addr;
using utcp::SipKey;

const SipKey key{0x0123456789abcdefULL, 0xfedcba9876543210ULL};

FourTuple tuple(std::uint32_t i) {
  return FourTuple{Endpoint{Ipv4Addr::from_octets(10, 0, 0, 1), static_cast<std::uint16_t>(80)},
                   Endpoint{Ipv4Addr{0xC0000200u + (i >> 16)}, static_cast<std::uint16_t>(i & 0xffff)}};
}

// The table has lookups only: no begin(), end() or for_each (§4.3, §13.1).
template <class T>
concept Iterable = requires(const T& t) { t.begin(); } || requires(const T& t) { t.end(); };
static_assert(!Iterable<ConnTable>);

TEST(ConnTable, InsertFindErase) {
  ConnTable t(key);
  EXPECT_EQ(t.size(), 0u);
  EXPECT_EQ(t.find(tuple(1)), std::nullopt);
  EXPECT_TRUE(t.insert(tuple(1), 10));
  EXPECT_TRUE(t.insert(tuple(2), 20));
  EXPECT_FALSE(t.insert(tuple(1), 99));  // present: unchanged
  EXPECT_EQ(t.find(tuple(1)), 10u);
  EXPECT_EQ(t.find(tuple(2)), 20u);
  EXPECT_EQ(t.size(), 2u);
  EXPECT_TRUE(t.erase(tuple(1)));
  EXPECT_FALSE(t.erase(tuple(1)));
  EXPECT_EQ(t.find(tuple(1)), std::nullopt);
  EXPECT_EQ(t.find(tuple(2)), 20u);
  EXPECT_EQ(t.size(), 1u);
  t.check_invariants();
}

TEST(ConnTable, HashIsKeyedSipHash13OverTheFields) {
  ConnTable t(key);
  const FourTuple x = tuple(77);
  utcp::SipHasher13 h(key);
  h.update_u32(x.local.addr.v);
  h.update_u16(x.local.port);
  h.update_u32(x.remote.addr.v);
  h.update_u16(x.remote.port);
  EXPECT_EQ(t.hash(x), h.finish());
  EXPECT_NE(ConnTable(SipKey{1, 2}).hash(x), t.hash(x));
  // The direction matters: swapping local and remote is another tuple.
  EXPECT_NE(t.hash(x), t.hash(FourTuple{x.remote, x.local}));
}

TEST(ConnTable, GrowsAndKeepsEveryEntry) {
  ConnTable t(key);
  for (std::uint32_t i = 0; i < 5000; ++i) {
    ASSERT_TRUE(t.insert(tuple(i), i));
  }
  EXPECT_EQ(t.size(), 5000u);
  EXPECT_GE(t.capacity(), 10000u);
  t.check_invariants();
  for (std::uint32_t i = 0; i < 5000; ++i) {
    EXPECT_EQ(t.find(tuple(i)), i);
  }
  for (std::uint32_t i = 0; i < 5000; i += 2) {
    ASSERT_TRUE(t.erase(tuple(i)));
  }
  t.check_invariants();
  for (std::uint32_t i = 0; i < 5000; ++i) {
    EXPECT_EQ(t.find(tuple(i)), i % 2 == 1 ? std::optional<std::uint32_t>(i) : std::nullopt);
  }
}

// 1e5 random operations against std::map; small key space, so probe runs
// wrap around and backward-shift deletion is exercised.
TEST(ConnTable, RandomOperationsMatchAReference) {
  ConnTable t(key);
  std::map<FourTuple, std::uint32_t> ref;
  std::mt19937 rng(12345);
  for (int op = 0; op < 100000; ++op) {
    const FourTuple x = tuple(rng() % 300);
    const auto slot = static_cast<std::uint32_t>(rng());
    switch (rng() % 3) {
      case 0: {
        const bool fresh = !ref.contains(x);
        EXPECT_EQ(t.insert(x, slot), fresh);
        if (fresh) {
          ref[x] = slot;
        }
        break;
      }
      case 1:
        EXPECT_EQ(t.erase(x), ref.erase(x) == 1);
        break;
      default: {
        const auto it = ref.find(x);
        EXPECT_EQ(t.find(x), it == ref.end() ? std::nullopt : std::optional<std::uint32_t>(it->second));
        break;
      }
    }
    ASSERT_EQ(t.size(), ref.size());
    if (op % 1000 == 0) {
      t.check_invariants();
    }
  }
  t.check_invariants();
  for (const auto& [x, slot] : ref) {
    EXPECT_EQ(t.find(x), slot);
  }
}

}  // namespace
