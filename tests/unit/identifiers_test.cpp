#include "core/identifiers.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <set>
#include <vector>

#include "core/stack_impl.hpp"
#include "utcp/config.hpp"

namespace {

using utcp::Endpoint;
using utcp::FourTuple;
using utcp::Ipv4Addr;
using utcp::Seq32;
using utcp::SipKey;
using utcp::StackKeys;
using utcp::Time;
using namespace std::chrono_literals;

const SipKey key{0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};

FourTuple tuple(std::uint16_t lport, std::uint16_t rport, std::uint8_t last = 2) {
  return FourTuple{Endpoint{Ipv4Addr::from_octets(10, 0, 0, 1), lport},
                   Endpoint{Ipv4Addr::from_octets(10, 0, 0, last), rport}};
}

TEST(Identifiers, KeysAreDerivedFromTheSeedOnly) {
  const auto a = StackKeys::derive(utcp::Seed::from_u64(1));
  EXPECT_EQ(a, StackKeys::derive(utcp::Seed::from_u64(1)));
  const auto b = StackKeys::derive(utcp::Seed::from_u64(2));
  EXPECT_NE(a.isn, b.isn);
  // One key per purpose, all different.
  const std::set<std::pair<std::uint64_t, std::uint64_t>> keys{
      {a.isn.k0, a.isn.k1},           {a.ts_offset.k0, a.ts_offset.k1},
      {a.port_offset.k0, a.port_offset.k1}, {a.port_table.k0, a.port_table.k1},
      {a.hash.k0, a.hash.k1},         {a.ip_id.k0, a.ip_id.k1}};
  EXPECT_EQ(keys.size(), 6u);
}

TEST(Identifiers, IsnClockTicksEveryFourMicroseconds) {
  EXPECT_EQ(utcp::isn_clock(Time{0}), 0u);
  EXPECT_EQ(utcp::isn_clock(Time{3999}), 0u);
  EXPECT_EQ(utcp::isn_clock(Time{4000}), 1u);
  EXPECT_EQ(utcp::isn_clock(Time{1'000'000}), 250u);  // 250 per ms
  EXPECT_EQ(utcp::isn_clock(Time{-1}), 0xffff'ffffu);  // floor below 0
  // 32 bits of 4 µs ticks wrap after 2^32 * 4 µs (about 4.8 h).
  EXPECT_EQ(utcp::isn_clock(Time{(std::int64_t{1} << 32) * 4000 + 8000}), 2u);
}

// m1-ip test 7: for a fixed key and tuple the ISN grows by 250 per ms of now
// (RFC 6528 §3, M in 4 µs ticks), and F differs across tuples.
TEST(Identifiers, IsnIncreasesBy250PerMillisecond) {
  const FourTuple t = tuple(40000, 80);
  const Time t0{5'000'000'123};
  Seq32 prev = utcp::isn_for(key, t, t0);
  for (int ms = 1; ms <= 1000; ++ms) {
    const Seq32 cur = utcp::isn_for(key, t, t0 + std::chrono::milliseconds(ms));
    EXPECT_EQ(cur - prev, 250u) << ms;
    prev = cur;
  }
  // Within one 4 µs tick nothing changes.
  EXPECT_EQ(utcp::isn_for(key, t, Time{4000}), utcp::isn_for(key, t, Time{7999}));
}

TEST(Identifiers, IsnDiffersAcrossTuples) {
  const Time now{123'456'789};
  std::set<std::uint32_t> isns;
  std::vector<FourTuple> tuples;
  for (std::uint16_t p = 0; p < 64; ++p) {
    tuples.push_back(tuple(static_cast<std::uint16_t>(40000 + p), 80));
    tuples.push_back(tuple(40000, static_cast<std::uint16_t>(1000 + p)));
    tuples.push_back(tuple(40000, 80, static_cast<std::uint8_t>(3 + p)));
  }
  for (const FourTuple& t : tuples) {
    isns.insert(utcp::isn_for(key, t, now).raw());
  }
  EXPECT_EQ(isns.size(), tuples.size());
  // A different key gives a different offset for the same tuple.
  const SipKey other{1, 2};
  EXPECT_NE(utcp::isn_for(key, tuples[0], now), utcp::isn_for(other, tuples[0], now));
}

TEST(Identifiers, StackIsnUsesNow) {
  utcp::StackConfig cfg;
  cfg.local_addr = Ipv4Addr::from_octets(10, 0, 0, 1);
  cfg.seed = utcp::Seed::from_u64(7);
  utcp::StackImpl s(cfg);
  const FourTuple t = tuple(40000, 80);
  s.advance(Time{2'000'000'000});
  const Seq32 a = s.core.isn(t);
  EXPECT_EQ(a, utcp::isn_for(s.core.keys().isn, t, Time{2'000'000'000}));
  s.advance(Time{2'001'000'000});
  EXPECT_EQ(s.core.isn(t) - a, 250u);
}

TEST(Identifiers, TimestampOffsetPerTuple) {
  const FourTuple t1 = tuple(40000, 80);
  const FourTuple t2 = tuple(40001, 80);
  EXPECT_EQ(utcp::ts_offset_for(key, t1), utcp::ts_offset_for(key, t1));
  EXPECT_NE(utcp::ts_offset_for(key, t1), utcp::ts_offset_for(key, t2));

  utcp::StackConfig cfg;
  cfg.seed = utcp::Seed::from_u64(7);
  {
    utcp::StackImpl s(cfg);
    EXPECT_EQ(s.core.ts_offset(t1), utcp::ts_offset_for(s.core.keys().ts_offset, t1));
  }
  cfg.tcp.ts_offset_random = false;  // RFC 7323 §5.4 offset off: TSval = the clock
  utcp::StackImpl s(cfg);
  EXPECT_EQ(s.core.ts_offset(t1), 0u);
  EXPECT_EQ(s.core.ts_offset(t2), 0u);
}

TEST(Identifiers, IpIdStartPerTuple) {
  std::set<std::uint16_t> ids;
  for (std::uint16_t p = 0; p < 32; ++p) {
    ids.insert(utcp::ip_id_start_for(key, tuple(static_cast<std::uint16_t>(40000 + p), 80)));
  }
  EXPECT_EQ(ids.size(), 32u);
  EXPECT_EQ(utcp::ip_id_start_for(key, tuple(40000, 80)),
            utcp::ip_id_start_for(key, tuple(40000, 80)));
}

}  // namespace
