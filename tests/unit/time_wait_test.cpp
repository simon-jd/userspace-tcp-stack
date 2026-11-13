#include "core/tcp/time_wait.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <random>

#include "core/timer/timer_heap.hpp"

namespace {

using utcp::Endpoint;
using utcp::FourTuple;
using utcp::Ipv4Addr;
using utcp::Seq32;
using utcp::SipKey;
using utcp::Time;
using utcp::TimerHeap;
using utcp::TimerKind;
using utcp::TimeWaitEntry;
using utcp::TimeWaitTable;
using namespace std::chrono_literals;

const SipKey key{0x1111111111111111ULL, 0x2222222222222222ULL};

FourTuple tuple(std::uint16_t i) {
  return FourTuple{Endpoint{Ipv4Addr::from_octets(10, 0, 0, 1), 80},
                   Endpoint{Ipv4Addr::from_octets(192, 0, 2, 9), static_cast<std::uint16_t>(30000 + i)}};
}

TimeWaitEntry entry(std::uint16_t i) {
  TimeWaitEntry e;
  e.tuple = tuple(i);
  e.snd_nxt = Seq32(1000u + i);
  e.rcv_nxt = Seq32(5000u + i);
  e.rcv_wnd = 65535u * 128u;  // scaled window, bytes
  e.rcv_wscale = 7;
  e.ts_recent = 0xdeadbeef;
  e.ts_recent_stamp = Time{123};
  e.ts_offset = 0x01020304u + i;
  e.ts_ok = true;
  e.conn_id = 40u + i;
  return e;
}

template <class T>
concept Iterable = requires(const T& t) { t.begin(); } || requires(const T& t) { t.end(); };
static_assert(!Iterable<TimeWaitTable>);

// m1-ip test 10: keyed insert/lookup/erase; entries hold rcv_wnd, rcv_wscale
// and ts_offset (the TIME-WAIT ACK's scaled window and TSval).
TEST(TimeWait, EntriesKeepWhatTimeWaitNeeds) {
  TimeWaitTable t(key);
  const std::uint32_t i0 = t.insert(entry(0));
  const std::uint32_t i1 = t.insert(entry(1));
  EXPECT_EQ(i0, 0u);
  EXPECT_EQ(i1, 1u);
  EXPECT_EQ(t.size(), 2u);
  EXPECT_EQ(t.find(tuple(1)), i1);
  EXPECT_EQ(t.find(tuple(2)), std::nullopt);
  const TimeWaitEntry& e = t.entry(i1);
  EXPECT_EQ(e, entry(1));
  EXPECT_EQ(e.rcv_wnd, 65535u * 128u);
  EXPECT_EQ(e.rcv_wscale, 7);
  EXPECT_EQ(e.ts_offset, 0x01020305u);
  EXPECT_TRUE(e.ts_ok);
  // Entries are mutable in place (a retransmitted FIN updates ts_recent).
  t.entry(i1).ts_recent = 7;
  EXPECT_EQ(t.entry(i1).ts_recent, 7u);
  t.erase(i0);
  EXPECT_FALSE(t.live(i0));
  EXPECT_EQ(t.find(tuple(0)), std::nullopt);
  EXPECT_EQ(t.size(), 1u);
  // The lowest free index is reused.
  EXPECT_EQ(t.insert(entry(5)), 0u);
  EXPECT_EQ(t.insert(entry(6)), 2u);
  t.check_invariants();
}

TEST(TimeWaitDeathTest, DuplicateTupleAborts) {
  TimeWaitTable t(key);
  t.insert(entry(0));
  EXPECT_DEATH(t.insert(entry(0)), "UTCP_CHECK");
}

// m1-ip test 10: entries expire through the timer heap (kind time_wait,
// owner = entry index).
TEST(TimeWait, EntriesExpireThroughTheTimerHeap) {
  TimeWaitTable t(key);
  TimerHeap h;
  const Time now{50'000'000'000};
  const std::uint32_t a = t.insert(entry(0), h, now + 60s);
  const std::uint32_t b = t.insert(entry(1), h, now + 30s);
  EXPECT_EQ(t.expiry(a, h), now + 60s);
  EXPECT_EQ(h.next_deadline(), now + 30s);
  t.check_invariants(h);
  // A retransmitted FIN restarts TIME-WAIT for b.
  t.restart(b, h, now + 20s + 60s);
  EXPECT_EQ(h.next_deadline(), now + 60s);
  EXPECT_EQ(h.pop_due(now + 60s - 1ns), std::nullopt);
  const auto fired = h.pop_due(now + 60s);
  ASSERT_TRUE(fired.has_value());
  EXPECT_EQ(fired->kind, TimerKind::time_wait);
  EXPECT_EQ(fired->owner, a);
  t.erase(fired->owner, h);  // the handler frees the entry and its timer
  EXPECT_EQ(t.find(tuple(0)), std::nullopt);
  EXPECT_EQ(h.timer_count(), 1u);
  const auto second = h.pop_due(now + 80s);
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(second->owner, b);
  t.erase(second->owner, h);
  EXPECT_EQ(t.size(), 0u);
  EXPECT_EQ(h.timer_count(), 0u);
  EXPECT_EQ(h.next_deadline(), Time::never());
  // An entry erased before expiry (a SYN reused the tuple) takes its timer.
  const std::uint32_t c = t.insert(entry(2), h, now + 100s);
  t.erase(c, h);
  EXPECT_EQ(h.armed_count(), 0u);
  t.check_invariants(h);
}

TEST(TimeWait, RandomOperationsMatchAReference) {
  TimeWaitTable t(key);
  TimerHeap h;
  std::map<std::uint16_t, std::uint32_t> ref;  // tuple id -> index
  std::mt19937 rng(7);
  for (int op = 0; op < 20000; ++op) {
    const auto id = static_cast<std::uint16_t>(rng() % 200);
    const auto it = ref.find(id);
    if (it == ref.end()) {
      ref[id] = t.insert(entry(id), h, Time{1'000'000'000LL + op});
    } else if (rng() % 2 == 0) {
      EXPECT_EQ(t.entry(it->second).conn_id, 40u + id);
      t.erase(it->second, h);
      ref.erase(it);
    } else {
      EXPECT_EQ(t.find(tuple(id)), it->second);
    }
    ASSERT_EQ(t.size(), ref.size());
    ASSERT_EQ(h.timer_count(), ref.size());
  }
  t.check_invariants(h);
  h.check_invariants();
}

}  // namespace
