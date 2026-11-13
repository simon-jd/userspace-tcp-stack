#include "core/tcp/send_queue.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <set>
#include <span>
#include <utility>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/rate.hpp"
#include "utcp/random.hpp"

namespace {

using utcp::AckedSummary;
using utcp::ChunkPool;
using utcp::Counters;
using utcp::RateState;
using utcp::SendQueue;
using utcp::Time;
using utcp::TxSeg;
using utcp::packets_in_flight;

std::vector<std::byte> pattern(std::size_t n, std::uint64_t start) {
  std::vector<std::byte> v(n);
  for (std::size_t i = 0; i < n; ++i) {
    v[i] = static_cast<std::byte>(((start + i) * 131 + 7) & 0xff);
  }
  return v;
}

Time at(std::int64_t ms) { return Time{ms * 1'000'000}; }

// Records DeliveredFn calls.
struct Deliveries {
  std::vector<std::pair<std::uint64_t, bool>> calls;  // (id, via_sack)
  auto fn() {
    return [this](const TxSeg& s, bool via_sack) { calls.emplace_back(s.id, via_sack); };
  }
};

// Writes `n` bytes and sends them as `n / mss` (+1) TxSegs.
void send_all(SendQueue& q, std::uint32_t mss, Time now, const RateState& rs = {}) {
  while (q.nxt() < q.end()) {
    const auto len = static_cast<std::uint32_t>(std::min<std::uint64_t>(mss, q.end() - q.nxt()));
    q.on_transmit(q.nxt(), len, false, now, rs);
  }
}

// The packet counters of q.segs(); the byte counters are copied from q.
Counters recount(const SendQueue& q) {
  Counters c = q.counters();
  c.packets_out = c.sacked_out = c.lost_out = c.retrans_out = 0;
  for (const TxSeg& s : q.segs()) {
    ++c.packets_out;
    c.sacked_out += s.sacked ? 1u : 0u;
    c.lost_out += s.lost ? 1u : 0u;
    c.retrans_out += s.retrans_inflight ? 1u : 0u;
  }
  return c;
}

TEST(SendQueue, WriteAndCopyOutAcrossRingWrap) {
  ChunkPool pool(64);
  SendQueue q(pool, 10'000);
  const auto a = pattern(10'000, 0);
  EXPECT_EQ(q.write(a), 10'000u);
  EXPECT_EQ(q.free_space(), 0u);
  EXPECT_EQ(q.write(a), 0u);  // full
  send_all(q, 1000, at(0));
  Deliveries d;
  q.on_cumulative_ack(6000, at(1), d.fn());
  EXPECT_EQ(q.una(), 6000u);
  EXPECT_EQ(q.free_space(), 6000u);
  // The next writes reuse the window [10000, 16000) past the first chunks.
  const auto b = pattern(6000, 10'000);
  EXPECT_EQ(q.write(b), 6000u);
  std::vector<std::byte> out(9000);
  q.copy_out(7000, out);
  EXPECT_EQ(out, pattern(9000, 7000));
  // Chunks below una were returned: 16000 - 6000 bytes span 3 chunks.
  EXPECT_LE(pool.in_use(), 4u);
  send_all(q, 1000, at(2));
  q.on_cumulative_ack(16'000, at(3), d.fn());
  EXPECT_EQ(pool.in_use(), 0u);
  q.check_invariants();
}

TEST(SendQueue, WriteStopsWhenTheChunkPoolIsExhausted) {
  ChunkPool pool(2);
  SendQueue q(pool, 64 * 1024);
  EXPECT_EQ(q.write(pattern(10'000, 0)), 2u * ChunkPool::chunk_size);
  EXPECT_EQ(q.write(pattern(10, 0)), 0u);
}

TEST(SendQueue, CumulativeAckInsideASegmentTrimsIt) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(3000, 0));
  send_all(q, 1000, at(0));
  Deliveries d;
  const AckedSummary s = q.on_cumulative_ack(1500, at(1), d.fn());
  EXPECT_EQ(s.pkts, 1u);
  ASSERT_EQ(q.segs().size(), 2u);
  EXPECT_EQ(q.segs()[0].off, 1500u);
  EXPECT_EQ(q.segs()[0].len, 500u);
  EXPECT_EQ(q.segs()[0].id, 1u);
  EXPECT_EQ(q.counters().packets_out, 2u);  // still one packet
  EXPECT_EQ(q.counters().bytes_acked, 1500u);
  ASSERT_EQ(d.calls.size(), 1u);  // only the fully acked segment is delivered
  // A retransmission of the trimmed head sends what is left.
  q.mark_lost(1500);
  const TxSeg& r = q.on_transmit(1500, 500, false, at(2), {});
  EXPECT_EQ(r.tx_count, 2u);
  EXPECT_EQ(q.counters().bytes_retrans, 500u);
  q.check_invariants();
}

TEST(SendQueue, PartialSackBlockLeavesTheSegmentUnsackedAndUnsplit) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(4000, 0));
  send_all(q, 1000, at(0));
  Deliveries d;
  const utcp::Range blocks[] = {{1500, 2500}, {3000, 3999}};
  const auto s = q.on_sack(blocks, at(1), d.fn());
  EXPECT_EQ(s.newly_sacked, 0u);
  EXPECT_TRUE(d.calls.empty());
  EXPECT_EQ(q.segs().size(), 4u);
  for (const TxSeg& seg : q.segs()) {
    EXPECT_FALSE(seg.sacked);
    EXPECT_EQ(seg.len, 1000u);
  }
  const utcp::Range whole[] = {{1000, 3000}};
  EXPECT_EQ(q.on_sack(whole, at(2), d.fn()).newly_sacked, 2u);
  EXPECT_EQ(q.counters().sacked_out, 2u);
  q.check_invariants();
}

TEST(SendQueue, DeliveredOncePerSegmentInSequenceOrder) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(6000, 0));
  send_all(q, 1000, at(0));  // ids 0..5 at offsets 0, 1000, ..., 5000
  Deliveries d;
  // SACK [3000, 5000) and [1000, 2000), newest block first as receivers
  // send them (RFC 2018 §4): delivered in sequence order all the same.
  const utcp::Range blocks[] = {{3000, 5000}, {1000, 2000}};
  const auto s = q.on_sack(blocks, at(1), d.fn());
  EXPECT_EQ(s.newly_sacked, 3u);
  EXPECT_EQ(s.high_sacked, 5000u);
  // The same blocks again deliver nothing.
  EXPECT_EQ(q.on_sack(blocks, at(2), d.fn()).newly_sacked, 0u);
  // The cumulative ACK to 6000 reports only the segments not SACKed earlier.
  const AckedSummary a = q.on_cumulative_ack(6000, at(3), d.fn());
  EXPECT_EQ(a.pkts, 6u);
  const std::vector<std::pair<std::uint64_t, bool>> expect{
      {1, true}, {3, true}, {4, true}, {0, false}, {2, false}, {5, false}};
  EXPECT_EQ(d.calls, expect);
  EXPECT_EQ(q.counters(), (Counters{0, 0, 0, 0, 6000, 0, 6000}));
}

TEST(SendQueue, SackBlocksInAnyOrderDeliverInSequenceOrder) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(10'000, 0));
  send_all(q, 1000, at(0));  // ids 0..9 at offsets 0, 1000, ..., 9000
  Deliveries d;
  // Four blocks in descending order; [6000, 8000) and [5000, 7000) overlap,
  // [2000, 3000) comes twice, and [3500, 4500) covers no whole segment.
  const utcp::Range blocks[] = {
      {6000, 8000}, {5000, 7000}, {3500, 4500}, {2000, 3000}, {2000, 3000}, {8000, 9000}};
  EXPECT_EQ(q.on_sack(blocks, at(1), d.fn()).newly_sacked, 5u);
  const std::vector<std::pair<std::uint64_t, bool>> expect{
      {2, true}, {5, true}, {6, true}, {7, true}, {8, true}};
  EXPECT_EQ(d.calls, expect);
  q.check_invariants();
  // More than max_sack_ranges blocks is a caller bug.
  const std::vector<utcp::Range> too_many(utcp::max_sack_ranges + 1, utcp::Range{0, 1000});
  EXPECT_DEATH(q.on_sack(too_many, at(2), d.fn()), "");
}

TEST(SendQueue, DeliveredFnSeesTheSegmentBeforeItIsPopped) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(2000, 0));
  send_all(q, 1000, at(0));
  std::vector<std::size_t> sizes;
  q.on_cumulative_ack(2000, at(1), [&](const TxSeg& s, bool) {
    sizes.push_back(q.segs().size());
    EXPECT_EQ(q.find(s.off), &s);
  });
  EXPECT_EQ(sizes, (std::vector<std::size_t>{2, 1}));
}

TEST(SendQueue, MarkLostAndClearAllSacked) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(5000, 0));
  send_all(q, 1000, at(0));
  Deliveries d;
  const utcp::Range blocks[] = {{2000, 4000}};
  q.on_sack(blocks, at(1), d.fn());
  q.mark_lost(0);
  q.mark_lost(1000);
  q.mark_lost(2000);  // SACKed: no effect
  EXPECT_EQ(q.counters().lost_out, 2u);
  EXPECT_EQ(q.lost_total(), 2u);
  EXPECT_FALSE(q.find(2000)->lost);
  // Retransmit 0, then mark it lost again: the retransmission is lost.
  q.on_transmit(0, 1000, false, at(2), {});
  EXPECT_EQ(q.counters().retrans_out, 1u);
  EXPECT_EQ(packets_in_flight(q.counters()), 5u - 2u - 2u + 1u);
  q.mark_lost(0);
  EXPECT_EQ(q.counters().retrans_out, 0u);
  EXPECT_EQ(q.counters().lost_out, 2u);
  EXPECT_EQ(q.lost_total(), 3u);
  // SACK of a lost segment with a retransmission in flight clears both.
  q.on_transmit(1000, 1000, false, at(3), {});
  const utcp::Range b2[] = {{1000, 2000}};
  q.on_sack(b2, at(4), d.fn());
  EXPECT_EQ(q.counters().retrans_out, 0u);
  EXPECT_EQ(q.counters().lost_out, 1u);
  EXPECT_EQ(q.counters().sacked_out, 3u);
  q.clear_all_sacked();
  EXPECT_EQ(q.counters().sacked_out, 0u);
  for (const TxSeg& s : q.segs()) {
    EXPECT_FALSE(s.sacked);
  }
  EXPECT_EQ(q.counters(), recount(q));
  q.check_invariants();
}

TEST(SendQueue, IdsStayStableAcrossPopsAndSplit) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(4000, 0));
  q.on_transmit(0, 1000, false, at(0), {});     // id 0
  q.on_transmit(1000, 1400, false, at(0), {});  // id 1
  q.on_transmit(2400, 1600, false, at(0), {});  // id 2
  Deliveries d;
  q.on_cumulative_ack(1000, at(1), d.fn());
  EXPECT_EQ(q.segs()[0].id, 1u);
  q.mark_lost(2400);
  q.split_to_mss(600);
  // [1000,1600) id 1, [1600,2200) id 3, [2200,2400) id 4,
  // [2400,3000) id 2, [3000,3600) id 5, [3600,4000) id 6 (all lost).
  std::vector<std::pair<std::uint64_t, std::uint64_t>> got;
  for (const TxSeg& s : q.segs()) {
    got.emplace_back(s.id, s.off);
  }
  const std::vector<std::pair<std::uint64_t, std::uint64_t>> expect{
      {1, 1000}, {3, 1600}, {4, 2200}, {2, 2400}, {5, 3000}, {6, 3600}};
  EXPECT_EQ(got, expect);
  EXPECT_EQ(q.counters().packets_out, 6u);
  EXPECT_EQ(q.counters().lost_out, 3u);
  EXPECT_TRUE(q.find(3600)->lost);
  EXPECT_FALSE(q.find(1600)->lost);
  q.on_cumulative_ack(2400, at(2), d.fn());
  EXPECT_EQ(q.segs()[0].id, 2u);
  q.check_invariants();
}

// split (m1-tcp-core): one TxSeg cut before a retransmission (Linux
// tcp_fragment); the tail keeps the flags and takes the FIN.
TEST(SendQueue, SplitCutsOneSegment) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(3000, 0));
  q.on_transmit(0, 1448, false, at(0), {});     // id 0
  q.on_transmit(1448, 1448, false, at(0), {});  // id 1
  q.on_transmit(2896, 104, true, at(0), {});    // id 2, with FIN
  q.mark_lost(0);
  q.split(0, 1436);
  ASSERT_EQ(q.segs().size(), 4u);
  EXPECT_EQ(q.segs()[0].id, 0u);
  EXPECT_EQ(q.segs()[0].len, 1436u);
  EXPECT_EQ(q.segs()[1].id, 3u);
  EXPECT_EQ(q.segs()[1].off, 1436u);
  EXPECT_EQ(q.segs()[1].len, 12u);
  EXPECT_TRUE(q.segs()[1].lost);
  EXPECT_EQ(q.counters().packets_out, 4u);
  EXPECT_EQ(q.counters().lost_out, 2u);
  EXPECT_EQ(q.counters(), recount(q));
  q.split(2896, 100);
  ASSERT_EQ(q.segs().size(), 5u);
  EXPECT_FALSE(q.segs()[3].fin);
  EXPECT_TRUE(q.segs()[4].fin);
  EXPECT_EQ(q.segs()[4].len, 4u);
  EXPECT_EQ(q.counters(), recount(q));
  q.on_transmit(0, 1436, false, at(1), {});
  EXPECT_EQ(q.counters().retrans_out, 1u);
  q.check_invariants();
}

TEST(SendQueue, FinRidesOnTheLastSegmentUntilAcked) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(1500, 0));
  q.on_transmit(0, 1000, false, at(0), {});
  q.on_transmit(1000, 500, true, at(0), {});
  EXPECT_TRUE(q.fin_sent());
  EXPECT_EQ(q.nxt_with_fin(), 1501u);
  Deliveries d;
  // Payload acked, FIN not: the segment stays as a bare FIN.
  auto s = q.on_cumulative_ack(1500, false, at(1), d.fn());
  EXPECT_EQ(s.pkts, 1u);
  ASSERT_EQ(q.segs().size(), 1u);
  EXPECT_EQ(q.segs()[0].len, 0u);
  EXPECT_TRUE(q.segs()[0].fin);
  EXPECT_EQ(q.counters().packets_out, 1u);
  // A bare FIN is never SACKed.
  const utcp::Range blocks[] = {{1000, 1500}};
  EXPECT_EQ(q.on_sack(blocks, at(1), d.fn()).newly_sacked, 0u);
  // Retransmit the bare FIN, then ACK it.
  q.mark_lost(1500);
  q.on_transmit(1500, 0, true, at(2), {});
  s = q.on_cumulative_ack(1500, true, at(3), d.fn());
  EXPECT_EQ(s.pkts, 1u);
  EXPECT_TRUE(s.retrans_acked);
  EXPECT_TRUE(q.fin_acked());
  EXPECT_EQ(q.una_with_fin(), 1501u);
  EXPECT_TRUE(q.segs().empty());
  q.check_invariants();
}

TEST(SendQueue, BareFinIsItsOwnSegment) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(1000, 0));
  send_all(q, 1000, at(0));
  q.on_transmit(1000, 0, true, at(1), {});
  EXPECT_EQ(q.counters().packets_out, 2u);
  Deliveries d;
  EXPECT_EQ(q.on_cumulative_ack(1000, false, at(2), d.fn()).pkts, 1u);
  EXPECT_EQ(q.on_cumulative_ack(1000, true, at(3), d.fn()).pkts, 1u);
  EXPECT_EQ(d.calls.size(), 2u);
}

TEST(SendQueue, RateSnapshotTakenAtEveryTransmission) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(1000, 0));
  RateState rs;
  // No rate_on_send yet: no snapshot.
  EXPECT_TRUE(q.on_transmit(0, 1000, false, at(0), rs).rate_used);
  rs.has_sent = true;
  rs.delivered = 7;
  rs.delivered_time = at(5);
  rs.first_tx_time = at(4);
  rs.app_limited = 9;
  q.mark_lost(0);
  const TxSeg& s = q.on_transmit(0, 1000, false, at(6), rs);
  EXPECT_FALSE(s.rate_used);
  EXPECT_EQ(s.delivered, 7u);
  EXPECT_EQ(s.delivered_time, at(5));
  EXPECT_EQ(s.first_tx_time, at(4));
  EXPECT_TRUE(s.app_limited);
  EXPECT_EQ(s.first_tx, at(0));
  EXPECT_EQ(s.last_tx, at(6));
  EXPECT_TRUE(s.ever_retrans);
  // A SACK consumes the snapshot.
  Deliveries d;
  const utcp::Range blocks[] = {{0, 1000}};
  bool seen_unused = false;
  q.on_sack(blocks, at(7), [&](const TxSeg& seg, bool) { seen_unused = !seg.rate_used; });
  EXPECT_TRUE(seen_unused);
  EXPECT_TRUE(q.find(0)->rate_used);
}

// Acceptance test 2: packets_in_flight = packets_out - sacked_out - lost_out
// + retrans_out, with and without SACK.
TEST(SendQueue, InFlightWithSack) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.write(pattern(10'000, 0));
  send_all(q, 1000, at(0));  // 10 packets
  Deliveries d;
  EXPECT_EQ(packets_in_flight(q.counters()), 10u);
  const utcp::Range b1[] = {{1000, 4000}};
  q.on_sack(b1, at(1), d.fn());
  EXPECT_EQ(packets_in_flight(q.counters()), 7u);
  q.mark_lost(0);
  EXPECT_EQ(packets_in_flight(q.counters()), 6u);
  q.on_transmit(0, 1000, false, at(2), {});
  EXPECT_EQ(packets_in_flight(q.counters()), 7u);
  q.on_cumulative_ack(4000, at(3), d.fn());  // pops 0 (retransmitted) and the SACKed 1-3
  EXPECT_EQ(q.counters(), (Counters{6, 0, 0, 0, 11'000, 1000, 4000}));
  EXPECT_EQ(packets_in_flight(q.counters()), 6u);
}

TEST(SendQueue, InFlightWithoutSack) {
  ChunkPool pool(16);
  SendQueue q(pool, 64 * 1024);
  q.set_sack_ok(false);
  q.write(pattern(5000, 0));
  send_all(q, 1000, at(0));  // 5 packets
  // Blocks are ignored without SACK.
  const utcp::Range b1[] = {{1000, 4000}};
  Deliveries d;
  EXPECT_EQ(q.on_sack(b1, at(1), d.fn()).newly_sacked, 0u);
  // Duplicate ACKs raise sacked_out while sacked_out + max(lost_out, 1) <= packets_out.
  for (std::uint32_t i = 1; i <= 6; ++i) {
    q.reno_dupack();
    EXPECT_EQ(q.counters().sacked_out, std::min(i, 4u)) << i;
    EXPECT_EQ(packets_in_flight(q.counters()), 5u - std::min(i, 4u));
  }
  // With two packets lost the cap is packets_out - 2.
  q.mark_lost(0);
  q.mark_lost(1000);
  EXPECT_EQ(q.counters().sacked_out, 3u);
  EXPECT_EQ(packets_in_flight(q.counters()), 0u);
  q.on_transmit(0, 1000, false, at(2), {});
  EXPECT_EQ(packets_in_flight(q.counters()), 1u);
  // A cumulative ACK of n = 2 packets removes min(n - 1, sacked_out) = 1.
  q.on_cumulative_ack(2000, at(3), d.fn());
  EXPECT_EQ(q.counters().packets_out, 3u);
  EXPECT_EQ(q.counters().lost_out, 0u);
  EXPECT_EQ(q.counters().sacked_out, 2u);
  EXPECT_EQ(packets_in_flight(q.counters()), 1u);
  // n = 1 removes nothing; then the cap applies (2 + 1 <= 2 fails -> 1).
  q.on_cumulative_ack(3000, at(4), d.fn());
  EXPECT_EQ(q.counters().packets_out, 2u);
  EXPECT_EQ(q.counters().sacked_out, 1u);
  EXPECT_EQ(packets_in_flight(q.counters()), 1u);
  q.clear_all_sacked();
  EXPECT_EQ(q.counters().sacked_out, 0u);
  q.on_cumulative_ack(5000, at(5), d.fn());
  EXPECT_EQ(q.counters(), (Counters{0, 0, 0, 0, 6000, 1000, 5000}));
  q.check_invariants();
}

// 1e5 random operations; after each, the counters equal a recount and
// check_invariants holds.
void random_ops(bool sack_ok, std::uint64_t seed) {
  ChunkPool pool(1024);
  SendQueue q(pool, 256 * 1024);
  q.set_sack_ok(sack_ok);
  utcp::Rng rng(utcp::Seed::from_u64(seed));
  std::uint64_t written = 0;
  std::int64_t t = 0;
  // Ids delivered and still deliverable only once: clear_all_sacked makes the
  // segments in the queue deliverable again (a later SACK delivers them anew).
  std::set<std::uint64_t> delivered_ids;
  auto fn = [&](const TxSeg& s, bool) { EXPECT_TRUE(delivered_ids.insert(s.id).second) << s.id; };
  for (int step = 0; step < 100'000; ++step) {
    ++t;
    const std::uint32_t op = rng.below(9);
    const auto segs = q.segs();
    if (op == 0) {
      const auto n = rng.below(5000) + 1;
      written += q.write(pattern(n, written));
    } else if (op <= 2) {
      if (q.nxt() < q.end()) {
        const auto len = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(rng.below(1500) + 1, q.end() - q.nxt()));
        q.on_transmit(q.nxt(), len, false, at(t), {});
      }
    } else if (op == 3 && !segs.empty()) {
      const std::uint64_t span = q.nxt() - q.una();
      q.on_cumulative_ack(q.una() + rng.below64(span / 4 + 1), at(t), fn);
    } else if (op == 4 && !segs.empty()) {
      // 1-4 random blocks, possibly overlapping, in random order: one call
      // delivers in sequence order.
      const std::uint64_t span = q.nxt() - q.una();
      std::vector<utcp::Range> blocks(rng.below(4) + 1);
      for (utcp::Range& r : blocks) {
        r.begin = q.una() + rng.below64(span);
        r.end = std::min(q.nxt(), r.begin + rng.below(6000) + 1);
      }
      std::uint64_t last_end = 0;
      q.on_sack(blocks, at(t), [&](const TxSeg& s, bool via_sack) {
        fn(s, via_sack);
        EXPECT_LE(last_end, s.off) << step;
        last_end = s.end();
      });
    } else if (op == 5 && !segs.empty()) {
      q.mark_lost(segs[rng.below(static_cast<std::uint32_t>(segs.size()))].off);
    } else if (op == 6 && !segs.empty()) {
      const TxSeg& s = segs[rng.below(static_cast<std::uint32_t>(segs.size()))];
      if (s.lost && !s.retrans_inflight) {
        q.on_transmit(s.off, s.len, s.fin, at(t), {});
      }
    } else if (op == 7) {
      if (rng.below(50) == 0) {
        for (const TxSeg& s : q.segs()) {
          delivered_ids.erase(s.id);
        }
        q.clear_all_sacked();
      } else if (rng.below(100) == 0 && !segs.empty()) {
        const TxSeg& s = segs[rng.below(static_cast<std::uint32_t>(segs.size()))];
        if (s.len > 1) {
          q.split(s.off, rng.below(s.len - 1) + 1);
        }
      } else if (rng.below(200) == 0) {
        q.split_to_mss(static_cast<std::uint16_t>(rng.below(1400) + 100));
      } else {
        q.reno_dupack();
      }
    } else if (op == 8 && !segs.empty() && rng.below(20) == 0) {
      q.on_cumulative_ack(q.nxt(), at(t), fn);
    }
    ASSERT_EQ(q.counters().packets_out, recount(q).packets_out) << step;
    ASSERT_EQ(q.counters().lost_out, recount(q).lost_out) << step;
    ASSERT_EQ(q.counters().retrans_out, recount(q).retrans_out) << step;
    if (sack_ok) {
      ASSERT_EQ(q.counters().sacked_out, recount(q).sacked_out) << step;
    }
    q.check_invariants();
  }
  // The bytes copied out are the bytes written.
  if (q.end() > q.una()) {
    const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(q.end() - q.una(), 20'000));
    std::vector<std::byte> out(n);
    q.copy_out(q.una(), out);
    EXPECT_EQ(out, pattern(n, q.una()));
  }
}

TEST(SendQueue, RandomOperationsKeepCountersWithSack) { random_ops(true, 1); }
TEST(SendQueue, RandomOperationsKeepCountersWithoutSack) { random_ops(false, 2); }

}  // namespace
