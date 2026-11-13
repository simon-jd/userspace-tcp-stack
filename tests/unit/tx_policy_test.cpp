#include "core/tcp/tx_policy.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

#include "core/tcp/cc.hpp"
#include "utcp/config.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::CcConn;
using utcp::Duration;
using utcp::ProfileId;
using utcp::SendCheck;
using utcp::Time;
using utcp::TxPolicy;
using utcp::tcp_config;

utcp::TcpConfig with_nagle(utcp::Nagle n) {
  utcp::TcpConfig c = tcp_config(ProfileId::linux_compat);
  c.nagle = n;
  return c;
}

// A candidate segment: mss 1000, max_snd_wnd 10000.
SendCheck check(std::uint32_t seg_len, std::uint64_t unsent, std::uint32_t usable,
                std::uint64_t una, std::uint64_t nxt) {
  SendCheck c;
  c.seg_len = seg_len;
  c.mss = 1000;
  c.usable_window = usable;
  c.max_snd_wnd = 10'000;
  c.unsent = unsent;
  c.snd_una = una;
  c.snd_nxt = nxt;
  return c;
}

TEST(TxPolicy, NagleRfc896Table) {
  const TxPolicy p(with_nagle(utcp::Nagle::rfc896));
  struct Row {
    std::uint32_t len;
    std::uint64_t una, nxt;
    bool fin, nodelay, allowed;
  };
  const Row rows[] = {
      {1000, 0, 5000, false, false, true},   // full segment
      {500, 0, 0, false, false, true},       // small, nothing unacknowledged
      {500, 0, 1000, false, false, false},   // small, data unacknowledged: held
      {500, 4000, 5000, false, false, false},
      {500, 0, 1000, true, false, true},     // FIN is exempt
      {500, 0, 1000, false, true, true},     // TCP_NODELAY
      {0, 0, 1000, true, false, true},       // bare FIN
  };
  for (const Row& r : rows) {
    SendCheck c = check(r.len, r.len, 10'000, r.una, r.nxt);
    c.fin = r.fin;
    c.nodelay = r.nodelay;
    EXPECT_EQ(p.nagle_allows(c), r.allowed) << r.len << " " << r.una << " " << r.nxt;
  }
}

TEST(TxPolicy, NagleMinshallTable) {
  TxPolicy p(with_nagle(utcp::Nagle::minshall));
  // No small segment sent yet: small segments go even with data unacknowledged.
  EXPECT_TRUE(p.nagle_allows(check(500, 500, 10'000, 0, 3000)));
  p.on_data_sent(0, 1000, 1000);    // full: snd_sml unchanged
  p.on_data_sent(1000, 400, 1000);  // small: snd_sml = 1400
  p.on_data_sent(1400, 1000, 1000);
  // The small segment [1000, 1400) is unacknowledged: hold.
  EXPECT_FALSE(p.nagle_allows(check(500, 500, 10'000, 0, 2400)));
  EXPECT_FALSE(p.nagle_allows(check(500, 500, 10'000, 1000, 2400)));
  // Acknowledged, full segments still out: minshall sends, rfc896 would hold.
  EXPECT_TRUE(p.nagle_allows(check(500, 500, 10'000, 1400, 2400)));
  const TxPolicy rfc(with_nagle(utcp::Nagle::rfc896));
  EXPECT_FALSE(rfc.nagle_allows(check(500, 500, 10'000, 1400, 2400)));
  // Full segments, FIN and nodelay are never held.
  EXPECT_TRUE(p.nagle_allows(check(1000, 5000, 10'000, 0, 2400)));
  SendCheck fin = check(500, 500, 10'000, 0, 2400);
  fin.fin = true;
  EXPECT_TRUE(p.nagle_allows(fin));
  SendCheck nd = check(500, 500, 10'000, 0, 2400);
  nd.nodelay = true;
  EXPECT_TRUE(p.nagle_allows(nd));
}

// RFC 9293 §3.8.6.2.1 with D = unsent, U = usable window, Fs = 1/2.
TEST(TxPolicy, SenderSwsCases) {
  const TxPolicy p(with_nagle(utcp::Nagle::rfc896));
  // (1) min(D, U) >= Eff.snd.MSS.
  EXPECT_TRUE(p.sws_allows(check(1000, 5000, 3000, 0, 2000)));
  // (2) all queued data fits, nothing unacknowledged.
  EXPECT_TRUE(p.sws_allows(check(500, 500, 10'000, 0, 0)));
  // (2) with data unacknowledged: the Nagle bracket holds it...
  EXPECT_FALSE(p.sws_allows(check(500, 500, 10'000, 0, 1000)));
  // ...unless Nagle is off.
  SendCheck nd = check(500, 500, 10'000, 0, 1000);
  nd.nodelay = true;
  EXPECT_TRUE(p.sws_allows(nd));
  // Window-limited small segment: U = 600 < MSS and < max_snd_wnd / 2 = 5000.
  EXPECT_FALSE(p.sws_allows(check(600, 8000, 600, 0, 0)));
  nd = check(600, 8000, 600, 0, 0);
  nd.nodelay = true;
  EXPECT_FALSE(p.sws_allows(nd));  // SWS applies with Nagle off too
  // (3) min(D, U) >= Fs * max_snd_wnd: max_snd_wnd 1000, U 600 >= 500.
  SendCheck f = check(600, 8000, 600, 0, 0);
  f.max_snd_wnd = 1000;
  EXPECT_TRUE(p.sws_allows(f));
  f.snd_nxt = 400;  // [SND.NXT = SND.UNA] fails
  f.snd_una = 0;
  EXPECT_FALSE(p.sws_allows(f));
  f.max_snd_wnd = 1201;  // 600 < 600.5
  f.snd_nxt = 0;
  EXPECT_FALSE(p.sws_allows(f));
  // Zero window, empty queue, bare FIN.
  EXPECT_FALSE(p.sws_allows(check(0, 100, 0, 0, 0)));
  EXPECT_FALSE(p.sws_allows(check(0, 0, 10'000, 0, 0)));
  SendCheck bare = check(0, 0, 0, 0, 0);
  bare.fin = true;
  EXPECT_TRUE(p.sws_allows(bare));
  // sender_sws = false sends whatever fits.
  utcp::TcpConfig off = tcp_config(ProfileId::rfc);
  off.sender_sws = false;
  EXPECT_TRUE(TxPolicy(off).sws_allows(check(600, 8000, 600, 0, 0)));
}

TEST(TxPolicy, PacingBurstFromTsoAutosize) {
  const std::uint32_t gso = tcp_config(ProfileId::linux_compat).gso_max_size;  // 65215
  EXPECT_EQ(gso, 65215u);
  struct Row {
    std::uint64_t rate;  // bytes/s
    Duration min_rtt;
    std::uint32_t mss, min_tso, segs;
  };
  const Row rows[] = {
      // 12 Mbit/s, 10 ms: 1464 bytes (rate >> 10), 65215 >> 19 = 0 -> 1, floor 2.
      {1'500'000, 10ms, 1448, 2, 2},
      // 1 Gbit/s, 10 ms: 122070 bytes, capped at gso_max_size: 65215 / 1448 = 45.
      {125'000'000, 10ms, 1448, 2, 45},
      // 1 Gbit/s, 100 us: (100 >> 9) = 0 adds a full gso_max_size; still 45.
      {125'000'000, 100us, 1448, 2, 45},
      // 12 Mbit/s, 1 ms: 1464 + (65215 >> 1) = 34071 -> 23.
      {1'500'000, 1ms, 1448, 2, 23},
      // 12 Mbit/s, 300 us: 1464 + 65215, capped -> 45.
      {1'500'000, 300us, 1448, 2, 45},
      // 100 Mbit/s, 5 ms: 12207 + (65215 >> 9) = 12334 -> 8.
      {12'500'000, 5ms, 1448, 2, 8},
      // No min_rtt sample yet (~0U in Linux): no RTT term.
      {1'500'000, Duration::max(), 1448, 2, 2},
      // BBR below 1.2 Mbit/s uses min_tso_segs 1.
      {100'000, 10ms, 1448, 1, 1},
      {1'500'000, 10ms, 536, 2, 2},
      // 10 Gbit/s, 20 ms.
      {1'250'000'000, 20ms, 1448, 2, 45},
  };
  for (const Row& r : rows) {
    EXPECT_EQ(utcp::pacing_burst_segments(r.rate, r.min_rtt, gso, r.mss, r.min_tso), r.segs)
        << r.rate << " " << r.min_rtt.count();
  }
}

TEST(TxPolicy, PacingNextCreditsLateness) {
  // 12 Mbit/s, two 1448-byte segments: len_ns = 2896e9 / 1.5e6 = 1930666 ns.
  const std::uint64_t rate = 1'500'000;
  const Time pn{10'000'000'000};
  // On time: pacing_next + len_ns.
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn, 2896, rate), pn + Duration{1'930'666});
  // 5 ms late: credit min(len_ns / 2, 5 ms) = 965333: now + 965333.
  const Time late = pn + 5ms;
  EXPECT_EQ(utcp::pacing_next_after_send(pn, late, 2896, rate), late + Duration{965'333});
  // 0.3 ms late: the whole 300000 ns is credited.
  const Time bit_late = pn + 300us;
  EXPECT_EQ(utcp::pacing_next_after_send(pn, bit_late, 2896, rate),
            bit_late + Duration{1'630'666});
  // Early (the gate was open for another reason): from pacing_next, no credit.
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn - 1ms, 2896, rate), pn + Duration{1'930'666});
  // No rate: nothing added.
  EXPECT_EQ(utcp::pacing_next_after_send(pn, late, 2896, 0), late);
}

TEST(TxPolicy, PacingAppliesAfterTenSegments) {
  CcConn cc;
  utcp::TcpConfig knob = tcp_config(ProfileId::linux_compat);
  knob.test_fixed_pacing_rate = 1'000'000;
  const TxPolicy p(knob);
  for (std::uint64_t n = 0; n < 10; ++n) {
    EXPECT_FALSE(p.pacing_applies(cc, n)) << n;  // the first 10 data segments
  }
  EXPECT_TRUE(p.pacing_applies(cc, 10));
  cc.pacing_rate = 5;
  EXPECT_EQ(p.gate_rate(cc), 1'000'000u);  // the knob wins over the CC's rate

  utcp::TcpConfig c = tcp_config(ProfileId::linux_compat);  // cc_requested
  const TxPolicy q(c);
  EXPECT_FALSE(q.pacing_applies(cc, 100));
  cc.pacing_needed = true;
  EXPECT_TRUE(q.pacing_applies(cc, 100));
  EXPECT_FALSE(q.pacing_applies(cc, 9));
  EXPECT_EQ(q.gate_rate(cc), 5u);
  c.pacing = utcp::Pacing::never;
  EXPECT_FALSE(TxPolicy(c).pacing_applies(cc, 100));
  c.pacing = utcp::Pacing::always;
  cc.pacing_needed = false;
  EXPECT_TRUE(TxPolicy(c).pacing_applies(cc, 100));
}

TEST(TxPolicy, PacingRateFromCwndAndSrtt) {
  const utcp::TcpConfig cfg = tcp_config(ProfileId::linux_compat);
  CcConn cc;
  cc.mss = 1448;
  cc.cwnd = 10;
  cc.ssthresh = utcp::cwnd_infinite;
  EXPECT_EQ(utcp::pacing_rate_for(cc, 0, cfg), 0u);  // no RTT sample
  cc.srtt = 10ms;
  // Slow start: 200 % of 1448 * 10 / 10 ms = 2896000 bytes/s.
  EXPECT_EQ(utcp::pacing_rate_for(cc, 0, cfg), 2'896'000u);
  // cwnd >= ssthresh / 2: 120 % of 1448 * 20 / 10 ms.
  cc.cwnd = 20;
  cc.ssthresh = 30;
  EXPECT_EQ(utcp::pacing_rate_for(cc, 0, cfg), 3'475'200u);
  // max(cwnd, packets_out).
  EXPECT_EQ(utcp::pacing_rate_for(cc, 40, cfg), 6'950'400u);
  cc.max_pacing_rate = 1'000'000;
  EXPECT_EQ(utcp::pacing_rate_for(cc, 40, cfg), 1'000'000u);
}

}  // namespace
