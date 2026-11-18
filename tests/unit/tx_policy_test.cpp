#include "core/tcp/tx_policy.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/tcp/cc.hpp"
#include "core/tcp/recovery.hpp"
#include "support/recovery_script.hpp"
#include "tcp_test_util.hpp"
#include "utcp/config.hpp"
#include "utcp/trace.hpp"

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

// ---- m2b-rate-pacing acceptance test 2 (M2-DESIGN §2.5, §4.1).

// The quantum of M2-DESIGN §2.5: a burst is rate >> 10 bytes (about 0.98 ms
// of data), with no RTT term at min_rtt 20 ms and above (20000 >> 9 = 39 and
// 100000 >> 9 = 195, both >= 32), at least min_tso_segs (2) packets.
//   100 Mbit/s: 12 500 000 >> 10 = 12 207 bytes, / 1448 = 8 packets, which
//               take 8 * 1448 * 10^9 / 12 500 000 = 926 720 ns (~0.93 ms).
//   10 Mbit/s:  1 250 000 >> 10 = 1220 bytes < 1 packet: the floor of 2,
//               2 * 1448 * 10^9 / 1 250 000 = 2 316 800 ns (~2.3 ms).
TEST(TxPolicy, PacingQuantumAtTenAndHundredMbit) {
  const std::uint32_t gso = tcp_config(ProfileId::linux_compat).gso_max_size;
  for (const Duration min_rtt : {Duration{20ms}, Duration{100ms}}) {
    EXPECT_EQ(utcp::pacing_burst_segments(12'500'000, min_rtt, gso, 1448, 2), 8u)
        << min_rtt.count();
    EXPECT_EQ(utcp::pacing_burst_segments(1'250'000, min_rtt, gso, 1448, 2), 2u)
        << min_rtt.count();
  }
  const Time pn{10'000'000'000};
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn, 8 * 1448, 12'500'000), pn + Duration{926'720});
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn, 2 * 1448, 1'250'000), pn + Duration{2'316'800});
}

// M2-DESIGN §4.1: srtt 20 ms, cwnd 10, mss 1448, slow start:
// pacing_rate = 1448 * 200 * 10 * 10^9 / (100 * 20 * 10^6) = 1 448 000 B/s;
// burst = max(1414 / 1448, 2) = 2 packets (1 448 000 >> 10 = 1414);
// len_ns = 2896 * 10^9 / 1 448 000 = 2 ms; lateness is credited up to half
// of it, 1 ms.
TEST(TxPolicy, PacingExampleOfTheDesign) {
  const utcp::TcpConfig cfg = tcp_config(ProfileId::linux_compat);
  CcConn cc;
  cc.mss = 1448;
  cc.cwnd = 10;
  cc.ssthresh = utcp::cwnd_infinite;
  cc.srtt = 20ms;
  const std::uint64_t rate = utcp::pacing_rate_for(cc, 10, cfg);
  EXPECT_EQ(rate, 1'448'000u);
  EXPECT_EQ(utcp::pacing_burst_segments(rate, 20ms, cfg.gso_max_size, 1448, 2), 2u);
  const Time pn{10'000'000'000};
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn, 2896, rate), pn + 2ms);
  // 0.4 ms late: all of it is credited.
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn + 400us, 2896, rate), pn + 400us + 1600us);
  // Exactly half late, and later: the credit stops at 1 ms.
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn + 1ms, 2896, rate), pn + 1ms + 1ms);
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn + 5ms, 2896, rate), pn + 5ms + 1ms);
  EXPECT_EQ(utcp::pacing_next_after_send(pn, pn + 1s, 2896, rate), pn + 1s + 1ms);
}

// ---- The engine: which transmissions the gate holds (M2-DESIGN §2.5).

namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;
using utcp::RecoveryCtx;
using utcp::Seq32;
using utcp::StackConfig;
using utcp::TlpAction;
using utcp::TraceEvent;
using utcp::TraceKind;
using utcp::TxKind;
using utcp::XmitTimer;
using namespace utcp::test::tcpt;

class TxLog : public utcp::TraceSink {
public:
  void on_event(const TraceEvent& e) override {
    if (e.kind == TraceKind::tx) {
      tx.push_back(e);
    }
  }
  [[nodiscard]] std::vector<TraceEvent> of(TxKind k) const {
    std::vector<TraceEvent> v;
    for (const TraceEvent& e : tx) {
      if (e.tx == k) {
        v.push_back(e);
      }
    }
    return v;
  }
  std::vector<TraceEvent> tx;
};

// The stack sends 1460-byte segments to a scripted peer at a fixed pacing
// rate (bytes/s); recovery is the stub unless the script says otherwise.
struct PacedSender {
  static constexpr std::uint32_t mss = 1460;
  t::ScriptedRecovery script;
  TxLog log;
  std::optional<Scripted> s;
  Seq32 base;

  explicit PacedSender(std::uint64_t rate, std::uint32_t initial_cwnd = 10) {
    StackConfig cfg = config(Side::b);
    cfg.tcp.test_fixed_pacing_rate = rate;
    cfg.tcp.initial_cwnd = initial_cwnd;
    cfg.test_recovery_script = &script;
    cfg.trace_mask = utcp::trace_bit(TraceKind::tx);
    cfg.tcp.snd_buf_init = 1 << 20;
    s.emplace(cfg);
    s->stack().set_trace_sink(&log);
  }
  PacedSender(const PacedSender&) = delete;
  PacedSender& operator=(const PacedSender&) = delete;
  ~PacedSender() { s->stack().set_trace_sink(nullptr); }

  // The peer connects; its ACK of the SYN-ACK comes 10 ms later, so that
  // min_rtt is 10 ms (10000 >> 9 = 19: the burst has no RTT term, as at the
  // RTTs of M2) instead of the 0 of an instant handshake. Then the stack
  // writes `segments` full segments.
  bool open(std::uint32_t segments) {
    const auto l = stack().tcp_listen(utcp::Endpoint{{}, port}, 16, {});
    if (!l) {
      return false;
    }
    s->listener = *l;
    s->nxt = Seq32{10'000};
    t::TcpSpec syn = s->spec(w::tcp_syn);
    syn.ack = Seq32{};
    syn.opt.mss = s->po.mss;
    syn.opt.wscale = s->po.wscale;
    syn.opt.sack_permitted = s->po.sack;
    s->send(syn);
    const auto sa = s->out();
    if (sa.size() != 1 || !is_synack(sa[0].v)) {
      return false;
    }
    s->nxt = s->nxt + 1;
    s->their = sa[0].v.h.seq + 1;
    d().run_for(10ms);
    s->send(s->spec(w::tcp_ack));
    const auto a = stack().tcp_accept(s->listener);
    if (!a || !s->out().empty()) {
      return false;
    }
    s->h = *a;
    base = s->their;
    const t::Bytes data = t::pattern(std::size_t{segments} * mss);
    const auto n = s->stack().tcp_send(s->h, data);
    return n && *n == data.size();
  }
  utcp::Stack& stack() { return s->stack(); }
  Driven& d() { return s->d(); }
  [[nodiscard]] Time now() { return d().now(); }
  [[nodiscard]] Seq32 seg(std::uint32_t k) const { return base + k * mss; }
  void ack(std::uint32_t cum) {
    t::TcpSpec sp = s->spec(w::tcp_ack);
    sp.ack = seg(cum);
    s->send(sp);
  }
  // Sequence numbers of the data segments sent since the last call.
  std::vector<Seq32> sent() {
    std::vector<Seq32> v;
    for (const Parsed& p : s->out()) {
      if (is_data(p.v)) {
        v.push_back(p.v.h.seq);
      }
    }
    return v;
  }
  std::vector<Seq32> segs(std::initializer_list<std::uint32_t> ks) const {
    std::vector<Seq32> v;
    for (const std::uint32_t k : ks) {
      v.push_back(seg(k));
    }
    return v;
  }
  void run_to(Time when) { d().run_for(when - now()); }
};

// At two segments per burst, the burst ending at segment ten charges 2920
// bytes. The preceding burst left at the same instant, so it earns no credit.
TEST(TxPolicy, LargeInitialWindowStopsAtTheFirstEdt) {
  PacedSender x(1'000'000, 32);
  ASSERT_TRUE(x.open(40));
  const Time start = x.now();
  EXPECT_EQ(x.sent().size(), 10u);
  x.run_to(start + 2920us - 1ns);
  EXPECT_TRUE(x.sent().empty());
  x.run_to(start + 2920us);
  EXPECT_EQ(x.sent(), x.segs({10, 11}));
}

// Linux tcp_xmit_retransmit_queue checks tcp_pacing_check before each skb
// and every transmission moves tcp_wstamp_ns. At 1 MB/s a burst is 2
// packets (1 000 000 >> 10 = 976 bytes < 1460: the floor), 2920 bytes =
// 2.92 ms. Four segments marked lost while the gate is closed wait for it;
// the lost loop sends one burst per opening and stops at the closed gate;
// new data waits behind the retransmissions' 5.84 ms.
TEST(TxPolicy, LostLoopStopsAtAClosedGateAndRetransmissionsMoveIt) {
  PacedSender x(1'000'000);
  x.script.exempt = [](const RecoveryCtx&, const utcp::TxSeg&) -> std::optional<bool> {
    return false;
  };
  std::optional<Time> reo;
  x.script.timer = [&](const RecoveryCtx&) -> std::optional<std::pair<XmitTimer, Time>> {
    if (reo) {
      return std::pair{XmitTimer::reo, *reo};
    }
    return std::nullopt;
  };
  x.script.timer_fired = [&](RecoveryCtx& c, XmitTimer k) {
    if (k != XmitTimer::reo) {
      return false;
    }
    reo.reset();
    for (std::uint64_t i = 5; i < 9; ++i) {
      c.q.mark_lost(i * PacedSender::mss);
    }
    return true;
  };
  ASSERT_TRUE(x.open(40));
  EXPECT_EQ(x.sent().size(), 10u);  // the first 10 data segments are not paced
  x.d().run_for(10ms);
  // cwnd 10 -> 14, 6 in flight. The initial EDT is far behind, so
  // segments 10 and 11 take the full credit; pacing_next = now + 2.92 ms - 1.46 ms (credit).
  // 0.5 ms later recovery marks 5-8 lost (a REO timer armed with the ACK).
  const Time t1 = x.now();
  reo = t1 + 500us;
  x.ack(4);
  EXPECT_EQ(x.sent(), x.segs({10, 11}));
  EXPECT_EQ(x.stack().next_deadline(), t1 + 500us);
  // The gate is closed at the REO expiry: nothing.
  x.run_to(t1 + 500us);
  EXPECT_TRUE(x.sent().empty());
  EXPECT_EQ(x.stack().next_deadline(), t1 + 1460us);
  // Each opening sends one burst of two retransmissions; each moves
  // pacing_next by 2.92 ms (on time: no credit).
  x.run_to(t1 + 1460us);
  EXPECT_EQ(x.sent(), x.segs({5, 6}));
  EXPECT_EQ(x.stack().next_deadline(), t1 + 4380us);
  x.run_to(t1 + 4380us - Duration{1});
  EXPECT_TRUE(x.sent().empty());
  x.run_to(t1 + 4380us);
  EXPECT_EQ(x.sent(), x.segs({7, 8}));
  EXPECT_EQ(x.stack().next_deadline(), t1 + 7300us);
  x.run_to(t1 + 7300us);
  EXPECT_EQ(x.sent(), x.segs({12, 13}));  // new data after them
  const auto rx = x.log.of(TxKind::rexmit);
  ASSERT_EQ(rx.size(), 4u);
  for (std::size_t i = 0; i < rx.size(); ++i) {
    EXPECT_EQ(rx[i].gate_rate, 1'000'000u);
    EXPECT_EQ(rx[i].burst_start, i % 2 == 0);
  }
  EXPECT_EQ(rx[0].t, t1 + 1460us);
  EXPECT_EQ(rx[2].t, t1 + 4380us);
  x.stack().debug_check();
}

// At 25 kB/s each two-segment burst advances EDT by 116.8 ms.
// The first ACK opens cwnd before startup EDT. At that EDT a new burst
// leaves, then RTO resends the head immediately while the gate is closed.
TEST(TxPolicy, RtoHeadIsNotGatedButMovesPacingNext) {
  PacedSender x(25'000);
  ASSERT_TRUE(x.open(40));
  EXPECT_EQ(x.sent().size(), 10u);
  const Time t0 = x.now();
  x.d().run_for(10ms);
  const Time t1 = x.now();
  x.ack(4);
  const utcp::Duration rto = x.stack().tcp_info(x.s->h)->rto;
  ASSERT_LT(t1 + rto, t0 + 233600us);
  ASSERT_GT(t1 + rto, t0 + 116800us);
  EXPECT_TRUE(x.sent().empty());
  x.run_to(t0 + 116800us);
  EXPECT_EQ(x.sent(), x.segs({10, 11}));
  x.run_to(t1 + rto);
  EXPECT_EQ(x.sent(), x.segs({4}));
  const auto head = x.log.of(TxKind::rto_rexmit);
  ASSERT_EQ(head.size(), 1u);
  EXPECT_EQ(head[0].t, t1 + rto);  // pacing_next (t0 + 233.6 ms) is ahead
  EXPECT_EQ(head[0].gate_rate, 0u);
  EXPECT_FALSE(head[0].burst_start);
  x.ack(5);  // cwnd 2; segment 5 (marked lost by the RTO) waits
  EXPECT_TRUE(x.sent().empty());
  EXPECT_EQ(x.stack().next_deadline(), t0 + 292ms);
  x.run_to(t0 + 292ms);
  const auto s = x.sent();
  ASSERT_FALSE(s.empty());
  EXPECT_EQ(s[0], x.seg(5));
  x.stack().debug_check();
}

// Linux tcp_send_loss_probe: a new-data probe goes through tcp_write_xmit
// and its tcp_pacing_check; a probe that resends the last segment uses
// __tcp_retransmit_skb without the check. At 100 kB/s one segment is
// 14.6 ms. Ten segments go out unpaced at t0, two wait for cwnd; recovery
// arms three PTOs in turn:
//  t0 + 40 ms: new data: the gate is open (the startup EDT has elapsed): segment
//              10 as tlp, pacing_next = t0 + 20 + 14.6 - 7.3 (credit).
//  t0 + 41 ms: new data: gated; nothing sent, the pace timer at t0 + 47.3.
//  t0 + 42 ms: the last segment: sent at once (segment 10 again), and
//              pacing_next moves to t0 + 47.3 + 14.6 = t0 + 61.9 ms.
TEST(TxPolicy, LossProbeRetransmissionIsNotGatedNewDataProbeIs) {
  PacedSender x(100'000);
  // The handshake takes 10 ms (open()); the data leaves at t0.
  const Time t0 = x.now() + 10ms;
  std::vector<std::pair<Time, TlpAction>> plan{{t0 + 40ms, TlpAction::new_data},
                                               {t0 + 41ms, TlpAction::new_data},
                                               {t0 + 42ms, TlpAction::retransmit_last}};
  x.script.timer = [&](const RecoveryCtx&) -> std::optional<std::pair<XmitTimer, Time>> {
    if (!plan.empty()) {
      return std::pair{XmitTimer::pto, plan.front().first};
    }
    return std::nullopt;
  };
  x.script.pto = [&](RecoveryCtx&) -> std::optional<TlpAction> {
    const TlpAction a = plan.front().second;
    plan.erase(plan.begin());
    return a;
  };
  ASSERT_TRUE(x.open(12));
  ASSERT_EQ(x.now(), t0);
  EXPECT_EQ(x.sent().size(), 10u);
  x.run_to(t0 + 40ms);
  EXPECT_EQ(x.sent(), x.segs({10}));
  x.run_to(t0 + 41ms);
  EXPECT_TRUE(x.sent().empty());
  EXPECT_EQ(x.stack().next_deadline(), t0 + 42ms);  // the third PTO, then the pace timer
  x.run_to(t0 + 42ms);
  EXPECT_EQ(x.sent(), x.segs({10}));
  EXPECT_EQ(x.stack().next_deadline(), t0 + 47300us);  // the pace timer of the second PTO
  const auto tlp = x.log.of(TxKind::tlp);
  ASSERT_EQ(tlp.size(), 2u);
  EXPECT_EQ(tlp[0].t, t0 + 40ms);
  EXPECT_EQ(tlp[0].gate_rate, 100'000u);  // through the gate
  EXPECT_TRUE(tlp[0].burst_start);
  EXPECT_EQ(tlp[1].t, t0 + 42ms);  // pacing_next was 5.3 ms ahead
  EXPECT_EQ(tlp[1].gate_rate, 0u);
  EXPECT_FALSE(tlp[1].burst_start);
  EXPECT_EQ(x.script.calls_of("on_tlp_sent"),
            (std::vector<std::string>{"on_tlp_sent 1 1", "on_tlp_sent 1 0", "on_tlp_sent 2 1"}));
  // The ACK of everything opens cwnd; segment 11 waits for t0 + 61.9 ms.
  x.ack(11);
  EXPECT_TRUE(x.sent().empty());
  x.run_to(t0 + 61900us - Duration{1});
  EXPECT_TRUE(x.sent().empty());
  x.run_to(t0 + 61900us);
  EXPECT_EQ(x.sent(), x.segs({11}));
  x.stack().debug_check();
}

}  // namespace
