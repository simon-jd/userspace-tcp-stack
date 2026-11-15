// m1-tcp-core acceptance test 4: timers (DESIGN §4.8, §4.9, §4.10, §6):
// delayed ACKs, Nagle, RTO backoff and Karn, the SYN schedules and the retry
// limits.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/tcp/recovery.hpp"
#include "support/recovery_script.hpp"
#include "tcp_test_util.hpp"
#include "utcp/retry_model.hpp"
#include "utcp/trace.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::Endpoint;
using utcp::Error;
using utcp::Handle;
using utcp::ProfileId;
using utcp::Seq32;
using utcp::StackConfig;
using utcp::TcpState;
using utcp::Time;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;
using namespace utcp::test::tcpt;

std::string name(ProfileId p) { return p == ProfileId::rfc ? "rfc" : "linux_compat"; }

// Times of the log entries from `from` matching `pred`, relative to `t0`.
template <class Pred>
std::vector<Duration> times(const t::TcpHarness& h, Side from, Time t0, Pred pred) {
  std::vector<Duration> out;
  for (const t::Sent* s : find(h, from, pred)) {
    out.push_back(s->t - t0);
  }
  return out;
}

// §3.9 delack rows: rfc delays every ACK of in-order data below two full
// segments by a fixed 200 ms; linux_compat ACKs the first 16 data segments at
// once (quick-ack, min(16, rcv_wnd / (2 * rcv_mss))) and then waits ato
// (40 ms: TCP_ATO_MIN, the cap while srtt is below it, even as ato itself
// grows at each delayed-ACK expiry). Two full segments are ACKed at once in
// both; linux_compat also ACKs the first at once (rcv_ssthresh grew, Linux
// tcp_grow_window sets icsk_ack.quick).
TEST(TcpTimer, DelayedAckPerProfile) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    SCOPED_TRACE(name(profile));
    t::TcpHarness h(config(Side::a, profile), config(Side::b, profile));
    h.set_delay(Side::a, 5ms);
    h.set_delay(Side::b, 5ms);
    const auto p = open(h);
    ASSERT_TRUE(p);
    const Duration gap = profile == ProfileId::rfc ? 1s : 100ms;
    std::vector<Duration> delays;
    for (int i = 0; i < 24; ++i) {
      h.clear_log();
      const Time t0 = h.now();
      ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(100, static_cast<std::uint8_t>(i))));
      h.run_for(gap);
      const auto acks = times(h, Side::b, t0, is_pure_ack);
      ASSERT_EQ(acks.size(), 1u);
      delays.push_back(acks[0] - 5ms);  // from the data's arrival
    }
    for (std::size_t i = 0; i < delays.size(); ++i) {
      SCOPED_TRACE(i);
      if (profile == ProfileId::rfc) {
        EXPECT_EQ(delays[i], 200ms);
      } else {
        EXPECT_EQ(delays[i], i < 16 ? Duration::zero() : Duration{40ms});
      }
    }
    const Duration ato = h.b().tcp_info(p->server)->ato;
    if (profile == ProfileId::rfc) {
      EXPECT_EQ(ato, 200ms);
    } else {
      // Linux doubles ato at each delayed-ACK expiry (tcp_delack_timer_handler)
      // up to the RTO; here up to delack_max (§4.10 deviation).
      EXPECT_GT(ato, 40ms);
      EXPECT_LE(ato, 200ms);
    }
    // Two full segments: the ACK at the second's arrival.
    h.clear_log();
    const Time t0 = h.now();
    const std::uint32_t mss = h.a().tcp_info(p->client)->snd_mss;
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(2 * std::size_t{mss}, 9)));
    h.run_for(1s);
    const auto acks = times(h, Side::b, t0, is_pure_ack);
    ASSERT_EQ(acks.size(), profile == ProfileId::rfc ? 1u : 2u);
    for (const Duration d : acks) {
      EXPECT_EQ(d, 5ms);
    }
    EXPECT_GT(h.b().stats().TcpExtDelayedACKs, 0u);
  }
}

// RFC 9293 §3.7.4 (Nagle) per §3.9: rfc896 holds a small segment while any
// data is unacknowledged, minshall only while a small segment is; nodelay
// sends at once.
TEST(TcpTimer, NagleOnAndOff) {
  struct Case {
    ProfileId profile;
    bool nodelay;
    bool full_first;  // a full segment is in flight when the small one is written
    bool held;
  };
  const Case cases[] = {{ProfileId::linux_compat, false, false, true},
                        {ProfileId::linux_compat, true, false, false},
                        {ProfileId::linux_compat, false, true, false},
                        {ProfileId::rfc, false, false, true},
                        {ProfileId::rfc, true, false, false},
                        {ProfileId::rfc, false, true, true},
                        {ProfileId::rfc, true, true, false}};
  for (const Case& c : cases) {
    SCOPED_TRACE(name(c.profile) + (c.nodelay ? " nodelay" : " nagle") +
                 (c.full_first ? " full first" : " small first"));
    t::TcpHarness h(config(Side::a, c.profile), config(Side::b, c.profile));
    h.set_delay(Side::a, 10ms);
    h.set_delay(Side::b, 10ms);
    utcp::TcpSocketOptions o;
    o.nodelay = c.nodelay;
    const auto p = open(h, 100ms, o);
    ASSERT_TRUE(p);
    const std::uint32_t mss = h.a().tcp_info(p->client)->snd_mss;
    h.clear_log();
    const Time t0 = h.now();
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(c.full_first ? mss : 100, 1)));
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(100, 2)));
    h.run_for(1s);
    const auto data = times(h, Side::a, t0, is_data);
    ASSERT_EQ(data.size(), 2u);
    EXPECT_EQ(data[0], Duration::zero());
    if (c.held) {
      // Released by the first segment's ACK (b ACKs a lone small segment
      // after its delayed-ACK time in rfc, at once in quick-ack mode).
      EXPECT_GT(data[1], 20ms - 1ns);
    } else {
      EXPECT_EQ(data[1], Duration::zero());
    }
    EXPECT_EQ(drain(h.b(), p->server).size(), (c.full_first ? mss : 100u) + 100u);
  }
}

// RFC 6298 §5.5-5.7 and Karn (§3): the RTO doubles per expiry; the ACK of a
// retransmitted segment gives no sample (timestamps off), so SRTT and the
// backed-off RTO stay until a new segment is timed.
TEST(TcpTimer, RtoBackoffAndKarn) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    SCOPED_TRACE(name(profile));
    StackConfig ca = config(Side::a, profile), cb = config(Side::b, profile);
    ca.tcp.timestamps = cb.tcp.timestamps = false;
    t::TcpHarness h(ca, cb);
    h.set_delay(Side::a, 10ms);
    h.set_delay(Side::b, 10ms);
    const auto p = open(h);
    ASSERT_TRUE(p);
    const Duration rto0 = h.a().tcp_info(p->client)->rto;
    EXPECT_EQ(rto0, profile == ProfileId::rfc ? Duration{1s} : Duration{220ms});
    int drops = 3;
    h.set_hook([&](Side from, t::Bytes& d) {
      const auto q = parse(d);
      if (from == Side::a && q && is_data(q->v) && drops > 0) {
        --drops;
        return t::Verdict::drop;
      }
      return t::Verdict::deliver;
    });
    h.clear_log();
    const Time t0 = h.now();
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(1000)));
    h.run_for(20s);
    const auto tx = times(h, Side::a, t0, is_data);
    ASSERT_EQ(tx.size(), 4u);
    EXPECT_EQ(tx[0], Duration::zero());
    EXPECT_EQ(tx[1], rto0);
    EXPECT_EQ(tx[2], 3 * rto0);
    EXPECT_EQ(tx[3], 7 * rto0);
    auto i = h.a().tcp_info(p->client);
    EXPECT_EQ(i->unacked, 0u);
    EXPECT_EQ(i->srtt, 20ms);             // Karn: no sample from the retransmission
    EXPECT_EQ(i->rto, 8 * rto0);          // backoff kept (RFC 6298 §5.7)
    EXPECT_EQ(i->total_retrans, 3u);
    EXPECT_EQ(h.a().stats().TcpExtTCPTimeouts, 3u);
    EXPECT_EQ(drain(h.b(), p->server), t::pattern(1000));
    // New data, timed at 100 ms (two full segments, ACKed at once): SRTT
    // moves, the backoff is gone.
    h.set_delay(Side::a, 50ms);
    h.set_delay(Side::b, 50ms);
    const std::size_t two = 2 * std::size_t{h.a().tcp_info(p->client)->snd_mss};
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(two, 1)));
    h.run_for(1s);
    i = h.a().tcp_info(p->client);
    EXPECT_EQ(i->unacked, 0u);
    if (profile == ProfileId::rfc) {
      EXPECT_EQ(i->srtt, 30ms);  // one ACK for both: 20 + (100 - 20) / 8

      EXPECT_EQ(i->rto, 1s);
    } else {
      // Quick-ack mode: one ACK per segment, two samples: 20 -> 30 -> 38.75.
      EXPECT_EQ(i->srtt, 38750us);
      EXPECT_LT(i->rto, rto0 * 2);
    }
  }
}

// §4.4 step 6: SND.NXT never moves back, so the ACK of the original flight,
// delayed past an RTO, is in range and acknowledges everything.
TEST(TcpTimer, AckOfOriginalFlightAcceptedAfterRto) {
  t::TcpHarness h;
  h.set_delay(Side::a, 10ms);
  h.set_delay(Side::b, 10ms);
  const auto p = open(h);
  ASSERT_TRUE(p);
  bool holding = true;
  h.set_hook([&](Side from, t::Bytes& d) {
    const auto q = parse(d);
    if (from == Side::b && q && is_pure_ack(q->v) && holding) {
      return t::Verdict::hold;
    }
    return t::Verdict::deliver;
  });
  const t::Bytes data = t::pattern(10'000, 3);
  ASSERT_TRUE(h.a().tcp_send(p->client, data));
  const std::uint32_t segs = h.a().tcp_info(p->client)->unacked;
  EXPECT_GT(segs, 1u);
  h.run_for(400ms);  // one RTO (220 ms): the head is resent
  const auto rexmit = find(h, Side::a, is_data);
  ASSERT_EQ(rexmit.size(), segs + 1);
  EXPECT_EQ(parse(rexmit.back()->bytes)->v.h.seq, parse(rexmit.front()->bytes)->v.h.seq);
  EXPECT_EQ(h.a().tcp_info(p->client)->ca_state, utcp::CaState::loss);
  ASSERT_GT(h.held_count(), 0u);
  holding = false;
  h.release_all_held();
  h.run_for(2s);
  const auto i = h.a().tcp_info(p->client);
  EXPECT_EQ(i->unacked, 0u);
  EXPECT_EQ(i->ca_state, utcp::CaState::open);
  EXPECT_EQ(h.a().stats().TcpExtTCPChallengeACK, 0u);
  EXPECT_EQ(drain(h.b(), p->server), data);
  h.a().debug_check();
  h.b().debug_check();
}

// RFC 5681 §3.1 / Linux tcp_enter_loss: a second RTO of the same loss
// episode keeps ssthresh.
TEST(TcpTimer, TwoRtosInARowKeepSsthresh) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    SCOPED_TRACE(name(profile));
    t::TcpHarness h(config(Side::a, profile), config(Side::b, profile));
    h.set_delay(Side::a, 10ms);
    h.set_delay(Side::b, 10ms);
    const auto p = open(h);
    ASSERT_TRUE(p);
    h.set_hook([&](Side from, t::Bytes& d) {
      const auto q = parse(d);
      return from == Side::a && q && is_data(q->v) ? t::Verdict::drop : t::Verdict::deliver;
    });
    const Duration rto = h.a().tcp_info(p->client)->rto;
    const std::uint32_t cwnd = h.a().tcp_info(p->client)->cwnd;
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(40'000)));
    EXPECT_EQ(h.a().tcp_info(p->client)->unacked, cwnd);
    h.run_for(rto + rto / 2);
    auto i = h.a().tcp_info(p->client);
    EXPECT_EQ(i->ca_state, utcp::CaState::loss);
    EXPECT_EQ(i->ssthresh, std::max(cwnd / 2, 2u));
    EXPECT_EQ(i->cwnd, 1u);
    h.run_for(2 * rto);  // the second expiry
    i = h.a().tcp_info(p->client);
    EXPECT_EQ(h.a().stats().TcpExtTCPTimeouts, 2u);
    EXPECT_EQ(i->ssthresh, std::max(cwnd / 2, 2u));
    EXPECT_EQ(i->cwnd, 1u);
  }
}

// M2-DESIGN §2.5, Linux tcp_event_data_sent: lsndtime is stamped by every
// data transmission, retransmissions included, so tcp_info last_data_sent
// counts from the RTO retransmission, not from the original send.
TEST(TcpTimer, RtoRetransmissionStampsLastDataSent) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    SCOPED_TRACE(name(profile));
    t::TcpHarness h(config(Side::a, profile), config(Side::b, profile));
    h.set_delay(Side::a, 10ms);
    h.set_delay(Side::b, 10ms);
    const auto p = open(h);
    ASSERT_TRUE(p);
    h.set_hook([&](Side from, t::Bytes& d) {
      const auto q = parse(d);
      return from == Side::a && q && is_data(q->v) ? t::Verdict::drop : t::Verdict::deliver;
    });
    const Duration rto = h.a().tcp_info(p->client)->rto;
    h.clear_log();
    const Time t0 = h.now();
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(1000)));
    h.run_for(rto + rto / 2);
    const auto tx = times(h, Side::a, t0, is_data);
    ASSERT_EQ(tx.size(), 2u);  // the original and the RTO retransmission
    EXPECT_EQ(tx[1], rto);
    EXPECT_EQ(h.a().tcp_info(p->client)->last_data_sent, rto / 2);
  }
}

// §4.8 SYN schedule: linux_compat (syn_retries 6, syn_linear_timeouts 4)
// retransmits at 1, 2, 3, 4, 5, 7, 11, 19, 35, 67 s and fails at 131 s; rfc
// (7, 0, rto_max 60 s) at 1, 3, 7, 15, 31, 63, 123 s and fails at 183 s.
TEST(TcpTimer, SynRetrySchedules) {
  struct Case {
    ProfileId profile;
    std::vector<int> at;
    int fail;
  };
  const Case cases[] = {{ProfileId::linux_compat, {0, 1, 2, 3, 4, 5, 7, 11, 19, 35, 67}, 131},
                        {ProfileId::rfc, {0, 1, 3, 7, 15, 31, 63, 123}, 183}};
  for (const Case& c : cases) {
    SCOPED_TRACE(name(c.profile));
    t::TcpHarness h(config(Side::a, c.profile), config(Side::b, c.profile));
    h.set_hook([](Side from, t::Bytes&) {
      return from == Side::a ? t::Verdict::drop : t::Verdict::deliver;
    });
    ASSERT_TRUE(h.b().tcp_listen(Endpoint{{}, port}, 16, {}));
    const Time t0 = h.now();
    const auto cl = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    ASSERT_TRUE(cl);
    h.run_until(t0 + std::chrono::seconds{c.fail} - 1ms);
    EXPECT_EQ(state(h.a(), *cl), TcpState::syn_sent);
    const auto syns = times(h, Side::a, t0, is_syn);
    ASSERT_EQ(syns.size(), c.at.size());
    for (std::size_t i = 0; i < syns.size(); ++i) {
      EXPECT_EQ(syns[i], std::chrono::seconds{c.at[i]}) << i;
    }
    h.run_until(t0 + std::chrono::seconds{c.fail});
    EXPECT_EQ(state(h.a(), *cl), TcpState::closed);
    EXPECT_NE(events_of(h.a(), *cl) & utcp::ev_error, 0);
    EXPECT_EQ(h.a().take_error(*cl), Error::timed_out);
    EXPECT_EQ(times(h, Side::a, t0, is_syn).size(), c.at.size());
    EXPECT_TRUE(find(h, Side::a, is_rst).empty());
    EXPECT_EQ(h.a().stats().TcpExtTCPAbortOnTimeout, 1u);
    EXPECT_EQ(h.a().stats().TcpAttemptFails, 1u);
  }
}

// As built, Linux tcp_rcv_synsent_state_process (§4.4 SYN-SENT step 1): an
// unacceptable ACK in SYN-SENT draws <SEQ=SEG.ACK><CTL=RST> (none for an
// RST) and, before any SYN retransmission, re-arms the SYN timer at 2 ms
// (TCP_TIMEOUT_MIN), so a reused tuple whose stale peer connection our RST
// just freed connects at once. The early SYN counts as a retransmission; a
// later unacceptable ACK leaves the backed-off timer alone.
TEST(TcpTimer, UnacceptableAckInSynSentResendsTheSynSoon) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    for (const bool rst : {false, true}) {
      SCOPED_TRACE(name(profile) + (rst ? " rst" : " ack"));
      Driven d(profile);
      const auto h = d.stack().tcp_connect(Endpoint{Driven::peer(80)}, {});
      ASSERT_TRUE(h);
      const auto first = d.out();
      ASSERT_EQ(first.size(), 1u);
      const auto syn = parse(first[0]);
      ASSERT_TRUE(syn && is_syn(syn->v));
      d.run_for(10ms);
      // The stale peer's challenge ACK for an old connection on the tuple.
      t::TcpSpec bad(Driven::peer(80), Endpoint{d.stack().config().local_addr, syn->v.h.sport});
      bad.seq = Seq32{5000};
      bad.ack = syn->v.h.seq + 100'000;
      bad.flags = rst ? w::tcp_rst | w::tcp_ack : w::tcp_ack;
      d.send(bad);
      const auto reply = d.out();
      if (rst) {
        EXPECT_TRUE(reply.empty());
      } else {
        ASSERT_EQ(reply.size(), 1u);
        const auto r = parse(reply[0]);
        ASSERT_TRUE(r && is_rst(r->v));
        EXPECT_EQ(r->v.h.seq, bad.ack);
      }
      EXPECT_EQ(state(d.stack(), *h), TcpState::syn_sent);
      EXPECT_EQ(d.stack().next_deadline() - d.now(), 2ms);
      d.run_for(2ms);
      const auto again = d.out();
      ASSERT_EQ(again.size(), 1u);
      const auto syn2 = parse(again[0]);
      ASSERT_TRUE(syn2 && is_syn(syn2->v));
      EXPECT_EQ(syn2->v.h.seq, syn->v.h.seq);
      EXPECT_EQ(d.stack().stats().TcpExtTCPSynRetrans, 1u);
      // After a retransmission the timer keeps its backed-off value.
      const Duration left = d.stack().next_deadline() - d.now();
      EXPECT_GE(left, 1s);
      d.send(bad);
      (void)d.out();
      EXPECT_EQ(d.stack().next_deadline() - d.now(), left);
      // The peer, its stale connection gone, completes the handshake.
      t::TcpSpec sa = bad;
      sa.flags = w::tcp_syn | w::tcp_ack;
      sa.ack = syn->v.h.seq + 1;
      sa.opt.mss = 1460;
      d.send(sa);
      EXPECT_EQ(state(d.stack(), *h), TcpState::established);
      d.stack().debug_check();
    }
  }
}

// §4.8: a passive child whose SYN-ACK is never acknowledged resends it at 1,
// 3, 7, 15 and 31 s (synack_retries 5, doubling from rto_initial) and is
// freed silently at 63 s (Linux reqsk_timer_handler, tcp_synack_retries).
TEST(TcpTimer, SynAckRetriesFreeTheChild) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Driven d(profile);
    ASSERT_TRUE(d.stack().tcp_listen(Endpoint{{}, port}, 4, {}));
    t::TcpSpec syn(Driven::peer(40000), d.local());
    syn.seq = Seq32{1000};
    syn.flags = w::tcp_syn;
    syn.opt.mss = 1460;
    d.send(syn);
    const Time t0 = d.now();
    std::vector<Duration> synacks;
    for (int ms = 0; ms <= 70'000; ms += 500) {
      for (const t::Bytes& b : d.out()) {
        const auto q = parse(b);
        ASSERT_TRUE(q && is_synack(q->v));
        synacks.push_back(d.now() - t0);
      }
      if (ms == 62'500) {
        EXPECT_EQ(d.stack().debug_usage().tcp_slots, 2u);
      }
      d.run_for(500ms);
    }
    const std::vector<Duration> want{0s, 1s, 3s, 7s, 15s, 31s};
    EXPECT_EQ(synacks, want);
    EXPECT_EQ(d.stack().debug_usage().tcp_slots, 1u);  // the listener
    EXPECT_EQ(d.stack().stats().TcpExtTCPSynRetrans, 5u);
    EXPECT_EQ(d.stack().stats().TcpOutRsts, 0u);
    d.stack().debug_check();
  }
}

// §4.8 data retry limit (Linux retransmits_timed_out): the connection sends
// RST and fails with timed_out at the first RTO expiry with now -
// retrans_stamp >= retry_abort_time(data_retries, rto_min, rto_max), measured
// from the first retransmission. rfc at a 1 s RTO: 722 s; linux_compat at a
// 200 ms RTO: 1044.4 s.
TEST(TcpTimer, DataRetryExhaustionSendsRst) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    SCOPED_TRACE(name(profile));
    const StackConfig ca = config(Side::a, profile);
    t::TcpHarness h(ca, config(Side::b, profile));
    const auto p = open(h);
    ASSERT_TRUE(p);
    h.set_hook([](Side from, t::Bytes&) {
      return from == Side::a ? t::Verdict::drop : t::Verdict::deliver;
    });
    h.clear_log();
    const Time t0 = h.now();
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(1000)));
    h.run_for(1200s);
    const auto tx = times(h, Side::a, t0, is_data);
    const auto rst = times(h, Side::a, t0, is_rst);
    ASSERT_GE(tx.size(), 3u);
    ASSERT_EQ(rst.size(), 1u);
    const Duration bound = utcp::retry_abort_time(ca.tcp.data_retries, ca.tcp.rto_min,
                                                  ca.tcp.rto_max);
    const Duration first = tx[1];  // the first retransmission
    const Duration abort = rst[0] - first;
    EXPECT_GE(abort, bound);
    EXPECT_LT(tx.back() - first, bound);
    // The RST is the expiry after the last retransmission: the timeouts so
    // far doubled up to rto_max.
    const Duration last_gap = tx.back() - tx[tx.size() - 2];
    EXPECT_EQ(rst[0] - tx.back(), std::min(2 * last_gap, ca.tcp.rto_max));
    if (profile == ProfileId::rfc) {
      EXPECT_EQ(abort, 722s);
      EXPECT_EQ(tx.size(), 1u + 16u);
    } else {
      EXPECT_GT(abort, 1044s);
      EXPECT_LT(abort, 1045s);
    }
    EXPECT_EQ(state(h.a(), p->client), TcpState::closed);
    EXPECT_EQ(h.a().take_error(p->client), Error::timed_out);
    EXPECT_EQ(h.a().stats().TcpExtTCPAbortOnTimeout, 1u);
  }
}

// Linux tcp_ack_probe / tcp_send_probe0: the backoff that zero-window
// probing built up ends when the window opens with nothing in flight, so the
// first segment sent then is protected by the base RTO, not by the
// backed-off one (up to rto_max).
TEST(TcpTimer, WindowOpeningEndsProbeBackoff) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept(Seq32{10'000}, 0));  // the completing ACK closes the window
    const Duration rto0 = c.stack().tcp_info(c.h)->rto;
    ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(1000)));
    EXPECT_TRUE(c.out().empty());
    // 70 s of zero-window probes, each answered with window 0.
    int probes = 0;
    for (int ms = 0; ms < 70'000; ms += 10) {
      c.d().run_for(10ms);
      for (const Parsed& p : c.out()) {
        ASSERT_TRUE(is_pure_ack(p.v));
        EXPECT_EQ(p.v.h.seq, c.their - 1);  // <SEQ=SND.UNA-1>
        ++probes;
        c.send(c.spec(w::tcp_ack));
      }
    }
    EXPECT_GE(probes, 6);
    EXPECT_GE(c.stack().tcp_info(c.h)->rto, 32 * rto0);
    // The window opens: the data goes out and is lost.
    c.window = 65535;
    c.send(c.spec(w::tcp_ack));
    const auto sent = c.out();
    ASSERT_EQ(sent.size(), 1u);
    ASSERT_TRUE(is_data(sent[0].v));
    EXPECT_EQ(c.stack().tcp_info(c.h)->rto, rto0);
    const Time t1 = c.d().now();
    std::optional<Duration> gap;
    for (int ms = 0; ms < 5000 && !gap; ++ms) {
      c.d().run_for(1ms);
      for (const Parsed& p : c.out()) {
        if (is_data(p.v)) {
          gap = c.d().now() - t1;
        }
      }
    }
    ASSERT_TRUE(gap.has_value());
    EXPECT_EQ(*gap, rto0);
    c.stack().debug_check();
  }
}

// Linux tcp_write_timeout with SOCK_DEAD: an orphan retries
// tcp_orphan_retries times; the server's sysctl is 0, which means 8 while
// the backed-off RTO is below rto_max (§3.9 orphan_retries). So under
// linux_compat an orphan to a dead peer gives up at the first RTO expiry past
// retry_abort_time(8, ...), about 204 s here, not after 1044 s; under rfc it
// keeps data_retries (722 s).
TEST(TcpTimer, OrphanRetryLimit) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    const StackConfig ca = config(Side::a, profile);
    t::TcpHarness h(ca, config(Side::b, profile));
    const auto p = open(h);
    ASSERT_TRUE(p);
    h.set_hook([](Side from, t::Bytes&) {
      return from == Side::a ? t::Verdict::drop : t::Verdict::deliver;
    });
    h.clear_log();
    const Time t0 = h.now();
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(1000)));
    ASSERT_TRUE(h.a().tcp_close(p->client));
    h.run_for(1200s);
    const auto tx = times(h, Side::a, t0, is_data);
    const auto rst = times(h, Side::a, t0, is_rst);
    ASSERT_GE(tx.size(), 3u);
    ASSERT_EQ(rst.size(), 1u);
    const std::uint8_t retries = profile == ProfileId::rfc ? ca.tcp.data_retries : 8;
    const Duration bound = utcp::retry_abort_time(retries, ca.tcp.rto_min, ca.tcp.rto_max);
    const Duration first = tx[1];
    const Duration abort = rst[0] - first;
    EXPECT_GE(abort, bound);
    EXPECT_LT(tx.back() - first, bound);
    if (profile == ProfileId::rfc) {
      EXPECT_EQ(abort, 722s);
    } else {
      EXPECT_EQ(abort, 204'400ms);  // expiries 0.4, 1.2, ..., 102.0, 204.4 s
    }
    EXPECT_EQ(h.a().stats().TcpExtTCPAbortOnTimeout, 1u);
    EXPECT_EQ(h.a().debug_usage().tcp_slots, 0u);
    h.a().debug_check();
  }
}

// RFC 1122 §4.2.2.17 (Linux tcp_retransmit_timer, tcp_rtx_probe0_timed_out):
// a peer that shrinks its window to zero under our data and answers every
// retransmission keeps the connection open past the data retry bound; once
// it falls silent the connection aborts at the first RTO expiry more than
// 2 * rto_max after its last ACK.
TEST(TcpTimer, ZeroWindowRetractionKeepsConnection) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept());
    const StackConfig cfg = c.stack().config();
    ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(1000)));
    ASSERT_EQ(c.out().size(), 1u);
    c.window = 0;  // retracted: nothing acknowledged
    c.send(c.spec(w::tcp_ack));
    Time last = c.d().now();
    int answers = 0;
    for (int i = 0; i < 15'000; ++i) {  // 1500 s, past every retry bound
      c.d().run_for(100ms);
      for (const Parsed& p : c.out()) {
        ASSERT_FALSE(is_rst(p.v));
        if (is_data(p.v)) {
          c.send(c.spec(w::tcp_ack));
          last = c.d().now();
          ++answers;
        }
      }
    }
    EXPECT_GE(answers, 10);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    // The peer falls silent.
    std::optional<Time> rst;
    for (int i = 0; i < 6'000 && !rst; ++i) {
      c.d().run_for(100ms);
      for (const Parsed& p : c.out()) {
        if (is_rst(p.v)) {
          rst = c.d().now();
        }
      }
    }
    ASSERT_TRUE(rst.has_value());
    EXPECT_GT(*rst - last, 2 * cfg.tcp.rto_max);
    EXPECT_LE(*rst - last, 3 * cfg.tcp.rto_max + 100ms);
    EXPECT_EQ(c.stack().take_error(c.h), Error::timed_out);
  }
}

// ---- m2-found acceptance test 4: the engine's M2 hooks (M2-DESIGN §1.7,
// §1.8, §2.5), with the stub recovery and through the RecoveryScript test
// seam (StackConfig::test_recovery_script).

using utcp::CaState;
using utcp::RecoveryCtx;
using utcp::TlpAction;
using utcp::TraceEvent;
using utcp::TraceKind;
using utcp::TxKind;
using utcp::XmitTimer;

class TraceLog : public utcp::TraceSink {
public:
  void on_event(const TraceEvent& e) override { events.push_back(e); }
  // The tx events of kind `k`, oldest first.
  [[nodiscard]] std::vector<TraceEvent> tx(TxKind k) const {
    std::vector<TraceEvent> v;
    for (const TraceEvent& e : events) {
      if (e.kind == TraceKind::tx && e.tx == k) {
        v.push_back(e);
      }
    }
    return v;
  }
  std::vector<TraceEvent> events;
};

// The stack sends data to a scripted peer (Scripted) with 1460-byte segments,
// SACK on and no timestamps; tx and timer events are traced.
struct Sender {
  static constexpr std::uint32_t mss = 1460;
  t::ScriptedRecovery script;
  TraceLog log;
  std::optional<Scripted> s;
  Seq32 base;  // the first data byte

  explicit Sender(StackConfig cfg, bool with_script = true) {
    if (with_script) {
      cfg.test_recovery_script = &script;
    }
    cfg.trace_mask = utcp::trace_bit(TraceKind::tx) | utcp::trace_bit(TraceKind::timer);
    cfg.tcp.snd_buf_init = 1 << 20;
    s.emplace(cfg);
    s->stack().set_trace_sink(&log);
  }
  Sender(const Sender&) = delete;
  Sender& operator=(const Sender&) = delete;
  ~Sender() { s->stack().set_trace_sink(nullptr); }

  // Accepts the peer's connection and writes `segments` full segments.
  bool open(std::uint32_t segments) {
    if (!s->accept()) {
      return false;
    }
    base = s->their;
    const t::Bytes data = t::pattern(std::size_t{segments} * mss);
    const auto n = stack().tcp_send(s->h, data);
    return n && *n == data.size();
  }
  utcp::Stack& stack() { return s->stack(); }
  Driven& d() { return s->d(); }
  [[nodiscard]] Seq32 seg(std::uint32_t k) const { return base + k * mss; }
  // A peer ACK of everything below segment `cum`, SACKing the segment index
  // ranges [first, last).
  void ack(std::uint32_t cum,
           std::initializer_list<std::pair<std::uint32_t, std::uint32_t>> sacked = {}) {
    t::TcpSpec sp = s->spec(w::tcp_ack);
    sp.ack = seg(cum);
    for (const auto& [first, last] : sacked) {
      sp.opt.sack[sp.opt.sack_count++] = {seg(first), seg(last)};
    }
    s->send(sp);
  }
  std::vector<Parsed> out() { return s->out(); }
  [[nodiscard]] std::size_t data_count(const std::vector<Parsed>& v) const {
    return static_cast<std::size_t>(
        std::count_if(v.begin(), v.end(), [](const Parsed& p) { return is_data(p.v); }));
  }
};

// §2.5: with a fixed pacing rate the lost segment waits for pacing_next and
// its retransmission moves pacing_next on; the stub recovery keeps M1's
// exemption of the fast retransmission from the cwnd gate (not from the
// pacing gate: Linux checks tcp_pacing_check before any retransmission).
TEST(TcpTimer, PacedFastRetransmitWaitsForTheGateAndAdvancesIt) {
  StackConfig cfg = config(Side::b);
  cfg.tcp.test_fixed_pacing_rate = 1'000'000;  // bytes/s: 1.46 ms per segment
  Sender x(cfg, false);
  ASSERT_TRUE(x.open(100));
  EXPECT_EQ(x.data_count(x.out()), 10u);  // the first 10 segments are not paced
  x.d().run_for(10ms);
  x.ack(6);  // cwnd 16, 4 in flight: paced bursts up to cwnd
  x.d().run_for(40ms);
  EXPECT_EQ(x.data_count(x.out()), 12u);  // segments 10-21
  // Three duplicate ACKs SACK 7, 7-8, 7-9: segment 6 is lost. The first
  // frees room for segment 22, which closes the gate again.
  x.ack(6, {{7, 8}});
  const Time t2 = x.d().now();
  x.ack(6, {{7, 9}});
  x.ack(6, {{7, 10}});
  auto o = x.out();
  ASSERT_EQ(o.size(), 1u);
  EXPECT_EQ(o[0].v.h.seq, x.seg(22));
  ASSERT_EQ(x.stack().tcp_info(x.s->h)->ca_state, CaState::recovery);
  // The fast retransmission waits for pacing_next.
  const Time gate = x.stack().next_deadline();
  EXPECT_GT(gate, t2);
  EXPECT_LT(gate, t2 + 1460us + 1us);
  x.d().run_for(gate - x.d().now());
  o = x.out();
  ASSERT_EQ(o.size(), 1u);
  EXPECT_EQ(o[0].v.h.seq, x.seg(6));
  const auto fr = x.log.tx(TxKind::fast_rexmit);
  ASSERT_EQ(fr.size(), 1u);
  EXPECT_EQ(fr[0].t, gate);
  EXPECT_GT(fr[0].in_flight, fr[0].cwnd);  // exempt from the cwnd gate (M1)
  EXPECT_EQ(fr[0].gate_rate, 1'000'000u);
  EXPECT_TRUE(fr[0].burst_start);
  // Its 1460 bytes moved pacing_next: after a full ACK frees the cwnd, new
  // data waits 1.46 ms more.
  x.ack(23);
  EXPECT_TRUE(x.out().empty());
  EXPECT_EQ(x.stack().next_deadline(), gate + 1460us);
  x.d().run_for(1460us);
  o = x.out();
  ASSERT_FALSE(o.empty());
  EXPECT_EQ(o[0].v.h.seq, x.seg(23));
}

// The scripted recovery answers exempt_from_cwnd false and lets a PRR-like
// cwnd_reduction admit the first retransmission through the cwnd gate (sent
// as rexmit, not fast_rexmit); next_seg_extra names one more segment, sent
// after the new data; on_burst_end learns whether new data went out.
TEST(TcpTimer, ScriptedRecoveryDrivesTheRetransmissionHooks) {
  Sender x(config(Side::b));
  x.script.exempt = [](const RecoveryCtx&, const utcp::TxSeg&) -> std::optional<bool> {
    return false;
  };
  x.script.reduce = [](RecoveryCtx& c, std::uint32_t, std::uint32_t, std::uint32_t) {
    c.cc.cwnd = c.cc.in_flight + 2;
    return true;
  };
  int extras = 0;
  x.script.extra = [&](RecoveryCtx& c) -> std::optional<std::optional<std::uint64_t>> {
    if (c.cc.ca_state != CaState::recovery || extras > 0) {
      return std::optional<std::uint64_t>{};  // handled: nothing
    }
    ++extras;
    return std::optional<std::uint64_t>{std::uint64_t{12} * Sender::mss};
  };
  ASSERT_TRUE(x.open(14));
  EXPECT_EQ(x.data_count(x.out()), 10u);
  EXPECT_FALSE(x.script.calls_of("on_burst_end 1").empty());
  x.d().run_for(10ms);
  x.ack(2);  // cwnd 12: segments 10-13, the last of the data
  EXPECT_EQ(x.data_count(x.out()), 4u);
  x.script.calls.clear();
  x.ack(2, {{3, 4}});
  x.ack(2, {{3, 5}});
  EXPECT_TRUE(x.out().empty());
  x.ack(2, {{3, 6}});  // Recovery: segment 2 is lost
  const auto o = x.out();
  ASSERT_EQ(o.size(), 2u);
  EXPECT_EQ(o[0].v.h.seq, x.seg(2));
  EXPECT_EQ(o[1].v.h.seq, x.seg(12));
  EXPECT_TRUE(x.log.tx(TxKind::fast_rexmit).empty());
  const auto rx = x.log.tx(TxKind::rexmit);
  ASSERT_EQ(rx.size(), 2u);
  EXPECT_LE(rx[0].in_flight, rx[0].cwnd);  // through the cwnd gate
  EXPECT_LE(rx[1].in_flight, rx[1].cwnd);
  EXPECT_EQ(extras, 1);
  EXPECT_EQ(x.script.calls_of("exempt_from_cwnd").size(), 1u);
  EXPECT_EQ(x.script.calls_of("exempt_from_cwnd")[0],
            "exempt_from_cwnd " + std::to_string(2 * Sender::mss));
  EXPECT_FALSE(x.script.calls_of("cwnd_reduction").empty());
  EXPECT_GE(x.script.calls_of("next_seg_extra").size(), 2u);
  EXPECT_TRUE(x.script.calls_of("on_burst_end 1").empty());  // retransmissions only
  EXPECT_FALSE(x.script.calls_of("on_burst_end 0").empty());
  x.stack().debug_check();
}

// A REO expiry (M2-DESIGN §1.6): recovery marks a segment lost, the engine
// retransmits it and the xmit timer goes back to the RTO recovery reports.
TEST(TcpTimer, ScriptedReoExpiryTransmitsAndRearmsTheRto) {
  Sender x(config(Side::b));
  std::optional<Time> reo_at;
  x.script.timer = [&](const RecoveryCtx&) -> std::optional<std::pair<XmitTimer, Time>> {
    if (reo_at) {
      return std::pair{XmitTimer::reo, *reo_at};
    }
    return std::nullopt;
  };
  x.script.timer_fired = [&](RecoveryCtx& c, XmitTimer k) {
    if (k != XmitTimer::reo) {
      return false;
    }
    reo_at.reset();
    c.q.mark_lost(std::uint64_t{3} * Sender::mss);
    return true;
  };
  ASSERT_TRUE(x.open(20));
  EXPECT_EQ(x.data_count(x.out()), 10u);
  x.d().run_for(10ms);
  const Time t1 = x.d().now();
  x.ack(2, {{4, 6}});  // Disorder; cwnd 14 (+4 delivered): segments 10-17
  EXPECT_EQ(x.data_count(x.out()), 8u);
  const Duration rto = x.stack().tcp_info(x.s->h)->rto;
  EXPECT_EQ(x.stack().next_deadline(), t1 + rto);
  reo_at = t1 + 5ms;
  ASSERT_TRUE(x.stack().tcp_send(x.s->h, t::pattern(1)));  // cwnd-limited: only the timers move
  EXPECT_TRUE(x.out().empty());
  EXPECT_EQ(x.stack().next_deadline(), t1 + 5ms);
  x.log.events.clear();
  x.d().run_for(5ms);
  const auto o = x.out();
  ASSERT_EQ(o.size(), 1u);
  EXPECT_EQ(o[0].v.h.seq, x.seg(3));
  // The order of events: reo fired, the rexmit, rto armed.
  std::vector<std::string> seen;
  for (const TraceEvent& e : x.log.events) {
    if (e.kind == TraceKind::timer && e.timer == utcp::TraceTimer::reo &&
        e.timer_op == utcp::TimerOp::fired) {
      seen.emplace_back("reo fired");
    } else if (e.kind == TraceKind::tx && e.tx == TxKind::rexmit) {
      seen.emplace_back("rexmit");
    } else if (e.kind == TraceKind::timer && e.timer == utcp::TraceTimer::rto &&
               e.timer_op == utcp::TimerOp::armed) {
      seen.emplace_back("rto armed");
    }
  }
  EXPECT_EQ(seen, (std::vector<std::string>{"reo fired", "rexmit", "rto armed"}));
  EXPECT_EQ(x.stack().next_deadline(), t1 + rto);
  EXPECT_EQ(x.script.calls_of("on_xmit_timer").size(), 1u);
  x.stack().debug_check();
}

// A PTO expiry (M2-DESIGN §1.7): on_pto's answer is sent as exactly one tlp
// segment, new data past cwnd by one or the last segment again; the RTO is
// then a full RTO from now. A PTO that sends nothing (a probe outstanding)
// leaves the head's remaining time.
TEST(TcpTimer, ScriptedPtoSendsOneProbeAndRearmsTheRto) {
  Sender x(config(Side::b));
  std::optional<Time> pto_at;
  TlpAction answer = TlpAction::none;
  x.script.timer = [&](const RecoveryCtx&) -> std::optional<std::pair<XmitTimer, Time>> {
    if (pto_at) {
      return std::pair{XmitTimer::pto, *pto_at};
    }
    return std::nullopt;
  };
  x.script.pto = [&](RecoveryCtx&) -> std::optional<TlpAction> {
    pto_at.reset();
    return answer;
  };
  ASSERT_TRUE(x.open(30));
  const Time t0 = x.d().now();
  EXPECT_EQ(x.data_count(x.out()), 10u);  // cwnd 10, nothing acknowledged
  const Duration rto = x.stack().tcp_info(x.s->h)->rto;
  ASSERT_GT(rto, 60ms);
  EXPECT_EQ(x.stack().next_deadline(), t0 + rto);
  const auto expire_pto = [&](TlpAction a) {
    answer = a;
    pto_at = x.d().now() + 20ms;
    ASSERT_TRUE(x.stack().tcp_send(x.s->h, t::pattern(1)));  // runs transmit and the timers
    EXPECT_TRUE(x.out().empty());
    EXPECT_EQ(x.stack().next_deadline(), *pto_at);
    x.d().run_for(20ms);
  };

  expire_pto(TlpAction::new_data);
  auto o = x.out();
  ASSERT_EQ(o.size(), 1u);
  EXPECT_EQ(o[0].v.h.seq, x.seg(10));
  EXPECT_EQ(o[0].v.payload.size(), Sender::mss);
  auto tlp = x.log.tx(TxKind::tlp);
  ASSERT_EQ(tlp.size(), 1u);
  EXPECT_EQ(tlp[0].cwnd, 10u);
  EXPECT_EQ(tlp[0].in_flight, 11u);  // cwnd + 1
  EXPECT_EQ(x.stack().next_deadline(), x.d().now() + rto);
  EXPECT_EQ(x.stack().stats().TcpExtTCPLossProbes, 1u);
  EXPECT_EQ(x.script.calls_of("on_tlp_sent"), (std::vector<std::string>{"on_tlp_sent 1 1"}));

  expire_pto(TlpAction::retransmit_last);
  o = x.out();
  ASSERT_EQ(o.size(), 1u);
  EXPECT_EQ(o[0].v.h.seq, x.seg(10));  // the last segment sent
  tlp = x.log.tx(TxKind::tlp);
  ASSERT_EQ(tlp.size(), 2u);
  EXPECT_EQ(tlp[1].in_flight, 12u);
  EXPECT_EQ(x.stack().stats().TcpRetransSegs, 1u);
  EXPECT_EQ(x.stack().next_deadline(), x.d().now() + rto);
  EXPECT_EQ(x.stack().stats().TcpExtTCPLossProbes, 2u);

  expire_pto(TlpAction::none);
  EXPECT_TRUE(x.out().empty());
  EXPECT_EQ(x.log.tx(TxKind::tlp).size(), 2u);
  EXPECT_EQ(x.stack().next_deadline(), t0 + rto);  // the head's remaining time
  EXPECT_EQ(x.stack().stats().TcpExtTCPLossProbes, 2u);
  EXPECT_EQ(x.script.calls_of("on_tlp_sent"),
            (std::vector<std::string>{"on_tlp_sent 1 1", "on_tlp_sent 2 1", "on_tlp_sent 0 0"}));
  x.stack().debug_check();
}

// ---- m2-found, coordinator decision on the ACK frequency: the receiver's
// ACKs do not depend on how many segments the host hands the stack before
// the application reads (DESIGN §3; Linux __tcp_ack_snd_check per segment).

struct AckRun {
  std::vector<std::pair<std::int64_t, std::uint32_t>> acks;  // (time ns, SEG.ACK) of the receiver's ACKs
  std::size_t data_segs = 0;  // data segments the receiver got
  std::size_t reads = 0;      // read rounds of the receiving application
  std::size_t got = 0;        // bytes read
};

// An 8 MiB bulk transfer a -> b over a 100 Mbit/s link with 5 ms each way.
// b's host hands it each segment at its arrival time, and its application
// reads after every `batch` segments or when no segment follows within 1 ms.
// The sender leaves slow start at 100 segments (initial_ssthresh), which
// keeps its flight far below the receive window (2 MiB, fixed): the windows b
// advertises, which do depend on the reads, never limit it, and it never
// catches up with the writer, so every segment but the last is full-sized
// (a segment below rcv_mss is ACKed by the read that drains it, Linux
// tcp_cleanup_rbuf, which depends on the reads by design).
AckRun bulk_with_read_batches(std::size_t batch) {
  constexpr std::size_t total = 8u << 20;
  constexpr std::uint64_t rate = 12'500'000;  // bytes/s
  constexpr Duration delay = 5ms;
  StackConfig ca = config(Side::a);
  ca.tcp.initial_ssthresh = 100;
  utcp::Stack a(ca);
  utcp::Stack b(config(Side::b));
  Time now{1'000'000'000};
  a.advance(now);
  b.advance(now);
  AckRun run;
  struct Wire {
    bool to_b = false;
    t::Bytes bytes;
  };
  std::map<std::pair<std::int64_t, std::uint64_t>, Wire> wire;  // (arrival ns, order)
  std::uint64_t order = 0;
  Time link_free = now;
  const auto pump = [&] {
    while (auto p = a.pop_transmit()) {
      const auto bytes = p->buf.bytes();
      const Time dep = std::max(now, link_free) +
                       Duration{static_cast<std::int64_t>(bytes.size() * 1'000'000'000 / rate)};
      link_free = dep;
      wire.emplace(std::pair{(dep + delay).ns, order++}, Wire{true, t::Bytes(bytes.begin(), bytes.end())});
    }
    while (auto p = b.pop_transmit()) {
      const auto bytes = p->buf.bytes();
      t::Bytes copy(bytes.begin(), bytes.end());
      if (const auto q = parse(copy); q && has(q->v, w::tcp_ack) && !has(q->v, w::tcp_syn)) {
        run.acks.emplace_back(now.ns, q->v.h.ack.raw());
      }
      wire.emplace(std::pair{(now + delay).ns, order++}, Wire{false, std::move(copy)});
    }
  };
  utcp::TcpSocketOptions ro;
  ro.rcv_buf = 2u << 20;
  const auto l = b.tcp_listen(Endpoint{{}, port}, 4, ro);
  utcp::TcpSocketOptions so;
  so.snd_buf = 4u << 20;
  const auto c = a.tcp_connect(Endpoint{b.config().local_addr, port}, so);
  if (!l || !c) {
    return run;
  }
  std::optional<Handle> srv;
  const t::Bytes data = t::pattern(total);
  std::size_t written = 0, unread_segs = 0;
  std::vector<std::byte> buf(1 << 20);
  const auto read_all = [&] {
    ++run.reads;
    unread_segs = 0;
    while (srv) {
      const auto n = b.tcp_recv(*srv, buf);
      if (!n || *n == 0) {
        break;
      }
      run.got += *n;
    }
  };
  pump();
  while (run.got < total && now < Time{60'000'000'000}) {
    Time next = std::min(a.next_deadline(), b.next_deadline());
    if (!wire.empty()) {
      next = std::min(next, Time{wire.begin()->first.first});
    }
    now = std::max(now, next);
    a.advance(now);
    b.advance(now);
    while (!wire.empty() && wire.begin()->first.first <= now.ns) {
      Wire wd = std::move(wire.begin()->second);
      wire.erase(wire.begin());
      if (!wd.to_b) {
        a.receive(now, wd.bytes);
        continue;
      }
      const auto q = parse(wd.bytes);
      b.receive(now, wd.bytes);
      if (!srv) {
        if (const auto h = b.tcp_accept(*l)) {
          srv = *h;
        }
      }
      if (q && is_data(q->v)) {
        ++run.data_segs;
        ++unread_segs;
        // The host's batch ends after `batch` segments or when the next
        // segment for b is more than 1 ms away.
        std::optional<std::int64_t> next_b;
        for (const auto& [key, v] : wire) {
          if (v.to_b) {
            next_b = key.first;
            break;
          }
        }
        if (unread_segs >= batch || !next_b || *next_b > (now + 1ms).ns) {
          read_all();
        }
      }
      pump();
    }
    while (written < total) {
      const auto n = a.tcp_send(*c, std::span(data).subspan(written));
      if (!n) {
        break;
      }
      written += *n;
    }
    pump();
  }
  a.debug_check();
  b.debug_check();
  return run;
}

TEST(TcpTimer, AckFrequencyDoesNotDependOnTheReceiveBatch) {
  const AckRun one = bulk_with_read_batches(1);
  const AckRun many = bulk_with_read_batches(44);
  ASSERT_EQ(one.got, std::size_t{8} << 20);
  ASSERT_EQ(many.got, std::size_t{8} << 20);
  EXPECT_GT(one.reads, 5 * many.reads);  // the batching took effect
  EXPECT_EQ(one.data_segs, many.data_segs);
  EXPECT_EQ(one.acks.size(), many.acks.size());
  EXPECT_TRUE(one.acks == many.acks);
  // One ACK per segment while rcv_ssthresh grows (tcp_grow_window sets
  // icsk_ack.quick), then one per two full segments.
  const double per_seg = static_cast<double>(many.acks.size()) / static_cast<double>(many.data_segs);
  RecordProperty("acks", static_cast<int>(many.acks.size()));
  RecordProperty("data_segs", static_cast<int>(many.data_segs));
  std::printf("acks %zu data segments %zu (%.3f per segment)\n", many.acks.size(), many.data_segs,
              per_seg);
  EXPECT_GT(per_seg, 0.45);
  EXPECT_LT(per_seg, 0.75);
}

}  // namespace
