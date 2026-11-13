// m1-tcp-core acceptance test 4: timers (DESIGN §4.8, §4.9, §4.10, §6):
// delayed ACKs, Nagle, RTO backoff and Karn, the SYN schedules and the retry
// limits.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "tcp_test_util.hpp"
#include "utcp/retry_model.hpp"

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

}  // namespace
