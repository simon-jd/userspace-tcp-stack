// Directed simulator scenarios for the timers (m1-tcp-core acceptance test
// 4, m1-tcp-robust test 6): SYN and data retry exhaustion, delayed-ACK
// timing per profile, Nagle on and off, and RTO backoff under heavy loss.
// The timing checks need exact expected times, so the delayed-ACK and
// retry-exhaustion paths are clean before the planned total loss; Nagle and
// the backoff run under loss and reordering.
#include "tcp_sim_util.hpp"

#include "utcp/retry_model.hpp"

namespace utcp::sim {
namespace {

// §3.9 syn_retries / syn_linear_timeouts, §4.8: every SYN is lost. The
// client retransmits at 1, 2, 3, 4, 5, 7, 11, 19, 35, 67 s (linux_compat) or
// 1, 3, 7, 15, 31, 63, 123 s (rfc) and fails with timed_out at 131 s / 183 s.
TEST(TcpTimerSim, SynRetryExhaustion) {
  struct Case {
    ProfileId profile;
    std::vector<int> at;
    int fail;
  };
  const Case cases[] = {{ProfileId::linux_compat, {0, 1, 2, 3, 4, 5, 7, 11, 19, 35, 67}, 131},
                        {ProfileId::rfc, {0, 1, 3, 7, 15, 31, 63, 123}, 183}};
  for (const Case& c : cases) {
    SCOPED_TRACE(static_cast<int>(c.profile));
    LinkParams dead = impaired(10ms, 1'000'000);
    Scenario s = two_node_scenario(6000, dead, impaired(10ms, 50'000));
    s.node[0].profile = s.node[1].profile = c.profile;
    s.conn.push_back(bulk(10'000, 10'000));
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    std::vector<Duration> syns;
    for (const Seg& g : o.segs(0, true)) {
      if (g.has(wire::tcp_syn)) {
        syns.push_back(g.t - o.result.start - 1ms);
      }
    }
    ASSERT_EQ(syns.size(), c.at.size());
    for (std::size_t i = 0; i < syns.size(); ++i) {
      EXPECT_EQ(syns[i], std::chrono::seconds{c.at[i]}) << i;
    }
    const auto end = o.events(0, [](const TraceEvent& e) {
      return e.kind == TraceKind::state && e.state == TcpState::closed && e.tuple.remote.port != 0;
    });
    ASSERT_EQ(end.size(), 1u);
    EXPECT_EQ(end[0].cause, CloseCause::timed_out);
    EXPECT_EQ(end[0].t - o.result.start - 1ms, std::chrono::seconds{c.fail});
    EXPECT_EQ(o.stats[0].TcpExtTCPAbortOnTimeout, 1u);
    EXPECT_EQ(o.stats[0].TcpOutRsts, 0u);  // not synchronized: no RST
  }
}

// §4.8, RFC 1122 §4.2.3.5: 1 MB into a 5 MB transfer the receiver's packets
// stop arriving. The sender backs off, sends RST at the first RTO expiry at
// least retry_abort_time(data_retries) after the first retransmission (rfc at
// a 1 s RTO: 722 s; linux_compat depends on its first RTO, here 934.6 s) and
// ends with timed_out.
TEST(TcpTimerSim, DataRetryExhaustion) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    SCOPED_TRACE(static_cast<int>(profile));
    Scenario s = two_node_scenario(6100, clean_link(5ms), clean_link(5ms));
    s.node[0].profile = s.node[1].profile = profile;
    s.app_idle_timeout = 3000s;  // the sender's application never closes: no orphan rules
    s.conn.push_back(bulk(5'000'000, 0));
    // The cut comes when the receiver has taken 1 MB off the wire.
    Time cut = Time::never();
    std::uint64_t in = 0;
    RunSpec spec;
    spec.setup = [&](std::vector<Tap*>& taps) {
      taps[1]->ingress = [&](Tap& t, Time, std::span<const std::byte> d) {
        in += d.size();
        if (in >= 1'000'000 && cut.is_never()) {
          cut = t.now();
        }
        return true;
      };
      taps[1]->egress = [&](Tap& t, Time, std::span<const std::byte>) { return t.now() < cut; };
    };
    const Outcome o = run_sim(s, spec);
    ASSERT_TRUE(o.ok()) << o.violations();
    std::vector<Time> rexmit;
    std::optional<Time> rst;
    for (const Rec& r : o.trace) {
      if (r.node != 0 || r.e.kind != TraceKind::tx || r.e.t < cut) {
        continue;
      }
      if (r.e.tx == TxKind::rto_rexmit) {
        rexmit.push_back(r.e.t);
      } else if (r.e.tx == TxKind::rst && !rst) {
        rst = r.e.t;
      }
    }
    ASSERT_GE(rexmit.size(), 3u);
    ASSERT_TRUE(rst.has_value());
    const TcpConfig cfg = tcp_config(profile);
    const Duration bound = retry_abort_time(cfg.data_retries, cfg.rto_min, cfg.rto_max);
    const Duration abort = *rst - rexmit.front();
    EXPECT_GE(abort, bound);
    EXPECT_LT(rexmit.back() - rexmit.front(), bound);
    // The RST is the first expiry past the bound.
    EXPECT_LT(abort - bound, cfg.rto_max);
    if (profile == ProfileId::rfc) {
      EXPECT_EQ(abort, 722s);  // RTO 1 s (rto_min) at the first retransmission
    }
    EXPECT_EQ(o.closes(0), std::vector<CloseCause>{CloseCause::timed_out});
    EXPECT_EQ(o.stats[0].TcpExtTCPAbortOnTimeout, 1u);
  }
}

// A TrickleClient on node 0 writes `chunk` bytes every `gap` to a StackNode
// server on node 1, whose reader pauses for `pause` after every `chunk`
// bytes when `pause` is non-zero.
Outcome trickle(std::uint64_t seed, const LinkParams& ab, const LinkParams& ba, ProfileId profile,
                std::size_t chunk, Duration gap, std::uint64_t total, bool nodelay,
                Duration pause = {}) {
  Scenario s = two_node_scenario(seed, ab, ba);
  s.node[0].profile = s.node[1].profile = profile;
  ConnSpec c = bulk(total, 0);
  if (pause > Duration{0}) {
    c.pause_every_s = chunk;
    c.pause_s = pause;
  }
  s.conn.push_back(c);
  TrickleClient cl;
  cl.total = total;
  cl.chunk = chunk;
  cl.gap = gap;
  cl.start = s.start + 1ms;
  cl.opts.nodelay = nodelay;
  RunSpec spec;
  spec.make = [&](const Scenario& sc, std::uint32_t i) -> std::unique_ptr<Node> {
    if (i != 0) {
      return nullptr;
    }
    auto n = std::make_unique<AppNode>(sc, i);
    n->script = [&](AppNode& node, Time now) { cl.step(node, now); };
    return n;
  };
  return run_sim(s, spec);
}

// §3.9 delack_ato, quickack: single 100-byte segments. rfc: 300 ms apart,
// read at once; each is ACKed exactly 200 ms later, except when the read
// moves the right edge far enough for a window update (then at once).
// linux_compat: 150 ms apart (below the receiver's RTO, so no idle quick
// ACKs); the receiver reads one segment and then pauses 250 ms, so every
// other segment waits unread. A segment read at once is ACKed at once
// (__tcp_cleanup_rbuf after a small segment, ICSK_ACK_PUSHED), as are the
// first ones (quick ACKs); an unread one after the adaptive ato, 40..200 ms.
TEST(TcpTimerSim, DelayedAckPerProfile) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    SCOPED_TRACE(static_cast<int>(profile));
    const bool rfc = profile == ProfileId::rfc;
    const Outcome o = trickle(6200, clean_link(10ms), clean_link(10ms), profile, 100,
                              rfc ? 300ms : 150ms, 40 * 100, false, rfc ? 0ms : 250ms);
    ASSERT_TRUE(o.ok()) << o.violations();
    std::vector<Duration> delays;
    std::optional<Time> pending;
    for (const Seg& g : o.wire) {
      if (g.node != 1) {
        continue;
      }
      if (!g.egress && g.len > 0 && !g.has(wire::tcp_fin)) {
        pending = g.t;
      } else if (g.egress && pending && g.len == 0 && !g.has(wire::tcp_fin) &&
                 !g.has(wire::tcp_syn)) {
        delays.push_back(g.t - *pending);
        pending.reset();
      }
    }
    ASSERT_EQ(delays.size(), 40u);
    std::uint64_t at_once = 0, delayed = 0;
    for (const Duration d : delays) {
      if (d == Duration{0}) {
        ++at_once;
        continue;
      }
      ++delayed;
      if (profile == ProfileId::rfc) {
        EXPECT_EQ(d, 200ms);
      } else {
        EXPECT_GE(d, 40ms);
        EXPECT_LE(d, 200ms);
      }
    }
    EXPECT_GE(delayed, profile == ProfileId::rfc ? 15u : 8u);
    EXPECT_GT(at_once, 0u);
    EXPECT_EQ(o.stats[1].TcpExtDelayedACKs, delayed);
  }
}

// The most small (below one MSS) new-data segments the client had
// unacknowledged at once, from the wire: a segment is acknowledged when an
// ACK at or above its end has reached the client.
int max_small_in_flight(const Outcome& o, std::uint32_t mss) {
  std::vector<Seq32> ends;  // ends of small new-data segments not yet acked
  std::optional<Seq32> high;
  int most = 0;
  for (const Seg& g : o.wire) {
    if (g.node != 0) {
      continue;
    }
    if (!g.egress && g.has(wire::tcp_ack)) {
      std::erase_if(ends, [&](Seq32 e) { return after_eq(g.h.ack, e); });
      continue;
    }
    if (!g.egress || g.len == 0 || g.has(wire::tcp_fin)) {
      continue;  // a FIN pushes its segment out regardless of Nagle
    }
    const Seq32 end = g.h.seq + g.len;
    if (high && !before(*high, end)) {
      continue;  // retransmission
    }
    high = end;
    if (g.len < mss) {
      ends.push_back(end);
      most = std::max(most, static_cast<int>(ends.size()));
    }
  }
  return most;
}

// RFC 9293 §3.7.4, §3.9 nagle: 100-byte writes every 5 ms over a 20 ms
// path with loss and reordering. With Nagle (both profiles) at most one
// small segment is unacknowledged at any time and the writes coalesce; with
// nodelay most writes leave at once as their own small segments (some
// coalesce while cwnd is full).
TEST(TcpTimerSim, NagleOnAndOff) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    for (const bool nodelay : {false, true}) {
      SCOPED_TRACE(std::to_string(static_cast<int>(profile)) + (nodelay ? " nodelay" : " nagle"));
      const Outcome o = trickle(6300, impaired(20ms, 20'000), impaired(20ms, 20'000), profile, 100,
                                5ms, 200 * 100, nodelay);
      ASSERT_TRUE(o.ok()) << o.violations();
      const int most = max_small_in_flight(o, 1448);
      std::uint64_t data_segs = 0;
      for (const Seg& g : o.segs(0, true)) {
        data_segs += g.len > 0 ? 1 : 0;
      }
      if (nodelay) {
        EXPECT_GE(most, 4);
        EXPECT_GT(data_segs, 80u);
      } else {
        EXPECT_EQ(most, 1);
        EXPECT_LT(data_segs, 40u);
      }
    }
  }
}

// RFC 6298 §5.5-5.6, Karn: under 20 % loss each RTO expiry doubles the RTO
// (up to rto_max) until a new RTT sample from never-retransmitted data; an
// expiry right after another keeps ssthresh (§5.3, RFC 5681 §3.1 / Linux
// tcp_enter_loss); SND.NXT never moves back (P6).
TEST(TcpTimerSim, RtoBackoffUnderHeavyLoss) {
  for (const ProfileId profile : {ProfileId::rfc, ProfileId::linux_compat}) {
    SCOPED_TRACE(static_cast<int>(profile));
    Scenario s = two_node_scenario(6400, impaired(10ms, 200'000), impaired(10ms, 200'000));
    s.node[0].profile = s.node[1].profile = profile;
    s.conn.push_back(bulk(300'000, 0));
    const Outcome o = run_sim(s);
    ASSERT_TRUE(o.ok()) << o.violations();
    const TcpConfig cfg = tcp_config(profile);
    int doubled = 0, kept = 0;
    std::optional<TraceEvent> last_rto;
    std::uint64_t high_nxt = 0;
    bool sample_since = false;
    for (const Rec& r : o.trace) {
      if (r.node != 0 || r.e.tuple.remote.port != 5000) {
        continue;
      }
      const TraceEvent& e = r.e;
      if (e.kind == TraceKind::tx) {
        EXPECT_GE(e.snd_nxt_off, high_nxt);
        high_nxt = std::max(high_nxt, e.snd_nxt_off);
      }
      if (e.kind == TraceKind::rtt) {
        sample_since = true;
      }
      if (e.kind == TraceKind::ack && last_rto && e.snd_una_off > last_rto->snd_una_off) {
        last_rto.reset();  // progress: the next expiry is not back to back
      }
      if (e.kind != TraceKind::rto) {
        continue;
      }
      if (last_rto && !sample_since) {
        EXPECT_EQ(e.rto_ns, std::min<std::int64_t>(2 * last_rto->rto_ns, cfg.rto_max.count()));
        doubled += 1;
        if (e.snd_una_off == last_rto->snd_una_off) {
          EXPECT_EQ(e.ssthresh, last_rto->ssthresh);
          kept += 1;
        }
      }
      last_rto = e;
      sample_since = false;
    }
    EXPECT_GT(doubled, 0);
    EXPECT_GT(kept, 0);
  }
}

}  // namespace
}  // namespace utcp::sim
