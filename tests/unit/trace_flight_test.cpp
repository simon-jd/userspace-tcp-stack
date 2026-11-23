// Compare the sender's snapshots with the scripted peer's wire sequence numbers.
#include <gtest/gtest.h>

#include <vector>

#include "tcp_test_util.hpp"
#include "utcp/trace.hpp"

namespace {
using namespace utcp;
namespace t = utcp::test;
using t::tcpt::Scripted;

struct FlightLog : TraceSink {
  std::vector<TraceEvent> events;
  void on_event(const TraceEvent& e) override { events.push_back(e); }

  std::vector<TraceEvent> of(TraceKind k) const {
    std::vector<TraceEvent> selected;
    for (const auto& e : events) {
      if (e.kind == k) selected.push_back(e);
    }
    return selected;
  }
};

TEST(TraceFlight, HandshakePublishesInstalledWindowForBothPeers) {
  using namespace std::chrono_literals;
  for (bool drop_first_syn : {false, true}) {
    auto active = t::tcpt::config(t::Side::a, ProfileId::rfc);
    auto passive = t::tcpt::config(t::Side::b, ProfileId::rfc);
    active.trace_mask = passive.trace_mask = trace_mask_all;
    active.tcp.timestamps = passive.tcp.timestamps = false;
    FlightLog client, server;
    t::TcpHarness pair(active, passive);
    pair.a().set_trace_sink(&client);
    pair.b().set_trace_sink(&server);
    pair.set_delay(t::Side::a, 2ms);
    pair.set_delay(t::Side::b, 3ms);
    bool dropped = false;
    pair.set_hook([&](t::Side from, t::Bytes& bytes) {
      const auto p = t::tcpt::parse(bytes);
      if (drop_first_syn && !dropped && from == t::Side::a && p && t::tcpt::is_syn(p->v)) {
        dropped = true;
        return t::Verdict::drop;
      }
      return t::Verdict::deliver;
    });
    const auto l = pair.b().tcp_listen(Endpoint{{}, t::tcpt::port}, 4, {});
    ASSERT_TRUE(l);
    const auto c = pair.a().tcp_connect(Endpoint{pair.addr(t::Side::b), t::tcpt::port}, {});
    ASSERT_TRUE(c);
    // Active sender already has a stream. The passive handshake stays lazy.
    ASSERT_TRUE(pair.a().tcp_send(*c, t::pattern(31)));
    pair.run_for(2s);
    ASSERT_TRUE(pair.b().tcp_accept(*l));
    EXPECT_EQ(dropped, drop_first_syn);
    for (const auto* log : {&client, &server}) {
      std::vector<TraceKind> order;
      for (const auto& e : log->events) {
        if (e.kind == TraceKind::cwnd && e.trigger == TraceTrigger::handshake) {
          EXPECT_EQ(e.prior_cwnd, 0u);
          EXPECT_EQ(e.prior_ssthresh, 0u);
          EXPECT_EQ(e.cwnd, log == &client && dropped ? 1u : 3u);
          EXPECT_EQ(e.ssthresh, active.tcp.initial_ssthresh);
          EXPECT_NE(e.ack, 0u);
          order.push_back(e.kind);
        } else if ((e.kind == TraceKind::rtt && e.trigger == TraceTrigger::handshake) ||
                   (e.kind == TraceKind::state && e.state == TcpState::established)) {
          order.push_back(e.kind);
        }
      }
      std::vector<TraceKind> expected{TraceKind::cwnd};
      if (log != &client || !dropped) expected.push_back(TraceKind::rtt);
      expected.push_back(TraceKind::state);
      EXPECT_EQ(order, expected);
    }
  }
}

TEST(TraceFlight, HandshakeAndSegmentAckHaveIndependentRttEvents) {
  auto cfg = t::tcpt::config(t::Side::b, ProfileId::rfc);
  cfg.trace_mask = trace_bit(TraceKind::rtt);
  FlightLog log;
  Scripted s(cfg);
  s.stack().set_trace_sink(&log);
  ASSERT_TRUE(s.accept());
  ASSERT_EQ(log.events.size(), 1u);
  EXPECT_EQ(log.events.front().trigger, TraceTrigger::handshake);
  EXPECT_EQ(log.events.front().sample_rtt_ns, 0);
  EXPECT_EQ(log.events.front().kind, TraceKind::rtt);
  ASSERT_EQ(s.stack().tcp_send(s.h, t::pattern(113)).value(), 113u);
  ASSERT_EQ(s.out().size(), 1u);
  s.d().run_for(std::chrono::milliseconds{7});
  auto a = s.spec(wire::tcp_ack);
  a.ack = s.their + 11;
  s.send(a);  // partial cumulative ACK supplies no completed segment
  EXPECT_EQ(log.events.size(), 1u);
  a.ack = s.their + 113;
  s.send(a);
  s.send(a);  // repeated ACK, no fresh timing information
  ASSERT_EQ(log.events.size(), 2u);
  EXPECT_EQ(log.events.back().kind, TraceKind::rtt);
  EXPECT_EQ(log.events.back().ack, a.ack.raw());
  EXPECT_EQ(log.events.back().sample_rtt_ns, 7'000'000);
  EXPECT_EQ(log.events.back().srtt_ns, s.stack().tcp_info(s.h)->srtt.count());
  EXPECT_EQ(log.events.back().in_flight_bytes, 0u);
}

TEST(TraceFlight, TimeoutThenAmbiguousAckWithoutTimestamps) {
  auto cfg = t::tcpt::config(t::Side::b, ProfileId::rfc);
  cfg.trace_mask = trace_mask_all;
  FlightLog log;
  Scripted s(cfg);
  s.stack().set_trace_sink(&log);
  ASSERT_TRUE(s.accept());
  log.events.clear();
  ASSERT_EQ(s.stack().tcp_send(s.h, t::pattern(113)).value(), 113u);
  ASSERT_EQ(s.out().size(), 1u);
  s.d().run_for(std::chrono::seconds{1});
  ASSERT_EQ(s.out().size(), 1u);
  const auto loss = log.of(TraceKind::recovery);
  ASSERT_EQ(loss.size(), 1u);
  EXPECT_EQ(loss.front().trigger, TraceTrigger::rto);
  EXPECT_EQ(loss.front().prior_ca, CaState::open);
  EXPECT_EQ(loss.front().ca, CaState::loss);
  EXPECT_EQ(loss.front().in_flight_bytes, 113u);
  ASSERT_EQ(log.of(TraceKind::cwnd).size(), 1u);
  auto a = s.spec(wire::tcp_ack);
  a.ack = s.their + 113;
  s.send(a);
  EXPECT_TRUE(log.of(TraceKind::rtt).empty());
  const auto transitions = log.of(TraceKind::recovery);
  ASSERT_EQ(transitions.size(), 2u);
  EXPECT_EQ(transitions.back().prior_ca, CaState::loss);
  EXPECT_EQ(transitions.back().trigger, TraceTrigger::ack);
  EXPECT_EQ(transitions.back().ca, CaState::open);
}

TEST(TraceFlight, EchoTimestampSuppliesUnambiguousRttAfterRto) {
  auto cfg = t::tcpt::config(t::Side::b, ProfileId::rfc);
  cfg.trace_mask = trace_bit(TraceKind::rtt);
  FlightLog log;
  Scripted s(cfg);
  s.po.ts = true;
  s.stack().set_trace_sink(&log);
  ASSERT_TRUE(s.accept());
  ASSERT_TRUE(s.stack().tcp_send(s.h, t::pattern(113)));
  ASSERT_EQ(s.out().size(), 1u);
  s.d().run_for(s.stack().next_deadline() - s.d().now());
  ASSERT_EQ(s.out().size(), 1u);  // saves the retransmitted segment's timestamp
  s.d().run_for(std::chrono::milliseconds{9});
  auto a = s.spec(wire::tcp_ack);
  a.ack = s.their + 113;
  s.send(a);
  ASSERT_EQ(log.events.size(), 2u);
  EXPECT_EQ(log.events.back().sample_rtt_ns, 9'000'000);
  EXPECT_EQ(log.events.back().rto_ns, s.stack().tcp_info(s.h)->rto.count());
}

TEST(TraceFlight, TailProbeRepairPublishesBothTransitionsOnOneAck) {
  auto cfg = t::tcpt::config(t::Side::b);
  cfg.tcp.cc = CcAlgo::cubic;
  cfg.tcp.pacing = Pacing::never;
  cfg.tcp.nodelay = true;
  cfg.trace_mask = trace_mask_all;
  FlightLog log;
  Scripted s(cfg);
  s.stack().set_trace_sink(&log);
  ASSERT_TRUE(s.accept());
  ASSERT_EQ(log.of(TraceKind::cwnd).size(), 1u);
  EXPECT_TRUE(log.of(TraceKind::recovery).empty());
  ASSERT_TRUE(s.stack().tcp_send(s.h, t::pattern(3 * 1460)));
  ASSERT_EQ(s.out().size(), 3u);
  s.d().run_for(s.stack().next_deadline() - s.d().now());
  ASSERT_EQ(s.out().size(), 1u);
  ASSERT_EQ(log.of(TraceKind::tx).back().tx, TxKind::tlp);
  ASSERT_TRUE(s.stack().tcp_send(s.h, t::pattern(1460)));
  ASSERT_EQ(s.out().size(), 1u);
  auto a = s.spec(wire::tcp_ack);
  a.ack = s.their + 4 * 1460;
  log.events.clear();
  s.send(a);
  const auto changes = log.of(TraceKind::recovery);
  ASSERT_EQ(changes.size(), 2u);
  EXPECT_EQ(changes[0].prior_ca, CaState::open);
  EXPECT_EQ(changes[0].ca, CaState::cwr);
  EXPECT_EQ(changes[1].prior_ca, CaState::cwr);
  EXPECT_EQ(changes[1].ca, CaState::open);
  for (const auto& e : changes) {
    EXPECT_EQ(e.t, s.d().now());
    EXPECT_EQ(e.ack, a.ack.raw());
    EXPECT_EQ(e.in_flight_bytes, 0u);
  }
  const auto windows = log.of(TraceKind::cwnd);
  ASSERT_GE(windows.size(), 2u);
  EXPECT_EQ(windows.front().cwnd, windows.front().prior_cwnd);
  EXPECT_NE(windows.front().ssthresh, windows.front().prior_ssthresh);
  EXPECT_NE(windows.back().cwnd, windows.back().prior_cwnd);
  log.events.clear();
  s.send(a);
  EXPECT_TRUE(log.of(TraceKind::cwnd).empty());
  EXPECT_TRUE(log.of(TraceKind::recovery).empty());
  EXPECT_TRUE(log.of(TraceKind::rtt).empty());
}

TEST(TraceFlight, WirePayloadAcrossWrapAndLateTraceAttach) {
  auto cfg = t::tcpt::config(t::Side::b, ProfileId::rfc);
  cfg.tcp.test_isn = 0xffff'ffefu;
  cfg.tcp.nodelay = true;
  cfg.trace_mask = trace_mask_all;
  FlightLog log;
  Scripted s(cfg);
  s.stack().set_trace_sink(&log);
  ASSERT_TRUE(s.accept());
  const Seq32 base = s.their;
  ASSERT_EQ(base.raw(), 0xffff'fff0u);
  const auto handshake = log.of(TraceKind::tx);
  ASSERT_EQ(handshake.size(), 1u);
  EXPECT_EQ(handshake.front().tx, TxKind::synack);
  for (const auto& e : log.events) EXPECT_EQ(e.in_flight_bytes, 0u);
  log.events.clear();

  ASSERT_EQ(s.stack().tcp_send(s.h, t::pattern(1497)).value(), 1497u);
  auto sent = s.out();
  ASSERT_EQ(sent.size(), 2u);
  ASSERT_EQ(sent[0].v.h.seq, base);
  ASSERT_EQ(sent[0].v.payload.size(), 1460u);
  ASSERT_EQ(sent[1].v.h.seq, base + 1460u);
  ASSERT_EQ(sent[1].v.payload.size(), 37u);
  const auto tx = log.of(TraceKind::tx);
  ASSERT_EQ(tx.size(), 2u);
  EXPECT_EQ(tx[0].in_flight_bytes, 1460u);
  EXPECT_EQ(tx[1].in_flight_bytes, 1497u);
  EXPECT_EQ(tx[1].in_flight, 2u);

  // A partial cumulative ACK crosses sequence zero. The older SACK arrived
  // with no sink attached and only covers part of a transmitted segment.
  s.stack().set_trace_sink(nullptr);
  auto a = s.spec(wire::tcp_ack);
  a.ack = base + 13;
  a.opt.sack_count = 1;
  a.opt.sack[0] = {base + 1450, base + 1475};
  s.send(a);
  s.stack().set_trace_sink(&log);
  log.events.clear();
  a.ack = base + 32;
  a.opt.sack[0] = {base + 1460, base + 1497};
  s.send(a);
  auto rx = log.of(TraceKind::rx);
  auto ack = log.of(TraceKind::ack);
  ASSERT_EQ(rx.size(), 1u);
  ASSERT_EQ(ack.size(), 1u);
  EXPECT_EQ(rx[0].in_flight_bytes, 1497u - 13u - 25u);
  EXPECT_EQ(ack[0].in_flight_bytes, 1450u - 32u);
  EXPECT_EQ(ack[0].sacked_out, 1u);
  EXPECT_EQ(ack[0].ack, 16u);
  s.send(a);
  EXPECT_EQ(log.of(TraceKind::ack).back().in_flight_bytes, 1418u);

  // FIN-WAIT-1 is published before transmitting the bare FIN.
  log.events.clear();
  ASSERT_TRUE(s.stack().tcp_shutdown(s.h, Shutdown::write));
  auto transitions = log.of(TraceKind::state);
  ASSERT_EQ(transitions.size(), 1u);
  EXPECT_EQ(transitions[0].state, TcpState::fin_wait_1);
  EXPECT_EQ(transitions[0].in_flight_bytes, 1418u);
  auto closing = log.of(TraceKind::tx);
  ASSERT_FALSE(closing.empty());
  EXPECT_NE(closing.back().flags & wire::tcp_fin, 0);
  EXPECT_EQ(closing.back().len, 0u);
  EXPECT_EQ(closing.back().in_flight_bytes, 1418u);
  a.opt.sack_count = 0;
  a.ack = base + 1498;
  s.send(a);
  EXPECT_EQ(log.of(TraceKind::ack).back().in_flight_bytes, 0u);
  EXPECT_EQ(log.of(TraceKind::state).back().state, TcpState::fin_wait_2);
  EXPECT_EQ(log.of(TraceKind::state).back().in_flight_bytes, 0u);
}
TEST(TraceFlight, LateAttachAfterWholeAndPartialSacks) {
  auto cfg = t::tcpt::config(t::Side::b, ProfileId::rfc);
  cfg.trace_mask = trace_mask_all;
  FlightLog log;
  Scripted s(cfg);
  ASSERT_TRUE(s.accept());
  ASSERT_EQ(s.stack().tcp_send(s.h, t::pattern(3 * 1460)).value(), 4380u);
  ASSERT_EQ(s.out().size(), 3u);
  auto a = s.spec(wire::tcp_ack);
  a.opt.sack_count = 2;
  a.opt.sack[0] = {s.their + 3001, s.their + 3101};
  a.opt.sack[1] = {s.their + 1460, s.their + 2920};
  s.send(a);
  s.stack().set_trace_sink(&log);
  s.send(a);
  const auto before = log.of(TraceKind::rx);
  const auto after = log.of(TraceKind::ack);
  ASSERT_EQ(before.size(), 1u);
  ASSERT_EQ(after.size(), 1u);
  EXPECT_EQ(before[0].in_flight_bytes, 4380u - 1460u - 100u);
  EXPECT_EQ(after[0].in_flight_bytes, before[0].in_flight_bytes);
  EXPECT_EQ(after[0].sacked_out, 1u);
}

TEST(TraceFlight, TimerRetransmissionLeavesUniquePayloadUnchanged) {
  auto cfg = t::tcpt::config(t::Side::b, ProfileId::rfc);
  cfg.trace_mask = trace_mask_all;
  FlightLog log;
  Scripted s(cfg);
  s.stack().set_trace_sink(&log);
  ASSERT_TRUE(s.accept());
  ASSERT_EQ(s.stack().tcp_send(s.h, t::pattern(113)).value(), 113u);
  ASSERT_EQ(s.out().size(), 1u);
  s.d().run_for(std::chrono::seconds{1});
  const auto retrans = s.out();
  ASSERT_EQ(retrans.size(), 1u);
  EXPECT_EQ(retrans[0].v.h.seq, s.their);
  EXPECT_EQ(retrans[0].v.payload.size(), 113u);
  const auto tx = log.of(TraceKind::tx);
  ASSERT_EQ(tx.back().tx, TxKind::rto_rexmit);
  EXPECT_EQ(tx.back().in_flight_bytes, 113u);
  EXPECT_EQ(tx.back().retrans_out, 1u);
}
}  // namespace
