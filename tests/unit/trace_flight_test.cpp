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

TEST(DedicatedTrace, HandshakeAndSegmentAckHaveIndependentRttEvents) {
  auto cfg = t::tcpt::config(t::Side::b, ProfileId::rfc);
  cfg.trace_mask = trace_bit(TraceKind::rtt);
  FlightLog log;
  Scripted s(cfg);
  s.stack().set_trace_sink(&log);
  ASSERT_TRUE(s.accept());
  ASSERT_EQ(log.events.size(), 1u);
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
  EXPECT_EQ(log.events.back().in_flight_bytes, 0u);
}

TEST(DedicatedTrace, TimeoutThenAmbiguousAckWithoutTimestamps) {
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
  EXPECT_EQ(loss.front().ca, CaState::loss);
  EXPECT_EQ(loss.front().in_flight_bytes, 113u);
  ASSERT_EQ(log.of(TraceKind::cwnd).size(), 1u);
  auto a = s.spec(wire::tcp_ack);
  a.ack = s.their + 113;
  s.send(a);
  EXPECT_TRUE(log.of(TraceKind::rtt).empty());
  const auto transitions = log.of(TraceKind::recovery);
  ASSERT_EQ(transitions.size(), 2u);
  EXPECT_EQ(transitions.back().ca, CaState::open);
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
