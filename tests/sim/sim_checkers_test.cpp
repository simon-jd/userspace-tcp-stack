// Checkers fed synthetic sequences that must fire and must not fire
// (m1-sim acceptance test 6, checker part; the World-driven checks are in
// sim_world_test.cpp).
#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <vector>

#include "core/wire/tcp.hpp"
#include "utcp/sim/checkers.hpp"
#include "utcp/sim/datagram.hpp"
#include "utcp/sim/world.hpp"

namespace utcp::sim {
namespace {

using namespace std::chrono_literals;

const Endpoint ea{node_addr(0), 40000};
const Endpoint eb{node_addr(1), 5000};
const FourTuple ab{ea, eb};  // a's view: a sends to b
const FourTuple ba{eb, ea};

std::vector<std::byte> seg(Endpoint from, Endpoint to, std::uint32_t seq, std::uint32_t ack,
                           std::uint16_t flags, std::uint16_t window, std::size_t len = 0,
                           std::optional<std::uint8_t> ws = std::nullopt,
                           std::vector<std::pair<std::uint32_t, std::uint32_t>> sack = {},
                           bool sack_permitted = false) {
  TcpSegmentSpec s;
  s.src = from;
  s.dst = to;
  s.seq = seq;
  s.ack = ack;
  s.flags = flags;
  s.window = window;
  s.opt.wscale = ws;
  s.opt.sack_permitted = sack_permitted;
  for (const auto& [b, e] : sack) {
    s.opt.sack[s.opt.sack_count++] = {Seq32(b), Seq32(e)};
  }
  const std::vector<std::byte> payload(len);
  s.payload = payload;
  return build_tcp(s);
}

constexpr std::uint16_t syn = wire::tcp_syn;
constexpr std::uint16_t ack = wire::tcp_ack;
constexpr std::uint32_t iss_a = 1000, iss_b = 900'000;

// a and b handshake on the wire with ISNs `ia` and `ib`: a's SYN offers
// wscale `wa`, b's SYN-ACK offers `wb` (nullopt: no option) with window
// `synack_window`. Each datagram is seen leaving its sender and arriving at
// the other node.
void handshake(InFlightChecker& c, std::optional<std::uint8_t> wa, std::optional<std::uint8_t> wb,
               std::uint16_t synack_window = 1000, std::uint32_t ia = iss_a,
               std::uint32_t ib = iss_b, bool own_sack = false, bool peer_sack = false) {
  const auto s1 = seg(ea, eb, ia, 0, syn, 65535, 0, wa, {}, own_sack);
  ASSERT_FALSE(c.on_egress(0, s1));
  c.on_ingress(1, s1);
  const auto s2 = seg(eb, ea, ib, ia + 1, syn | ack, synack_window, 0, wb, {}, peer_sack);
  ASSERT_FALSE(c.on_egress(1, s2));
  c.on_ingress(0, s2);
}

// --- InFlightChecker: wire shadow.

TEST(SimCheckersInFlight, DataWithinScaledEdgePasses) {
  InFlightChecker c;
  handshake(c, 7, 2);  // b's receive window is scaled by 4
  // b ACKs a's SYN with window 1000 << 2 = 4000 bytes.
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 1, ack, 1000));
  EXPECT_EQ(c.right_edge(ab), Seq32(iss_a + 1 + 4000));
  // a sends exactly up to the edge.
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 1, iss_b + 1, ack, 500, 1460)));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 1461, iss_b + 1, ack, 500, 1460)));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 2921, iss_b + 1, ack, 500, 1080)));
}

TEST(SimCheckersInFlight, SenderIgnoringPeerWscaleFires) {
  // b offers wscale 2 (window field 1000 means 4000 bytes); a sender that
  // applies a shift of 7 instead believes 128000 bytes are open.
  InFlightChecker c;
  handshake(c, 7, 2);
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 1, ack, 1000));
  std::uint32_t seq = iss_a + 1;
  std::optional<std::string> fired;
  for (int i = 0; i < 10 && !fired; ++i) {
    fired = c.on_egress(0, seg(ea, eb, seq, iss_b + 1, ack, 500, 1460));
    seq += 1460;
  }
  ASSERT_TRUE(fired.has_value());
  EXPECT_NE(fired->find("right edge"), std::string::npos) << *fired;
}

TEST(SimCheckersInFlight, PeerWithoutWscaleMeansNoScaling) {
  // a offered wscale, b did not: no scaling either way (RFC 7323 §2.2); a
  // sender that still scales b's window by its shift fires.
  InFlightChecker c;
  handshake(c, 7, std::nullopt);
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 1, ack, 3000));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 1, iss_b + 1, ack, 500, 1460)));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 1461, iss_b + 1, ack, 500, 1460)));
  EXPECT_TRUE(c.on_egress(0, seg(ea, eb, iss_a + 2921, iss_b + 1, ack, 500, 1460)).has_value());
}

TEST(SimCheckersInFlight, SynWindowIsNotScaled) {
  InFlightChecker c;
  handshake(c, 7, 7, 30000);
  // Only the SYN-ACK's window (30000, not 30000 << 7) is known.
  EXPECT_EQ(c.right_edge(ab), Seq32(iss_a + 1 + 30000));
  std::uint32_t seq = iss_a + 1;
  for (int i = 0; i < 30; ++i) {
    ASSERT_FALSE(c.on_egress(0, seg(ea, eb, seq, iss_b + 1, ack, 500, 1000)));
    seq += 1000;
  }
  EXPECT_TRUE(c.on_egress(0, seg(ea, eb, seq, iss_b + 1, ack, 500, 1)).has_value());
}

TEST(SimCheckersInFlight, RetransmissionsBeyondEdgeDoNotFire) {
  InFlightChecker c;
  handshake(c, 0, 0);
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 1, ack, 3000));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 1, iss_b + 1, ack, 500, 1460)));
  // New data past the edge fires once ...
  EXPECT_TRUE(c.on_egress(0, seg(ea, eb, iss_a + 1461, iss_b + 1, ack, 500, 2000)).has_value());
  // ... and its retransmissions, whole or in part, do not.
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 1461, iss_b + 1, ack, 500, 2000)));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 2461, iss_b + 1, ack, 500, 1000)));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 1, iss_b + 1, ack, 500, 1460)));
}

TEST(SimCheckersInFlight, EdgeIsMaximumOverDeliveredAcks) {
  InFlightChecker c;
  handshake(c, 0, 0);
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 1, ack, 5000));
  // A later ACK with a smaller window (a shrinking receiver) does not take
  // back what the sender was allowed to send.
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 1, ack, 100));
  EXPECT_EQ(c.right_edge(ab), Seq32(iss_a + 1 + 5000));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, iss_a + 1, iss_b + 1, ack, 500, 5000)));
}

TEST(SimCheckersInFlight, CorruptedAcksAreIgnored) {
  InFlightChecker c;
  handshake(c, 0, 0);
  auto big = seg(eb, ea, iss_b + 1, iss_a + 1, ack, 60000);
  big[big.size() - 1] ^= std::byte{1};  // urgent pointer: the checksum is now wrong
  c.on_ingress(0, big);
  EXPECT_EQ(c.right_edge(ab), Seq32(iss_a + 1 + 1000));  // from the SYN-ACK only
}

TEST(SimCheckersInFlight, ForgedSynDoesNotSetWscale) {
  // A SYN-ACK whose ISN is not the one b sent (e.g. garbage) is ignored.
  InFlightChecker c;
  const auto s1 = seg(ea, eb, iss_a, 0, syn, 65535, 0, 7);
  ASSERT_FALSE(c.on_egress(0, s1));
  c.on_ingress(1, s1);
  ASSERT_FALSE(c.on_egress(1, seg(eb, ea, iss_b, iss_a + 1, syn | ack, 65535, 0, 0)));
  c.on_ingress(0, seg(eb, ea, iss_b + 77, iss_a + 1, syn | ack, 65535, 0, 14));
  c.on_ingress(0, seg(eb, ea, iss_b, iss_a + 1, syn | ack, 65535, 0, 0));
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 1, ack, 1000));
  EXPECT_EQ(c.right_edge(ab), Seq32(iss_a + 1 + 65535));  // shift 0, not 14
}

TEST(SimCheckersInFlight, WireSackReducesBytesInFlight) {
  InFlightChecker c;
  handshake(c, 0, 0);
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 1, ack, 65535));
  std::uint32_t seq = iss_a + 1;
  for (int i = 0; i < 10; ++i) {
    ASSERT_FALSE(c.on_egress(0, seg(ea, eb, seq, iss_b + 1, ack, 500, 1000)));
    seq += 1000;
  }
  // b ACKs 2000 bytes and SACKs 5000 more.
  c.on_ingress(0, seg(eb, ea, iss_b + 1, iss_a + 2001, ack, 65535, 0, std::nullopt,
                      {{iss_a + 4001, iss_a + 9001}}));
  TraceEvent e;
  e.kind = TraceKind::tx;
  e.tx = TxKind::data;
  e.tuple = ab;
  e.ca = CaState::open;
  e.mss = 1000;
  e.seq = iss_a + 9001;
  e.len = 1000;
  e.in_flight = 3;
  e.cwnd = 3;
  // In flight on the wire: 10000 sent - 2000 acked - 5000 SACKed = 3000.
  EXPECT_FALSE(c.on_trace(0, e));
  e.cwnd = 2;
  e.in_flight = 2;
  EXPECT_TRUE(c.on_trace(0, e).has_value());
  // The wire check applies only in Open with no loss marks: in Recovery or
  // Loss, or with segments marked lost, lost segments still count on the
  // wire although the sender no longer counts them in flight.
  for (const CaState ca : {CaState::disorder, CaState::cwr, CaState::recovery, CaState::loss}) {
    e.ca = ca;
    EXPECT_FALSE(c.on_trace(0, e)) << static_cast<int>(ca);
  }
  e.ca = CaState::open;
  e.lost_out = 1;
  EXPECT_FALSE(c.on_trace(0, e));
  e.lost_out = 0;
  EXPECT_TRUE(c.on_trace(0, e).has_value());
}

// Sequence numbers wrap past 2^32 inside the window (DESIGN §7.2 starts 10 %
// of seeds near 2^32): the edge, the highest sent and ACKed sequence numbers
// and the SACK ranges are compared modulo 2^32.
constexpr std::uint32_t wrap_iss_a = 0xffff'f000u;  // a's data crosses 2^32 after 4095 bytes
constexpr std::uint32_t wrap_iss_b = 0xffff'ff00u;

TEST(SimCheckersInFlight, EdgeAcrossSequenceWrap) {
  InFlightChecker c;
  handshake(c, 0, 0, 1000, wrap_iss_a, wrap_iss_b);
  // b ACKs a's SYN with window 8000: the edge lies past 2^32.
  c.on_ingress(0, seg(eb, ea, wrap_iss_b + 1, wrap_iss_a + 1, ack, 8000));
  ASSERT_EQ(c.right_edge(ab), Seq32(wrap_iss_a + 1 + 8000));
  EXPECT_LT(c.right_edge(ab)->raw(), wrap_iss_a);  // wrapped
  std::uint32_t seq = wrap_iss_a + 1;
  for (int i = 0; i < 8; ++i) {  // up to the edge, crossing 2^32 in the fifth segment
    ASSERT_FALSE(c.on_egress(0, seg(ea, eb, seq, wrap_iss_b + 1, ack, 500, 1000))) << i;
    seq += 1000;
  }
  // One byte past the wrapped edge fires; its retransmission does not.
  EXPECT_TRUE(c.on_egress(0, seg(ea, eb, seq, wrap_iss_b + 1, ack, 500, 1)).has_value());
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, seq, wrap_iss_b + 1, ack, 500, 1)));
  // A later ACK below the wrap with a smaller window does not move the edge
  // back; one past 2^32 moves it on.
  c.on_ingress(0, seg(eb, ea, wrap_iss_b + 1, wrap_iss_a + 1001, ack, 100));
  EXPECT_EQ(c.right_edge(ab), Seq32(wrap_iss_a + 1 + 8000));
  c.on_ingress(0, seg(eb, ea, wrap_iss_b + 1, wrap_iss_a + 6001, ack, 8000));
  EXPECT_EQ(c.right_edge(ab), Seq32(wrap_iss_a + 6001 + 8000));
  EXPECT_FALSE(c.on_egress(0, seg(ea, eb, seq + 1, wrap_iss_b + 1, ack, 500, 1000)));
}

TEST(SimCheckersInFlight, WireSackAcrossSequenceWrap) {
  // As WireSackReducesBytesInFlight, with the flight, the cumulative ACK and
  // the SACK block on both sides of 2^32.
  InFlightChecker c;
  handshake(c, 0, 0, 1000, wrap_iss_a, wrap_iss_b);
  c.on_ingress(0, seg(eb, ea, wrap_iss_b + 1, wrap_iss_a + 1, ack, 65535));
  std::uint32_t seq = wrap_iss_a + 1;
  for (int i = 0; i < 10; ++i) {
    ASSERT_FALSE(c.on_egress(0, seg(ea, eb, seq, wrap_iss_b + 1, ack, 500, 1000)));
    seq += 1000;
  }
  // ACK 2000 bytes (below 2^32), SACK [4001, 9001) (across it), and an older
  // overlapping block that must merge, not add.
  c.on_ingress(0, seg(eb, ea, wrap_iss_b + 1, wrap_iss_a + 2001, ack, 65535, 0, std::nullopt,
                      {{wrap_iss_a + 4001, wrap_iss_a + 9001}, {wrap_iss_a + 3501, wrap_iss_a + 5001}}));
  TraceEvent e;
  e.kind = TraceKind::tx;
  e.tx = TxKind::data;
  e.tuple = ab;
  e.ca = CaState::open;
  e.mss = 1000;
  e.seq = wrap_iss_a + 9001;
  e.len = 1000;
  // On the wire: 10000 sent - 2000 acked - 5500 SACKed = 2500 bytes.
  e.in_flight = 3;
  e.cwnd = 3;
  EXPECT_FALSE(c.on_trace(0, e));
  e.in_flight = 2;
  e.cwnd = 2;
  EXPECT_TRUE(c.on_trace(0, e).has_value());
  // The cumulative ACK passes 2^32 and part of the SACKed range: 10000 sent
  // - 4500 acked - 4500 still SACKed above it = 1000 bytes, one segment.
  c.on_ingress(0, seg(eb, ea, wrap_iss_b + 1, wrap_iss_a + 4501, ack, 65535, 0, std::nullopt,
                      {{wrap_iss_a + 4001, wrap_iss_a + 9001}}));
  e.in_flight = 1;
  e.cwnd = 1;
  EXPECT_FALSE(c.on_trace(0, e));
}

// --- InFlightChecker: self-reported numbers and the exemptions.

TraceEvent tx_event(TxKind kind, std::uint32_t in_flight, std::uint32_t cwnd) {
  TraceEvent e;
  e.kind = TraceKind::tx;
  e.tx = kind;
  e.tuple = ab;
  e.ca = CaState::recovery;
  e.len = 1000;
  e.mss = 1000;
  e.in_flight = in_flight;
  e.cwnd = cwnd;
  return e;
}

TEST(SimCheckersInFlight, InFlightAboveCwndFiresForData) {
  InFlightChecker c;
  EXPECT_FALSE(c.on_trace(0, tx_event(TxKind::data, 10, 10)));
  EXPECT_TRUE(c.on_trace(0, tx_event(TxKind::data, 11, 10)).has_value());
  EXPECT_TRUE(c.on_trace(0, tx_event(TxKind::rexmit, 11, 10)).has_value());
  EXPECT_TRUE(c.on_trace(0, tx_event(TxKind::pmtu_rexmit, 11, 10)).has_value());
}

TraceEvent rto_expiry() {
  TraceEvent e;
  e.kind = TraceKind::rto;
  e.tuple = ab;
  return e;
}

TEST(SimCheckersInFlight, FastRexmitRtoRexmitTlpExempt) {
  InFlightChecker c;
  EXPECT_FALSE(c.on_trace(0, tx_event(TxKind::fast_rexmit, 20, 10)));
  EXPECT_FALSE(c.on_trace(0, rto_expiry()));
  EXPECT_FALSE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 20, 1)));
  handshake(c, 0, 0, 1000, iss_a, iss_b, true, true);
  TraceEvent probe = tx_event(TxKind::tlp, 11, 10);
  probe.ca = CaState::open;
  EXPECT_FALSE(c.on_trace(0, probe));
  // Segments without data are not data transmissions.
  TraceEvent pure_ack = tx_event(TxKind::ack, 20, 10);
  pure_ack.len = 0;
  EXPECT_FALSE(c.on_trace(0, pure_ack));
  // Other trace kinds are ignored.
  TraceEvent rx = tx_event(TxKind::data, 20, 10);
  rx.kind = TraceKind::rx;
  EXPECT_FALSE(c.on_trace(0, rx));
}

TEST(SimCheckersInFlight, StrictFastRetransmissionUsesSenderReduction) {
  InFlightChecker c;
  const auto tx = tx_event(TxKind::fast_rexmit, 5, 4);
  c.set_reduction(0, RecoveryReduction::prr);
  c.set_reduction(1, RecoveryReduction::rfc6675);
  EXPECT_FALSE(c.on_trace(0, tx));
  c.set_strict_fast_rexmit(true);
  EXPECT_TRUE(c.on_trace(0, tx));
  EXPECT_FALSE(c.on_trace(1, tx));
}

// Trace callbacks precede egress; accepted ACK traces follow ingress.
struct ProbeFixture {
  InFlightChecker checker;
  TraceEvent probe = tx_event(TxKind::tlp, 1, 10);

  explicit ProbeFixture(bool retrans, bool fin = false, unsigned shift = 0) {
    handshake(checker, 0, shift, 4000, iss_a, iss_b, true, true);
    probe.ca = CaState::open;
    probe.seq = iss_a + 1;
    probe.flags = ack | (fin ? wire::tcp_fin : 0);
    probe.snd_nxt_off = 1000;
    if (retrans) {
      auto original = probe;
      original.tx = TxKind::data;
      EXPECT_FALSE(checker.on_trace(0, original));
    }
    EXPECT_FALSE(checker.on_trace(0, probe));
  }

  void input(unsigned offset, std::uint16_t window, std::size_t len = 0,
             std::vector<std::pair<std::uint32_t, std::uint32_t>> sack = {},
             bool accepted = true, unsigned peer_off = 1) {
    const auto seq = iss_b + peer_off;
    const auto number = iss_a + 1 + offset;
    checker.on_ingress(0, seg(eb, ea, seq, number, ack, window, len, {}, sack));
    if (accepted) {
      TraceEvent event;
      event.kind = TraceKind::ack;
      event.tuple = ab;
      event.seq = seq;
      event.ack = number;
      event.snd_una_off = offset;
      event.mss = 1000;
      EXPECT_FALSE(checker.on_trace(0, event));
    }
  }

  bool second_rejected() { return checker.on_trace(0, probe).has_value(); }
};

TEST(SimCheckersInFlight, RetransmittedProbeRequiresMarkerAndMatchingEvidence) {
  for (bool fin : {false, true}) {
    const unsigned marker = fin ? 1001 : 1000;
    for (unsigned ending = 0; ending < 6; ++ending) {
      SCOPED_TRACE(::testing::Message() << "fin=" << fin << " ending=" << ending);
      ProbeFixture f(true, fin);
      EXPECT_TRUE(f.second_rejected());
      f.input(0, 4000);  // pure duplicate below marker, window from SYN-ACK
      EXPECT_TRUE(f.second_rejected());
      f.input(100, 4000, 0, {{iss_a + 1, iss_a + 1 + marker},
                              {iss_a, iss_a + 2 + marker}});
      EXPECT_TRUE(f.second_rejected());  // nested D-SACK below marker
      if (fin) {
        f.input(1000, 4000);
        EXPECT_TRUE(f.second_rejected());  // FIN occupies one sequence number
      }
      if (ending == 0) {
        f.input(marker, 4000, 0, {{iss_a + 1 + marker - 1000, iss_a + 1 + marker}});
      } else {
        f.input(marker, 4000);
        EXPECT_TRUE(f.second_rejected());  // first advancing ACK at equality
        if (ending == 1) {
          f.input(marker, 3900);
          EXPECT_TRUE(f.second_rejected());  // actual window update
          f.input(marker, 3900, 1);
          EXPECT_TRUE(f.second_rejected());  // data-bearing ACK
          f.input(marker, 3900);
        } else if (ending == 2) {
          auto later = f.probe;
          later.tx = TxKind::data;
          later.seq = iss_a + 1 + marker;
          later.len = 1;
          later.snd_nxt_off += 1;
          EXPECT_FALSE(f.checker.on_trace(0, later));
          f.input(marker + 1, 4000);
        } else if (ending == 3) {
          (void)f.checker.on_trace(0, rto_expiry());
        } else {
          TraceEvent state;
          state.kind = TraceKind::recovery;
          state.tuple = ab;
          state.ca = ending == 4 ? CaState::recovery : CaState::loss;
          (void)f.checker.on_trace(0, state);
        }
      }
      EXPECT_FALSE(f.second_rejected());
    }
  }
}

TEST(SimCheckersInFlight, NewDataProbeEndsAtWireMarker) {
  for (bool fin : {false, true}) {
    ProbeFixture f(false, fin);
    const unsigned marker = fin ? 1001 : 1000;
    f.input(marker - 1, 4000);
    EXPECT_TRUE(f.second_rejected());
    f.input(marker, 4000);
    EXPECT_FALSE(f.second_rejected());
  }
}

TEST(SimCheckersInFlight, RejectedIngressCannotChangeDuplicateAckWindow) {
  for (unsigned stale : {0u, 1000u}) {
    ProbeFixture f(true, false, 2);
    f.input(1000, 1000);  // effective window 4000, as on the unscaled SYN
    EXPECT_TRUE(f.second_rejected());
    f.input(stale, 900, 0, {}, false);  // no accepted ACK trace
    f.input(1000, 1000);
    EXPECT_FALSE(f.second_rejected());
  }
}

TEST(SimCheckersInFlight, ProbeRequiresBilateralSack) {
  for (bool client : {false, true}) {
    for (bool server : {false, true}) {
      InFlightChecker c;
      handshake(c, 0, 0, 1000, iss_a, iss_b, client, server);
      auto p = tx_event(TxKind::tlp, 1, 10);
      p.ca = CaState::open;
      const auto v = c.on_trace(0, p);
      if (client && server) {
        EXPECT_FALSE(v);
      } else {
        ASSERT_TRUE(v);
        EXPECT_NE(v->find("negotiated SACK"), std::string::npos);
      }
    }
  }
}

TEST(SimCheckersInFlight, DisabledRackForbidsProbesForEitherReduction) {
  for (auto reduction : {RecoveryReduction::rfc6675, RecoveryReduction::prr}) {
    InFlightChecker c;
    handshake(c, 0, 0, 1000, iss_a, iss_b, true, true);
    TcpConfig config;
    config.recovery_reduction = reduction;
    config.rack_tlp = false;
    c.set_config(0, config);
    auto p = tx_event(TxKind::tlp, 1, 10);
    p.ca = CaState::open;
    auto v = c.on_trace(0, p);
    ASSERT_TRUE(v);
    EXPECT_NE(v->find("RACK-TLP disabled"), std::string::npos);
  }
}

TEST(SimCheckersInFlight, ProbeRequiresEligibleStateAndOnePacketAllowance) {
  for (auto state : {CaState::open, CaState::disorder, CaState::cwr, CaState::recovery, CaState::loss}) {
    InFlightChecker c;
    handshake(c, 0, 0, 1000, iss_a, iss_b, true, true);
    auto p = tx_event(TxKind::tlp, 12, 10);
    p.ca = state;
    EXPECT_TRUE(c.on_trace(0, p));
    p.in_flight = 11;
    EXPECT_EQ(c.on_trace(0, p).has_value(), state == CaState::recovery || state == CaState::loss);
  }
}

TraceEvent paced(unsigned time_us, bool start, unsigned id = 1) {
  TraceEvent e;
  e.conn_id = id;
  e.kind = TraceKind::tx;
  e.tx = TxKind::data;
  e.t = Time{static_cast<std::int64_t>(time_us) * 1000};
  e.len = 1000;
  e.gate_rate = 1'000'000;  // 1000 us per packet
  e.burst_start = start;
  return e;
}

TEST(SimCheckersPacing, StartupCrossingChargesWholeBurstAndCreditsLateness) {
  for (const bool early : {false, true}) {
    PacingChecker c;
    for (unsigned i = 0; i < 8; ++i) {
      ASSERT_FALSE(c.on_trace(0, paced(1000, i == 0)));
    }
    // Two packets together reach ten. The previous eight only stamped t=1000.
    ASSERT_FALSE(c.on_trace(0, paced(1000, true)));
    ASSERT_FALSE(c.on_trace(0, paced(1000, false)));
    EXPECT_FALSE(c.on_trace(1, paced(1000, true)));  // independent sender
    EXPECT_FALSE(c.on_trace(0, paced(1000, true, 2)));  // independent connection
    if (early) {
      EXPECT_TRUE(c.on_trace(0, paced(2998, true)));  // >1 us early
    } else {
      ASSERT_FALSE(c.on_trace(0, paced(3500, true)));  // 500 us late
      EXPECT_FALSE(c.on_trace(0, paced(4000, true)));  // 1000 us minus 500 us credit
    }
  }
}

TEST(SimCheckersPacing, ExactlyOneMicrosecondSlack) {
  for (const auto early_ns : {1000, 1001}) {
    PacingChecker c;
    for (unsigned i = 0; i < 8; ++i) ASSERT_FALSE(c.on_trace(0, paced(1000, i == 0)));
    ASSERT_FALSE(c.on_trace(0, paced(1000, true)));
    ASSERT_FALSE(c.on_trace(0, paced(1000, false)));
    auto e = paced(3000, true);
    e.t.ns -= early_ns;
    EXPECT_EQ(c.on_trace(0, e).has_value(), early_ns > 1000);
  }
}

TEST(SimCheckersPacing, KnownRateValidatesOrdinarySendsWithEitherStartupFormat) {
  for (bool fixed : {false, true}) {
    for (bool tagged_startup : {false, true}) {
      for (auto invalid_rate : {0u, 100'000'000u}) {
        PacingChecker c;
        TcpConfig config;
        config.pacing = Pacing::always;
        if (fixed) config.test_fixed_pacing_rate = 1'000'000;
        c.set_config(0, config);
        auto data = paced(1000, true);
        data.pacing_rate = fixed ? 7'000'000 : 1'000'000;
        for (unsigned i = 0; i < 10; ++i) {
          data.burst_start = tagged_startup && i == 0;
          data.gate_rate = tagged_startup ? 1'000'000 : 0;
          ASSERT_FALSE(c.on_trace(0, data));
        }
        data.t = Time{10'000'000};  // exactly the tagged startup burst's EDT
        data.burst_start = true;
        data.gate_rate = invalid_rate;
        EXPECT_TRUE(c.on_trace(0, data)) << fixed << tagged_startup << invalid_rate;
      }
    }
  }
}

TEST(SimCheckersPacing, UntaggedStartupAndTimerExemptions) {
  for (const auto kind : {TxKind::rto_rexmit, TxKind::tlp}) {
    PacingChecker c;
    for (unsigned i = 0; i < 10; ++i) {
      auto e = paced(100, false);
      e.gate_rate = 0;
      e.snd_nxt_off = i + 1;
      ASSERT_FALSE(c.on_trace(0, e));
    }
    auto data = paced(1000, true);
    data.snd_nxt_off = 1010;
    ASSERT_FALSE(c.on_trace(0, data));  // next EDT is 1500us (lateness credit)
    if (kind == TxKind::rto_rexmit) {
      auto rto = rto_expiry();
      rto.conn_id = 1;
      (void)c.on_trace(0, rto);
    }
    auto timer = paced(1200, true);
    timer.tx = kind;
    timer.snd_nxt_off = 1010;
    EXPECT_FALSE(c.on_trace(0, timer));  // exempt, but advances EDT by 1000us
    timer.tx = TxKind::tlp;
    timer.snd_nxt_off += 1000;
    timer.t = Time{2'498'000};
    EXPECT_TRUE(c.on_trace(0, timer));  // new-data probe
  }
}

TEST(SimCheckersPacing, EngineGateFaultIsReportedByWorld) {
  LinkParams link;
  link.delay = 10ms;
  link.rate_bps = 100'000'000;
  link.queue_bytes = 500'000;
  auto s = two_node_scenario(42, link, link);
  s.gen_version = 4;
  s.node[0].pacing = Pacing::always;
  ConnSpec c;
  c.bytes_c2s = 512 * 1024;
  s.conn.push_back(c);
  auto good = run_scenario(s);
  ASSERT_EQ(good.verdict, Verdict::ok);
  s.node[0].test_fault = TestFault::ignore_pacing_gate;
  const auto bad = run_scenario(s);
  ASSERT_EQ(bad.verdict, Verdict::pacing);
  ASSERT_FALSE(bad.violations.empty());
  EXPECT_NE(bad.violations.front().message.find("before EDT"), std::string::npos);
}

TEST(SimCheckersInFlight, OnlyTheHeadRtoRexmitIsExempt) {
  InFlightChecker c;
  // Without an RTO expiry an rto_rexmit is not a head retransmission.
  EXPECT_TRUE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 2, 1)).has_value());
  // After an expiry the first one is exempt, a second one is not.
  EXPECT_FALSE(c.on_trace(0, rto_expiry()));
  EXPECT_FALSE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 2, 1)));
  EXPECT_TRUE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 3, 1)).has_value());
  EXPECT_FALSE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 1, 1)));  // within cwnd: fine
  // The expiry can also come as the xmit timer firing as kind rto.
  TraceEvent fired;
  fired.kind = TraceKind::timer;
  fired.tuple = ab;
  fired.timer = TraceTimer::rto;
  fired.timer_op = TimerOp::armed;
  EXPECT_FALSE(c.on_trace(0, fired));
  EXPECT_TRUE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 2, 1)).has_value());  // armed is no expiry
  fired.timer_op = TimerOp::fired;
  EXPECT_FALSE(c.on_trace(0, fired));
  EXPECT_FALSE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 2, 1)));
  // An expiry of another connection exempts nothing here.
  TraceEvent other = rto_expiry();
  other.conn_id = 7;
  EXPECT_FALSE(c.on_trace(0, other));
  EXPECT_TRUE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 2, 1)).has_value());
  // An expiry that retransmitted the SYN leaves no exemption behind.
  EXPECT_FALSE(c.on_trace(0, rto_expiry()));
  TraceEvent syn_tx = tx_event(TxKind::syn, 1, 1);
  syn_tx.len = 0;
  EXPECT_FALSE(c.on_trace(0, syn_tx));
  EXPECT_TRUE(c.on_trace(0, tx_event(TxKind::rto_rexmit, 2, 1)).has_value());
}

// --- TerminationChecker.

class Conns {
public:
  // An RST that connection `id` on `node` sent.
  void rst(std::uint32_t node, std::uint32_t id, std::int64_t t_s) {
    TraceEvent e;
    e.kind = TraceKind::tx;
    e.tx = TxKind::rst;
    e.t = Time{t_s * 1'000'000'000};
    e.conn_id = id;
    e.tuple = node == 0 ? ab : ba;
    c.on_trace(node, e);
  }
  // A state event of connection `id` on `node`.
  void state(std::uint32_t node, std::uint32_t id, TcpState s, std::int64_t t_s,
             CloseCause cause = CloseCause::none, const FourTuple* tuple = nullptr) {
    TraceEvent e;
    e.kind = TraceKind::state;
    e.t = Time{t_s * 1'000'000'000};
    e.conn_id = id;
    e.tuple = tuple != nullptr ? *tuple : (node == 0 ? ab : ba);
    e.state = s;
    e.cause = cause;
    c.on_trace(node, e);
  }
  std::vector<Violation> finish() const { return c.finish(Time{1000 * 1'000'000'000LL}); }
  TerminationChecker c;
};

TEST(SimCheckersTermination, FinExchangeEndsAreLegal) {
  Conns k;
  k.state(0, 1, TcpState::syn_sent, 1);
  k.state(1, 1, TcpState::syn_received, 1);
  k.state(0, 1, TcpState::established, 2);
  k.state(1, 1, TcpState::established, 2);
  k.state(0, 1, TcpState::fin_wait_1, 3);
  k.state(1, 1, TcpState::close_wait, 3);
  k.state(0, 1, TcpState::fin_wait_2, 3);
  k.state(1, 1, TcpState::last_ack, 4);
  k.state(0, 1, TcpState::time_wait, 4);
  k.state(1, 1, TcpState::closed, 4, CloseCause::last_ack);
  k.state(0, 1, TcpState::closed, 64, CloseCause::time_wait_expired);
  EXPECT_TRUE(k.finish().empty());
  EXPECT_EQ(k.c.open_connections(), 0u);
}

TEST(SimCheckersTermination, RstAfterPeerTimeWaitExpiryIsLegal) {
  // a went through TIME_WAIT and expired; b, still in LAST-ACK (its FIN's
  // ACK was lost), retransmits the FIN and gets an RST.
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(1, 1, TcpState::established, 1);
  k.state(0, 1, TcpState::fin_wait_1, 2);
  k.state(1, 1, TcpState::close_wait, 2);
  k.state(0, 1, TcpState::fin_wait_2, 2);
  k.state(1, 1, TcpState::last_ack, 3);
  k.state(0, 1, TcpState::time_wait, 3);
  k.state(0, 1, TcpState::closed, 63, CloseCause::time_wait_expired);
  k.state(1, 1, TcpState::closed, 70, CloseCause::rst_received);
  EXPECT_TRUE(k.finish().empty());
}

TEST(SimCheckersTermination, RstWhilePeerOpenFires) {
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(1, 1, TcpState::established, 1);
  k.state(1, 1, TcpState::closed, 5, CloseCause::rst_received);
  k.state(0, 1, TcpState::closed, 9, CloseCause::time_wait_expired);
  const auto v = k.finish();
  ASSERT_EQ(v.size(), 1u);
  EXPECT_EQ(v[0].kind, Verdict::termination);
  EXPECT_NE(v[0].message.find("rst_received"), std::string::npos) << v[0].message;
}

TEST(SimCheckersTermination, RstInEstablishedAfterPeerTimeWaitFires) {
  // The peer's TIME_WAIT ended, but we were never in a closing state: the
  // RST is not an accepted end (only FIN-WAIT-1/2, CLOSING, LAST-ACK).
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(1, 1, TcpState::established, 1);
  k.state(0, 1, TcpState::time_wait, 2);
  k.state(0, 1, TcpState::closed, 62, CloseCause::time_wait_expired);
  k.state(1, 1, TcpState::closed, 70, CloseCause::rst_received);
  EXPECT_EQ(k.finish().size(), 1u);
}

TEST(SimCheckersTermination, OrphanFinWait2TimeoutIsLegal) {
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(1, 1, TcpState::established, 1);
  k.state(0, 1, TcpState::fin_wait_1, 2);
  k.state(1, 1, TcpState::close_wait, 2);
  k.state(0, 1, TcpState::fin_wait_2, 2);
  k.c.on_app_close(0, 1, Time{2'000'000'000});
  k.state(0, 1, TcpState::closed, 62, CloseCause::fin_wait2_timeout);
  // b closes later: its FIN draws an RST from a's side.
  k.state(1, 1, TcpState::last_ack, 100);
  k.state(1, 1, TcpState::closed, 100, CloseCause::rst_received);
  EXPECT_TRUE(k.finish().empty());
}

TEST(SimCheckersTermination, RstInCloseWaitAfterPeerOrphanTimeoutIsLegal) {
  // Sweep seed 3106: b shut down writing, its application closed later, and
  // the orphan timed out in FIN-WAIT-2 while a, in CLOSE-WAIT, still had data
  // to send; a's next segment drew an RST.
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(1, 1, TcpState::established, 1);
  k.state(1, 1, TcpState::fin_wait_1, 2);
  k.state(0, 1, TcpState::close_wait, 2);
  k.state(1, 1, TcpState::fin_wait_2, 2);
  k.c.on_app_close(1, 1, Time{10'000'000'000});
  k.state(1, 1, TcpState::closed, 70, CloseCause::fin_wait2_timeout);
  k.state(0, 1, TcpState::closed, 75, CloseCause::rst_received);
  EXPECT_TRUE(k.finish().empty());

  // Any other end of the peer does not explain an RST in CLOSE-WAIT.
  Conns tw;
  tw.state(0, 1, TcpState::established, 1);
  tw.state(1, 1, TcpState::established, 1);
  tw.state(0, 1, TcpState::close_wait, 2);
  tw.state(1, 1, TcpState::time_wait, 3);
  tw.state(1, 1, TcpState::closed, 63, CloseCause::time_wait_expired);
  tw.state(0, 1, TcpState::closed, 70, CloseCause::rst_received);
  const auto v = tw.finish();
  ASSERT_EQ(v.size(), 1u);
  EXPECT_NE(v[0].message.find("close_wait"), std::string::npos) << v[0].message;
}

TEST(SimCheckersTermination, FinWait2TimeoutNeedsAnOrphan) {
  // Only an orphan times out in FIN-WAIT-2 (§4.12); a connection whose
  // application still holds it waits for the peer's FIN.
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(0, 1, TcpState::fin_wait_1, 2);
  k.state(0, 1, TcpState::fin_wait_2, 2);
  k.state(0, 1, TcpState::closed, 62, CloseCause::fin_wait2_timeout);
  const auto v = k.finish();
  ASSERT_EQ(v.size(), 1u);
  EXPECT_NE(v[0].message.find("had not closed"), std::string::npos) << v[0].message;
  // An application close after the timeout does not make it an orphan.
  k.c.on_app_close(0, 1, Time{70'000'000'000});
  EXPECT_EQ(k.finish().size(), 1u);
}

TEST(SimCheckersTermination, TimedOutWhenSynchronizedNeedsRst) {
  // Retry exhaustion in a synchronized state sends RST (§4.8).
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(0, 1, TcpState::closed, 900, CloseCause::timed_out);
  const auto v = k.finish();
  ASSERT_EQ(v.size(), 1u);
  EXPECT_NE(v[0].message.find("without sending RST"), std::string::npos) << v[0].message;

  Conns sent;  // the RST may be traced before or after the state change
  sent.state(0, 1, TcpState::established, 1);
  sent.state(0, 1, TcpState::fin_wait_1, 2);
  sent.rst(0, 1, 900);
  sent.state(0, 1, TcpState::closed, 900, CloseCause::timed_out);
  sent.state(0, 2, TcpState::close_wait, 1);
  sent.state(0, 2, TcpState::closed, 900, CloseCause::timed_out);
  sent.rst(0, 2, 900);
  EXPECT_TRUE(sent.finish().empty());

  Conns other;  // another connection's RST does not count
  other.state(0, 1, TcpState::established, 1);
  other.rst(0, 2, 900);
  other.rst(1, 1, 900);
  other.state(0, 1, TcpState::closed, 900, CloseCause::timed_out);
  EXPECT_EQ(other.finish().size(), 1u);
}

TEST(SimCheckersTermination, TimedOutBeforeSynchronizedNeedsNoRst) {
  // SYN-SENT and an active open's SYN-RECEIVED give up silently.
  Conns k;
  k.state(0, 1, TcpState::syn_sent, 1);
  k.state(0, 1, TcpState::closed, 130, CloseCause::timed_out);
  k.state(0, 2, TcpState::syn_sent, 1);
  k.state(0, 2, TcpState::syn_received, 2);
  k.state(0, 2, TcpState::closed, 130, CloseCause::timed_out);
  EXPECT_TRUE(k.finish().empty());
}

TEST(SimCheckersTermination, FinWait2TimeoutOutsideFinWait2Fires) {
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(0, 1, TcpState::fin_wait_1, 2);
  k.state(0, 1, TcpState::closed, 62, CloseCause::fin_wait2_timeout);
  EXPECT_EQ(k.finish().size(), 1u);
}

TEST(SimCheckersTermination, SynReceivedChildExpiryIsLegal) {
  // b's child never got the final ACK: freed after synack_retries; a gave up
  // its SYN retries.
  Conns k;
  const FourTuple listen_tuple{eb, Endpoint{}};
  k.state(1, 1, TcpState::listen, 0, CloseCause::none, &listen_tuple);
  k.state(0, 1, TcpState::syn_sent, 1);
  k.state(1, 2, TcpState::syn_received, 1);
  k.state(1, 2, TcpState::closed, 64, CloseCause::synack_timed_out);
  k.state(0, 1, TcpState::closed, 130, CloseCause::timed_out);
  k.c.on_app_close(1, 1, Time{200'000'000'000});
  k.state(1, 1, TcpState::closed, 200, CloseCause::listener_closed, &listen_tuple);
  EXPECT_TRUE(k.finish().empty());
}

TEST(SimCheckersTermination, AbortNeedsApplicationClose) {
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(1, 1, TcpState::established, 1);
  k.c.on_app_close(0, 1, Time{5'000'000'000});
  k.state(0, 1, TcpState::closed, 5, CloseCause::aborted);
  k.state(1, 1, TcpState::closed, 6, CloseCause::rst_received);
  EXPECT_TRUE(k.finish().empty());

  Conns bad;
  bad.state(0, 1, TcpState::established, 1);
  bad.state(0, 1, TcpState::closed, 5, CloseCause::aborted);  // no application close
  EXPECT_EQ(bad.finish().size(), 1u);
}

TEST(SimCheckersTermination, RefusedOnlyWhenDesigned) {
  Conns k;
  k.c.set_design([](std::uint32_t, const FourTuple& t) -> std::optional<CloseMode> {
    return t.remote.port == 6000 ? std::optional{CloseMode::refused} : std::nullopt;
  });
  const FourTuple to6000{ea, Endpoint{eb.addr, 6000}};
  k.state(0, 1, TcpState::syn_sent, 1, CloseCause::none, &to6000);
  k.state(0, 1, TcpState::closed, 1, CloseCause::refused, &to6000);
  EXPECT_TRUE(k.finish().empty());
  k.state(0, 2, TcpState::syn_sent, 2);
  k.state(0, 2, TcpState::closed, 2, CloseCause::refused);
  EXPECT_EQ(k.finish().size(), 1u);
}

TEST(SimCheckersTermination, UnclosedAndCauselessFire) {
  Conns k;
  k.state(0, 1, TcpState::established, 1);
  k.state(0, 2, TcpState::syn_sent, 1);
  k.state(0, 2, TcpState::closed, 3, CloseCause::none);
  const auto v = k.finish();
  ASSERT_EQ(v.size(), 2u);
  EXPECT_NE(v[0].message.find("still in state established"), std::string::npos) << v[0].message;
  EXPECT_EQ(k.c.open_connections(), 1u);
}

TEST(SimCheckersTermination, RelaxedAcceptsAnyCauseButNotOpen) {
  Conns k;
  k.c.set_relaxed(true);
  k.state(0, 1, TcpState::established, 1);
  k.state(0, 1, TcpState::closed, 3, CloseCause::rst_received);
  EXPECT_TRUE(k.finish().empty());
  k.state(0, 2, TcpState::established, 4);
  EXPECT_EQ(k.finish().size(), 1u);
}

// --- QuiescenceChecker inputs and the progress bound.

TEST(SimCheckersQuiescence, UsageLeaks) {
  StackUsage u;
  u.pool_buffers = 64;
  u.pool_buffers_free = 64;
  u.chunks = 10;
  u.chunks_free = 10;
  u.stack_timers_armed = 1;  // pmtu_expiry may remain
  EXPECT_TRUE(usage_settled(u));
  EXPECT_FALSE(usage_leaks(u));
  u.tcp_slots = 1;
  u.pool_buffers_free = 63;
  const auto leak = usage_leaks(u);
  ASSERT_TRUE(leak.has_value());
  EXPECT_NE(leak->find("tcp_slots 1"), std::string::npos) << *leak;
  EXPECT_NE(leak->find("pool_buffers_in_use 1"), std::string::npos) << *leak;
  u.conn_timers_armed = 1;
  EXPECT_FALSE(usage_settled(u));
}

TEST(SimCheckersProgress, BoundFollowsTheRetryModel) {
  const TcpConfig c = tcp_config(ProfileId::linux_compat);
  // retry_abort_time(15, 200 ms, 120 s) = 924.6 s (Linux tcp_retries2 = 15),
  // plus TIME_WAIT 60 s and 120 s.
  EXPECT_EQ(progress_bound(c), Duration{924'600'000'000} + 60s + 120s);
  ProgressChecker p(progress_bound(c));
  p.on_progress(Time{5'000'000'000});
  EXPECT_EQ(p.deadline(), Time{5'000'000'000} + progress_bound(c));
}

TEST(SimCheckersStream, PatternBytesAndEof) {
  StreamChecker s(Seed::from_u64(1));
  const Pattern& p = s.tcp_pattern(3, 0);
  std::vector<std::byte> data(1000);
  p.fill(500, data);
  s.on_written(3, 0, 1500);
  EXPECT_FALSE(s.on_read(3, 0, 500, data));
  data[10] ^= std::byte{0x40};
  const auto v = s.on_read(3, 0, 500, data);
  ASSERT_TRUE(v.has_value());
  EXPECT_NE(v->find("offset 510"), std::string::npos) << *v;
  EXPECT_FALSE(s.on_eof(3, 0, 1500));
  EXPECT_TRUE(s.on_eof(3, 0, 1499).has_value());
  // Directions and connections differ.
  EXPECT_NE(s.tcp_pattern(3, 1).at(0), p.at(0));
  s.set_enabled(false);
  EXPECT_FALSE(s.on_read(3, 0, 500, data));
}

TEST(SimCheckersStream, UdpPayloads) {
  StreamChecker s(Seed::from_u64(2));
  std::vector<std::byte> d(300);
  s.udp_payload(1, 0, 42, d);
  EXPECT_FALSE(s.on_datagram(1, 0, d));
  EXPECT_TRUE(s.on_datagram(1, 1, d).has_value());
  d[200] ^= std::byte{1};
  EXPECT_TRUE(s.on_datagram(1, 0, d).has_value());
}

}  // namespace
}  // namespace utcp::sim
