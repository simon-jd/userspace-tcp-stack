// m1-tcp-robust acceptance test 1: RFC 5961 (blind RST, SYN and data
// injection) and the out-of-window ACK limiter of DESIGN §4.4 and §4.7
// (Linux tcp_validate_incoming, tcp_oow_rate_limited), on a stack driven
// segment by segment by a scripted peer.
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "tcp_test_util.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Error;
using utcp::ProfileId;
using utcp::Seq32;
using utcp::TcpState;
namespace t = utcp::test;
namespace w = utcp::wire;
using namespace utcp::test::tcpt;

std::string name(ProfileId p) { return p == ProfileId::rfc ? "rfc" : "linux_compat"; }

constexpr std::uint32_t far = 0x40000000;  // far outside any window

std::size_t pure_acks(const std::vector<Parsed>& v) {
  std::size_t n = 0;
  for (const Parsed& p : v) {
    n += is_pure_ack(p.v) ? 1u : 0u;
  }
  return n;
}

// RFC 5961 §3.2: an RST at RCV.NXT resets, one elsewhere in the window draws
// a challenge ACK, one outside the window is dropped without a reply.
TEST(TcpRfc5961, RstRules) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept());
    t::TcpSpec rst = c.spec(w::tcp_rst);
    // Outside the window, above and below: silently dropped.
    for (const Seq32 seq : {c.nxt + far, c.nxt - 1000}) {
      rst.seq = seq;
      c.send(rst);
      EXPECT_TRUE(c.out().empty());
    }
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 0u);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    // In the window, not at RCV.NXT: a challenge ACK <SEQ=SND.NXT><ACK=RCV.NXT>.
    rst.seq = c.nxt + 1000;
    c.send(rst);
    const auto challenge = c.out();
    ASSERT_EQ(challenge.size(), 1u);
    EXPECT_TRUE(is_pure_ack(challenge[0].v));
    EXPECT_EQ(challenge[0].v.h.seq, c.their);
    EXPECT_EQ(challenge[0].v.h.ack, c.nxt);
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 1u);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    // At RCV.NXT: reset, no reply.
    rst.seq = c.nxt;
    c.send(rst);
    EXPECT_TRUE(c.out().empty());
    EXPECT_EQ(state(c.stack(), c.h), TcpState::closed);
    EXPECT_EQ(c.stack().take_error(c.h), Error::connection_reset);
    c.stack().debug_check();
  }
}

// RFC 5961 §4.2: a SYN in a synchronized state, in the window or not, gets a
// challenge ACK and changes nothing (Linux tcp_validate_incoming,
// syn_challenge).
TEST(TcpRfc5961, SynInEstablishedGetsChallengeAck) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept());
    for (const Seq32 seq : {c.nxt, c.nxt + far}) {
      t::TcpSpec syn = c.spec(w::tcp_syn);
      syn.ack = Seq32{};
      syn.seq = seq;
      syn.opt.mss = 1460;
      c.send(syn);
      const auto reply = c.out();
      ASSERT_EQ(reply.size(), 1u);
      EXPECT_TRUE(is_pure_ack(reply[0].v));
      EXPECT_EQ(reply[0].v.h.ack, c.nxt);
      c.d().run_for(600ms);  // past the limiter
    }
    EXPECT_EQ(c.stack().stats().TcpExtTCPSYNChallenge, 2u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 2u);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    c.send_data(100);
    c.d().run_for(300ms);
    EXPECT_EQ(drain(c.stack(), c.h).size(), 100u);
    c.stack().debug_check();
  }
}

// RFC 5961 §5.2, RFC 9293 §3.10.7.4: a segment acknowledging data never sent
// (SEG.ACK > SND.NXT) is ACKed and dropped, its payload with it.
TEST(TcpRfc5961, AckAboveSndNxtIsAckedAndDropped) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept());
    const Seq32 rcv_nxt = c.nxt;
    t::TcpSpec bad = c.spec(w::tcp_ack | w::tcp_psh);
    bad.ack = c.their + 1000;
    bad.payload = t::pattern(100);
    c.send(bad);
    const auto reply = c.out();
    ASSERT_EQ(reply.size(), 1u);
    EXPECT_TRUE(is_pure_ack(reply[0].v));
    EXPECT_EQ(reply[0].v.h.ack, rcv_nxt);
    EXPECT_TRUE(drain(c.stack(), c.h).empty());
    EXPECT_EQ(c.stack().tcp_info(c.h)->bytes_received, 0u);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    // The same bytes with a valid ACK are taken.
    c.send_data(100);
    c.d().run_for(300ms);
    EXPECT_EQ(drain(c.stack(), c.h), t::pattern(100));
    c.stack().debug_check();
  }
}

// RFC 5961 §5.2: SEG.ACK below SND.UNA - MAX.SND.WND draws a challenge ACK
// and the segment is dropped; an older ACK inside that bound is accepted and
// its payload taken.
TEST(TcpRfc5961, AckBelowMaxSndWndGetsChallengeAck) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    c.po.wscale = std::nullopt;  // MAX.SND.WND = 65535
    ASSERT_TRUE(c.accept());
    t::TcpSpec old = c.spec(w::tcp_ack | w::tcp_psh);
    old.ack = c.their - 65536;
    old.payload = t::pattern(100);
    c.send(old);
    const auto reply = c.out();
    ASSERT_EQ(reply.size(), 1u);
    EXPECT_TRUE(is_pure_ack(reply[0].v));
    EXPECT_EQ(reply[0].v.h.ack, c.nxt);
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 1u);
    EXPECT_TRUE(drain(c.stack(), c.h).empty());
    // SND.UNA - 65535 is the lowest acceptable ACK.
    old.ack = c.their - 65535;
    c.send(old);
    c.nxt = c.nxt + 100;
    c.d().run_for(300ms);
    EXPECT_EQ(drain(c.stack(), c.h), t::pattern(100));
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 1u);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    c.stack().debug_check();
  }
}

// §4.7 limiter: ten out-of-window pure ACKs within 100 ms draw one ACK
// (TcpExtTCPACKSkippedSeq counts the rest); after 500 ms another goes out.
TEST(TcpRfc5961, OutOfWindowPureAcksAreRateLimited) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept());
    std::size_t acks = 0;
    for (int i = 0; i < 10; ++i) {
      t::TcpSpec a = c.spec(w::tcp_ack);
      a.seq = c.nxt + far;
      c.send(a);
      acks += pure_acks(c.out());
      c.d().run_for(10ms);
    }
    EXPECT_EQ(acks, 1u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedSeq, 9u);
    c.d().run_for(500ms);
    t::TcpSpec a = c.spec(w::tcp_ack);
    a.seq = c.nxt - 5000;  // below RCV.NXT
    c.send(a);
    EXPECT_EQ(pure_acks(c.out()), 1u);
    c.stack().debug_check();
  }
}

// §4.7: segments with payload are exempt from the limiter (Linux
// tcp_oow_rate_limited), so ten duplicates within 100 ms draw ten ACKs, each
// reporting the duplicate in a D-SACK block (RFC 2883 §4).
TEST(TcpRfc5961, DuplicateDataAlwaysAckedWithDsack) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept());
    const Seq32 first = c.nxt;
    c.send_data(100);
    c.d().run_for(300ms);
    (void)c.out();
    for (int i = 0; i < 10; ++i) {
      t::TcpSpec dup = c.spec(w::tcp_ack | w::tcp_psh);
      dup.seq = first;
      dup.payload = t::pattern(100);
      c.send(dup);
      const auto reply = c.out();
      ASSERT_EQ(reply.size(), 1u) << i;
      EXPECT_TRUE(is_pure_ack(reply[0].v));
      EXPECT_EQ(reply[0].v.h.ack, c.nxt);
      ASSERT_GE(reply[0].v.opt.sack_count, 1u);
      EXPECT_EQ(reply[0].v.opt.sack[0].first, first);
      EXPECT_EQ(reply[0].v.opt.sack[0].second, first + 100);
      c.d().run_for(10ms);
    }
    EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedSeq, 0u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPDSACKOldSent, 10u);
    EXPECT_EQ(drain(c.stack(), c.h).size(), 100u);
    c.stack().debug_check();
  }
}

// RFC 5961 §7: at most one challenge ACK per 500 ms per connection, the
// limiter shared with ACKs to out-of-window segments (Linux
// last_oow_ack_time), and no stack-wide limit: another connection gets its
// own challenge ACK at the same moment.
TEST(TcpRfc5961, ChallengeAcksLimitedPerConnection) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept());
    Scripted c2(c);
    c2.peer_port = 40001;
    ASSERT_TRUE(c2.accept(Seq32{70'000}));
    std::size_t acks = 0;
    for (int i = 0; i < 10; ++i) {
      t::TcpSpec rst = c.spec(w::tcp_rst);
      rst.seq = c.nxt + 1;
      c.send(rst);
      acks += pure_acks(c.out());
      c.d().run_for(10ms);
    }
    EXPECT_EQ(acks, 1u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 1u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedChallenge, 9u);
    // Shared with out-of-window ACKs on the same connection.
    t::TcpSpec oow = c.spec(w::tcp_ack);
    oow.seq = c.nxt + far;
    c.send(oow);
    EXPECT_TRUE(c.out().empty());
    EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedSeq, 1u);
    // The other connection is not limited.
    t::TcpSpec rst2 = c2.spec(w::tcp_rst);
    rst2.seq = c2.nxt + 1;
    c2.send(rst2);
    const auto reply2 = c2.out();
    ASSERT_EQ(reply2.size(), 1u);
    EXPECT_EQ(reply2[0].v.h.ack, c2.nxt);
    EXPECT_EQ(reply2[0].v.h.dport, 40001);
    // 500 ms after the first, the next one is answered.
    c.d().run_for(500ms);
    t::TcpSpec rst = c.spec(w::tcp_rst);
    rst.seq = c.nxt + 1;
    c.send(rst);
    EXPECT_EQ(pure_acks(c.out()), 1u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 3u);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    EXPECT_EQ(state(c.stack(), c2.h), TcpState::established);
    c.stack().debug_check();
  }
}

}  // namespace
