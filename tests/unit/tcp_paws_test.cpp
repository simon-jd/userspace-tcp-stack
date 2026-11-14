// m1-tcp-robust acceptance test 2: PAWS, TS.Recent and TSecr validation
// (DESIGN §4.4 steps 0, 1 and 6, §4.8; RFC 7323 §4.3, §5.3), on a stack
// driven segment by segment. The RFC 5961 rules are in tcp_rfc5961_test.cpp.
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>

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

// RFC 7323 §5.3 R1: a data segment whose TSval is older than TS.Recent is
// dropped and ACKed, and counted (TcpExtPAWSEstab).
TEST(TcpPaws, OldTsvalDataDroppedAndAcked) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    c.po.ts = true;
    ASSERT_TRUE(c.accept());
    c.tsval += 10;
    c.send_data(100);
    c.d().run_for(1s);
    (void)c.out();
    const Seq32 rcv_nxt = c.nxt;
    c.tsval -= 5;
    c.send_data(100);
    const auto reply = c.out();
    ASSERT_EQ(reply.size(), 1u);
    EXPECT_TRUE(is_pure_ack(reply[0].v));
    EXPECT_EQ(reply[0].v.h.ack, rcv_nxt);
    EXPECT_EQ(drain(c.stack(), c.h).size(), 100u);
    EXPECT_EQ(c.stack().stats().TcpExtPAWSEstab, 1u);
    c.stack().debug_check();
  }
}

// §3.9 paws_disordered_ack: a pure duplicate ACK at RCV.NXT, window unchanged,
// whose TSval is a few ms older than TS.Recent (reordered behind a newer
// ACK) is kept with its SACK block under linux (tcp_disordered_ack) and
// dropped under strict (RFC 7323 R1).
TEST(TcpPaws, DisorderedDupAckPerProfile) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    c.po.ts = true;
    ASSERT_TRUE(c.accept());
    const std::uint32_t mss = c.stack().tcp_info(c.h)->snd_mss;
    ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(3 * std::size_t{mss})));
    const auto data = c.out();
    ASSERT_EQ(data.size(), 3u);
    const Seq32 third = data[2].v.h.seq;
    const auto third_end = third + static_cast<std::uint32_t>(data[2].v.payload.size());
    c.tsval += 10;
    c.send(c.spec(w::tcp_ack));  // a duplicate ACK; TS.Recent = tsval
    t::TcpSpec late = c.spec(w::tcp_ack);
    late.opt.ts->val = c.tsval - 5;
    late.opt.sack[0] = {third, third_end};
    late.opt.sack_count = 1;
    c.send(late);
    if (profile == ProfileId::linux_compat) {
      EXPECT_EQ(c.stack().stats().TcpExtPAWSEstab, 0u);
      EXPECT_EQ(c.stack().tcp_info(c.h)->sacked, 1u);
    } else {
      EXPECT_EQ(c.stack().stats().TcpExtPAWSEstab, 1u);
      EXPECT_EQ(c.stack().tcp_info(c.h)->sacked, 0u);
    }
    c.stack().debug_check();
  }
}

// RFC 7323 §5.5: TS.Recent older than 24 days is invalid, so an old TSval
// passes after a long idle period.
TEST(TcpPaws, TsRecentOlderThan24DaysIsIgnored) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    c.po.ts = true;
    ASSERT_TRUE(c.accept());
    c.d().run_for(std::chrono::hours{25 * 24});
    (void)c.out();
    c.tsval -= 1000;
    c.send_data(100);
    EXPECT_EQ(drain(c.stack(), c.h).size(), 100u);
    EXPECT_EQ(c.stack().stats().TcpExtPAWSEstab, 0u);
  }
}

// TS.Recent moves only for a segment that passed every check (Linux updates
// it in tcp_ack): an in-window SYN (challenge ACK, RFC 5961 §4.2) or an ACK
// above SND.NXT (RFC 5961 §5.2) with a far newer TSval must not, or every
// later legitimate segment would fail PAWS.
TEST(TcpPaws, RejectedSegmentsLeaveTsRecent) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    for (const bool syn : {true, false}) {
      SCOPED_TRACE(name(profile) + (syn ? " SYN" : " ACK above SND.NXT"));
      Scripted c(profile);
      c.po.ts = true;
      ASSERT_TRUE(c.accept());
      t::TcpSpec bad = c.spec(syn ? w::tcp_syn : w::tcp_ack);
      if (syn) {
        bad.ack = Seq32{};
      } else {
        bad.ack = c.their + 100'000;
      }
      bad.opt.ts->val = c.tsval + (1u << 30);
      c.send(bad);
      const auto challenge = c.out();
      ASSERT_EQ(challenge.size(), 1u);
      EXPECT_TRUE(is_pure_ack(challenge[0].v));
      EXPECT_EQ(challenge[0].v.h.ack, c.nxt);
      c.tsval += 5;
      c.send_data(100);
      EXPECT_EQ(drain(c.stack(), c.h).size(), 100u);
      EXPECT_EQ(c.stack().stats().TcpExtPAWSEstab, 0u);
      EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    }
  }
}

// RFC 5961 §3.2: an RST inside the window but not at RCV.NXT draws a
// challenge ACK and leaves the connection; one at RCV.NXT resets it.
TEST(TcpPaws, InWindowRstGetsChallengeAck) {
  Scripted c;
  ASSERT_TRUE(c.accept());
  t::TcpSpec rst = c.spec(w::tcp_rst);
  rst.seq = c.nxt + 1;
  c.send(rst);
  const auto reply = c.out();
  ASSERT_EQ(reply.size(), 1u);
  EXPECT_TRUE(is_pure_ack(reply[0].v));
  EXPECT_EQ(reply[0].v.h.ack, c.nxt);
  EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 1u);
  EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
  rst.seq = c.nxt;
  c.send(rst);
  EXPECT_TRUE(c.out().empty());
  EXPECT_EQ(state(c.stack(), c.h), TcpState::closed);
  EXPECT_EQ(c.stack().take_error(c.h), Error::connection_reset);
}

// §4.4 step 0 (Linux tcp_check_req): only a retransmitted SYN that passes
// PAWS resends the SYN-ACK. An old duplicate with the same IRS and an older
// TSval takes the PAWS path (an ACK, counted); a real retransmission later
// still gets the SYN-ACK.
TEST(TcpPaws, SynRetransmissionMustPassPaws) {
  Driven d;
  ASSERT_TRUE(d.stack().tcp_listen(utcp::Endpoint{{}, port}, 4, {}));
  t::TcpSpec syn(Driven::peer(40000), d.local());
  syn.seq = Seq32{1000};
  syn.flags = w::tcp_syn;
  syn.opt.mss = 1460;
  syn.opt.ts = w::Timestamps{1000, 0};
  d.send(syn);
  auto first = d.out();
  ASSERT_EQ(first.size(), 1u);
  ASSERT_TRUE(is_synack(parse(first[0])->v));
  d.run_for(300ms);
  syn.opt.ts = w::Timestamps{900, 0};
  d.send(syn);
  const auto old = d.out();
  ASSERT_EQ(old.size(), 1u);
  EXPECT_TRUE(is_pure_ack(parse(old[0])->v));
  EXPECT_EQ(d.stack().stats().TcpExtPAWSEstab, 1u);
  EXPECT_EQ(d.stack().stats().TcpExtTCPSynRetrans, 0u);
  d.run_for(600ms);  // past the oow limit, before the SYN-ACK timer (1 s)
  syn.opt.ts = w::Timestamps{1001, 0};
  d.send(syn);
  const auto again = d.out();
  ASSERT_EQ(again.size(), 1u);
  EXPECT_TRUE(is_synack(parse(again[0])->v));
  d.stack().debug_check();
}

// RFC 7323 §4.3 (2), §5.3 R3: TS.Recent takes SEG.TSval only from a segment
// with SEG.TSval >= TS.Recent and SEG.SEQ <= Last.ACK.sent that passes every
// check. An in-window RST (old or new TSval: RSTs skip PAWS) draws a
// challenge ACK and leaves it; so does out-of-order data above
// Last.ACK.sent. In-order data with an equal or newer TSval moves it. The
// stack's TSecr shows TS.Recent.
TEST(TcpPaws, TsRecentUpdateRule) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    c.po.ts = true;
    ASSERT_TRUE(c.accept());
    c.tsval += 10;
    c.send_data(100);
    c.d().run_for(300ms);
    auto acks = c.out();
    ASSERT_EQ(acks.size(), 1u);
    const std::uint32_t recent = c.tsval;
    ASSERT_EQ(acks[0].v.opt.ts->ecr, recent);
    std::uint32_t delta = 0;
    for (const std::uint32_t val : {recent - 3, recent + 1000}) {
      c.d().run_for(600ms);  // past the challenge-ACK limiter
      t::TcpSpec rst = c.spec(w::tcp_rst);
      rst.seq = c.nxt + 10;
      rst.opt.ts->val = val;
      c.send(rst);
      const auto reply = c.out();
      ASSERT_EQ(reply.size(), 1u) << delta;
      EXPECT_TRUE(is_pure_ack(reply[0].v));
      EXPECT_EQ(reply[0].v.opt.ts->ecr, recent);
      ++delta;
    }
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 2u);
    // Out-of-order data (SEG.SEQ > Last.ACK.sent) with a newer TSval: the
    // immediate duplicate ACK still echoes the old TS.Recent.
    t::TcpSpec ooo = c.spec(w::tcp_ack | w::tcp_psh);
    ooo.seq = c.nxt + 100;
    ooo.opt.ts->val = recent + 50;
    ooo.payload = t::pattern(100);
    c.send(ooo);
    acks = c.out();
    ASSERT_EQ(acks.size(), 1u);
    EXPECT_EQ(acks[0].v.opt.ts->ecr, recent);
    EXPECT_EQ(acks[0].v.h.ack, c.nxt);
    // In-order data with an equal TSval keeps it, a newer one moves it.
    c.tsval = recent;
    c.send_data(100);  // fills the hole: ACKed at once
    acks = c.out();
    ASSERT_EQ(acks.size(), 1u);
    EXPECT_EQ(acks[0].v.opt.ts->ecr, recent);
    c.nxt = c.nxt + 100;  // the out-of-order 100 bytes are now in order
    c.tsval = recent + 60;
    c.send_data(100);
    c.d().run_for(300ms);
    acks = c.out();
    ASSERT_EQ(acks.size(), 1u);
    EXPECT_EQ(acks[0].v.opt.ts->ecr, recent + 60);
    EXPECT_EQ(drain(c.stack(), c.h).size(), 400u);
    EXPECT_EQ(c.stack().stats().TcpExtPAWSEstab, 0u);
    c.stack().debug_check();
  }
}

// RFC 7323 §4 and Linux tcp_rtt_tsopt_us: the TSecr fallback (all newly
// acked data was retransmitted, so Karn leaves no sequence sample) takes no
// sample from a TSecr of 0 or one ahead of our clock: SRTT stays and the RTO
// keeps its backoff (RFC 6298 §5.7 resets it only on a valid sample). A
// valid TSecr gives the sample and resets the backoff.
TEST(TcpPaws, TsecrZeroOrAheadGivesNoRttSample) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    for (int mode = 0; mode < 3; ++mode) {
      SCOPED_TRACE(name(profile) + (mode == 0 ? " TSecr 0" : mode == 1 ? " ahead" : " valid"));
      Scripted c(profile);
      c.po.ts = true;
      ASSERT_TRUE(c.accept());
      const auto before = *c.stack().tcp_info(c.h);
      ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(100)));
      ASSERT_EQ(c.out().size(), 1u);
      c.d().run_for(before.rto);
      const auto rexmit = c.out();
      ASSERT_EQ(rexmit.size(), 1u);
      ASSERT_EQ(rexmit[0].v.payload.size(), 100u);
      const auto backed_off = *c.stack().tcp_info(c.h);
      EXPECT_EQ(backed_off.rto, 2 * before.rto);
      c.d().run_for(50ms);
      c.their = c.their + 100;
      ++c.tsval;
      t::TcpSpec ack = c.spec(w::tcp_ack);
      ack.opt.ts->ecr = mode == 0 ? 0u : mode == 1 ? c.their_ts + 100'000 : c.their_ts;
      c.send(ack);
      const auto after = *c.stack().tcp_info(c.h);
      EXPECT_EQ(after.unacked, 0u);
      if (mode < 2) {
        EXPECT_EQ(after.srtt, before.srtt);
        EXPECT_EQ(after.rttvar, before.rttvar);
        EXPECT_EQ(after.rto, backed_off.rto);
      } else {
        EXPECT_NE(after.srtt, before.srtt);
        EXPECT_LT(after.rto, backed_off.rto);
      }
      c.stack().debug_check();
    }
  }
}

}  // namespace
