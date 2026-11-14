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
// (TcpExtTCPACKSkippedSeq counts the rest); one 490 ms after the first ACK is
// still suppressed, one exactly 500 ms after it goes out (Linux
// __tcp_oow_rate_limited: elapsed < tcp_invalid_ratelimit is limited).
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
    c.d().run_for(390ms);  // 490 ms after the first ACK
    t::TcpSpec early = c.spec(w::tcp_ack);
    early.seq = c.nxt + far;
    c.send(early);
    EXPECT_EQ(pure_acks(c.out()), 0u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedSeq, 10u);
    c.d().run_for(10ms);  // 500 ms after the first ACK
    t::TcpSpec a = c.spec(w::tcp_ack);
    a.seq = c.nxt - 5000;  // below RCV.NXT
    c.send(a);
    EXPECT_EQ(pure_acks(c.out()), 1u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedSeq, 10u);
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
    // 490 ms after the first challenge ACK the next one is still suppressed;
    // exactly 500 ms after it, the next one is answered.
    c.d().run_for(390ms);
    t::TcpSpec early = c.spec(w::tcp_rst);
    early.seq = c.nxt + 1;
    c.send(early);
    EXPECT_EQ(pure_acks(c.out()), 0u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 2u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedChallenge, 10u);
    c.d().run_for(10ms);
    t::TcpSpec rst = c.spec(w::tcp_rst);
    rst.seq = c.nxt + 1;
    c.send(rst);
    EXPECT_EQ(pure_acks(c.out()), 1u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, 3u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedChallenge, 10u);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
    EXPECT_EQ(state(c.stack(), c2.h), TcpState::established);
    c.stack().debug_check();
  }
}

// RFC 5961 §7, §4.7: the limiter's data exemption is for duplicate ACKs
// only. A challenge ACK is limited whatever the segment carries (Linux
// tcp_send_challenge_ack, __tcp_oow_rate_limited): ten in-window RSTs with
// payload, ten data segments with SEG.ACK > SND.NXT and ten with SEG.ACK
// below SND.UNA - MAX.SND.WND, each burst within 100 ms, draw one ACK each.
TEST(TcpRfc5961, ChallengeAcksForSegmentsWithPayloadAreRateLimited) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    c.po.wscale = std::nullopt;  // MAX.SND.WND = 65535
    ASSERT_TRUE(c.accept());
    enum Kind { rst_data, ack_above, ack_below };
    std::uint64_t expect_challenges = 0;
    for (const Kind kind : {rst_data, ack_above, ack_below}) {
      SCOPED_TRACE(static_cast<int>(kind));
      std::size_t acks = 0;
      const std::uint64_t skipped0 = c.stack().stats().TcpExtTCPACKSkippedChallenge;
      for (int i = 0; i < 10; ++i) {
        t::TcpSpec s = c.spec(kind == rst_data ? w::tcp_rst : w::tcp_ack | w::tcp_psh);
        s.payload = t::pattern(kind == rst_data ? 1 : 100);
        if (kind == rst_data) {
          s.seq = c.nxt + 1;
        } else {
          s.ack = kind == ack_above ? c.their + 1000 : c.their - 70'000;
        }
        c.send(s);
        acks += pure_acks(c.out());
        c.d().run_for(10ms);
      }
      EXPECT_EQ(acks, 1u);
      ++expect_challenges;
      EXPECT_EQ(c.stack().stats().TcpExtTCPChallengeACK, expect_challenges);
      EXPECT_EQ(c.stack().stats().TcpExtTCPACKSkippedChallenge - skipped0, 9u);
      EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
      EXPECT_TRUE(drain(c.stack(), c.h).empty());
      c.d().run_for(500ms);  // past the limiter
    }
    // Duplicate data is still exempt (TcpRfc5961.DuplicateDataAlwaysAckedWithDsack).
    c.send_data(100);
    c.d().run_for(300ms);
    EXPECT_EQ(drain(c.stack(), c.h), t::pattern(100));
    c.stack().debug_check();
  }
}

// As built, Linux tcp_validate_incoming / tcp_reset_check (§4.4 step 3):
// once the peer's FIN is in (CLOSE-WAIT, LAST-ACK), an RST at RCV.NXT - 1,
// the FIN's own sequence number, resets although it lies left of the
// window. In ESTABLISHED the same RST is out of the window and dropped.
TEST(TcpRfc5961, RstAtTheFinSequenceResetsAfterThePeersFin) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    for (const bool last_ack : {false, true}) {
      SCOPED_TRACE(last_ack);
      Scripted c(profile);
      ASSERT_TRUE(c.accept());
      t::TcpSpec rst = c.spec(w::tcp_rst);
      rst.seq = c.nxt - 1;
      c.send(rst);
      EXPECT_TRUE(c.out().empty());
      EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
      c.send(c.spec(w::tcp_fin | w::tcp_ack));
      c.nxt = c.nxt + 1;
      c.d().run_for(10ms);
      (void)c.out();
      ASSERT_EQ(state(c.stack(), c.h), TcpState::close_wait);
      if (last_ack) {
        ASSERT_TRUE(c.stack().tcp_shutdown(c.h, utcp::Shutdown::write));
        const auto fin = c.out();
        ASSERT_EQ(fin.size(), 1u);
        EXPECT_TRUE(is_fin(fin[0].v));
        ASSERT_EQ(state(c.stack(), c.h), TcpState::last_ack);
      }
      rst = c.spec(w::tcp_rst);
      rst.seq = c.nxt - 1;
      c.send(rst);
      EXPECT_TRUE(c.out().empty());
      EXPECT_EQ(state(c.stack(), c.h), TcpState::closed);
      // CLOSE-WAIT: connection_reset; LAST-ACK closes without an error.
      if (last_ack) {
        EXPECT_EQ(c.stack().take_error(c.h), std::nullopt);
      } else {
        EXPECT_EQ(c.stack().take_error(c.h), Error::connection_reset);
      }
      c.stack().debug_check();
    }
  }
}

// As built, Linux tcp_validate_incoming (§4.4 step 3): with SACK, an RST at
// the right edge of the highest out-of-order block resets (the peer's
// SND.NXT when only a hole is missing); one inside the window elsewhere
// still draws a challenge ACK.
TEST(TcpRfc5961, RstAtTheHighestSackEdgeResets) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    for (const bool sack : {true, false}) {
      SCOPED_TRACE(sack);
      Scripted c(profile);
      c.po.sack = sack;
      ASSERT_TRUE(c.accept());
      t::TcpSpec ooo = c.spec(w::tcp_ack | w::tcp_psh);
      ooo.seq = c.nxt + 1000;
      ooo.payload = t::pattern(100);
      c.send(ooo);
      (void)c.out();  // the duplicate ACK
      c.d().run_for(600ms);
      t::TcpSpec rst = c.spec(w::tcp_rst);
      rst.seq = c.nxt + 1050;
      c.send(rst);
      EXPECT_EQ(pure_acks(c.out()), 1u);
      EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
      c.d().run_for(600ms);
      rst.seq = c.nxt + 1100;
      c.send(rst);
      if (sack) {
        EXPECT_TRUE(c.out().empty());
        EXPECT_EQ(state(c.stack(), c.h), TcpState::closed);
        EXPECT_EQ(c.stack().take_error(c.h), Error::connection_reset);
      } else {
        EXPECT_EQ(pure_acks(c.out()), 1u);
        EXPECT_EQ(state(c.stack(), c.h), TcpState::established);
      }
      c.stack().debug_check();
    }
  }
}

// §4.5 (Linux tcp_is_sackblock_valid, tcp_dsack_seen): a D-SACK block must
// lie inside [SND.UNA - MAX.SND.WND, SND.NXT] like any SACK block. One that
// reaches past SND.NXT, or starts below the lower bound, is discarded
// (TcpExtTCPSACKDiscard) and the ACK counts as one without D-SACK; a valid
// one below SND.UNA is counted.
TEST(TcpRfc5961, DsackOutsideTheSentRangeIsDiscarded) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    c.po.wscale = std::nullopt;  // MAX.SND.WND = 65535
    ASSERT_TRUE(c.accept());
    constexpr std::uint32_t total = 2920;  // two full segments: Nagle holds nothing back
    ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(total)));
    std::uint32_t sent = 0;
    for (const Parsed& p : c.out()) {
      sent += static_cast<std::uint32_t>(p.v.payload.size());
    }
    ASSERT_EQ(sent, total);
    // The peer acknowledges the first 1000 bytes.
    c.their = c.their + 1000;
    c.send(c.spec(w::tcp_ack));
    (void)c.out();
    const Seq32 una = c.their;
    struct Case {
      Seq32 b, e;
      bool valid;
    };
    const Case cases[] = {
        {una - 10, una + 0x1000'0000u, false},        // far past SND.NXT
        {una - 10, una + (total - 1000 + 1), false},  // one past SND.NXT
        {una - 70'000, una - 69'000, false},          // below SND.UNA - MAX.SND.WND
        {una - 100, una, true},                       // below SND.UNA: a real D-SACK
    };
    std::uint64_t discard = c.stack().stats().TcpExtTCPSACKDiscard;
    std::uint32_t dups = 0;
    for (const Case& k : cases) {
      SCOPED_TRACE(k.e.raw() - una.raw());
      t::TcpSpec a = c.spec(w::tcp_ack);
      a.opt.sack[0] = {k.b, k.e};
      a.opt.sack_count = 1;
      c.send(a);
      (void)c.out();
      dups += k.valid ? 1u : 0u;
      discard += k.valid ? 0u : 1u;
      EXPECT_EQ(c.stack().tcp_info(c.h)->dsack_dups, dups);
      EXPECT_EQ(c.stack().stats().TcpExtTCPSACKDiscard, discard);
      EXPECT_EQ(c.stack().stats().TcpExtTCPDSACKRecv, dups);
    }
    c.stack().debug_check();
  }
}

}  // namespace
