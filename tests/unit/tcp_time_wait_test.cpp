// m1-tcp-core acceptance test 5: TIME-WAIT and the orphan FIN-WAIT-2 timeout
// (DESIGN §4.4 "TIME-WAIT receiving a SYN", §4.12; RFC 9293 §3.6.1, RFC 1337,
// RFC 6191; Linux tcp_timewait_state_process).
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "tcp_test_util.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::Handle;
using utcp::ProfileId;
using utcp::Seq32;
using utcp::StackConfig;
using utcp::TcpState;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;
using namespace utcp::test::tcpt;

std::string name(ProfileId p) { return p == ProfileId::rfc ? "rfc" : "linux_compat"; }

// A connection between the driven stack (listener on `port`) and a scripted
// peer, with the peer's view of both sequence spaces.
struct Conn {
  std::uint16_t peer_port = 0;
  Handle h;
  Seq32 nxt;    // the peer's next sequence number
  Seq32 their;  // the stack's next sequence number (the peer's RCV.NXT)
  bool ts = false;
  std::uint32_t tsval = 0;  // the peer's last TSval
  std::uint32_t their_ts = 0;  // the stack's last TSval
};

class Tw {
public:
  explicit Tw(ProfileId profile = ProfileId::linux_compat) : Tw(config(Side::b, profile)) {}
  explicit Tw(const StackConfig& cfg) : d_(cfg) {
    const auto l = d_.stack().tcp_listen(utcp::Endpoint{{}, port}, 16, {});
    EXPECT_TRUE(l.has_value());
    listener_ = l.value_or(Handle{});
  }
  Driven& d() { return d_; }
  utcp::Stack& stack() { return d_.stack(); }
  Handle listener() const { return listener_; }

  t::TcpSpec spec(const Conn& c, std::uint16_t flags) const {
    t::TcpSpec s(Driven::peer(c.peer_port), d_.local());
    s.seq = c.nxt;
    s.ack = c.their;
    s.flags = flags;
    s.window = 1000;
    if (c.ts) {
      s.opt.ts = w::Timestamps{c.tsval, c.their_ts};
    }
    return s;
  }
  // Takes the stack's output; returns the parsed segments and remembers the
  // stack's last TSval in `c`.
  std::vector<Parsed> out(Conn& c) {
    out_.clear();
    std::vector<Parsed> v;
    for (t::Bytes& b : d_.out()) {
      out_.push_back(std::move(b));
    }
    for (const t::Bytes& b : out_) {
      const auto p = parse(b);
      if (p) {
        if (p->v.opt.ts) {
          c.their_ts = p->v.opt.ts->val;
        }
        v.push_back(*p);
      }
    }
    return v;
  }

  // Peer-initiated handshake, accepted.
  std::optional<Conn> connect(std::uint16_t peer_port, bool ts, Seq32 isn = Seq32{10'000}) {
    Conn c;
    c.peer_port = peer_port;
    c.ts = ts;
    c.tsval = 5000;
    c.nxt = isn;
    t::TcpSpec syn = spec(c, w::tcp_syn);
    syn.ack = Seq32{};
    syn.opt.mss = 1460;
    syn.opt.wscale = 7;
    syn.opt.sack_permitted = true;
    if (ts) {
      syn.opt.ts = w::Timestamps{c.tsval, 0};
    }
    d_.send(syn);
    const auto sa = out(c);
    if (sa.size() != 1 || !is_synack(sa[0].v)) {
      return std::nullopt;
    }
    c.nxt = isn + 1;
    c.their = sa[0].v.h.seq + 1;
    ++c.tsval;
    d_.send(spec(c, w::tcp_ack));
    const auto h = stack().tcp_accept(listener_);
    if (!h) {
      return std::nullopt;
    }
    c.h = *h;
    return c;
  }

  // The stack closes first; the peer ACKs its FIN and sends its own: the
  // stack ends in TIME-WAIT. Returns the stack's last ACK.
  std::optional<Parsed> to_time_wait(Conn& c) {
    if (!stack().tcp_close(c.h)) {
      return std::nullopt;
    }
    const auto fin = out(c);
    if (fin.size() != 1 || !is_fin(fin[0].v)) {
      return std::nullopt;
    }
    c.their = fin[0].v.h.seq + 1;
    d_.run_for(10ms);
    ++c.tsval;
    d_.send(spec(c, w::tcp_ack | w::tcp_fin));
    c.nxt = c.nxt + 1;
    const auto ack = out(c);
    if (ack.size() != 1 || !is_pure_ack(ack[0].v)) {
      return std::nullopt;
    }
    return ack[0];
  }

private:
  Driven d_;
  Handle listener_;
  std::vector<t::Bytes> out_;  // backing store of the last out() views
};

// §3.9 time_wait: 60 s (linux_compat, TCP_TIMEWAIT_LEN) or 240 s (rfc, 2 MSL).
TEST(TcpTimeWait, LastsPerProfile) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Tw tw(profile);
    auto c = tw.connect(40000, true);
    ASSERT_TRUE(c);
    ASSERT_TRUE(tw.to_time_wait(*c));
    EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 1u);
    EXPECT_EQ(tw.stack().debug_usage().tcp_slots, 1u);  // the listener; the TCB is gone
    const Duration len = profile == ProfileId::rfc ? Duration{240s} : Duration{60s};
    tw.d().run_for(len - 1ns);
    EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 1u);
    tw.d().run_for(1ns);
    EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 0u);
    EXPECT_EQ(tw.stack().stats().TcpExtTW, 1u);
    EXPECT_TRUE(tw.d().out().empty());
    tw.stack().debug_check();
  }
}

// RFC 1337: rst_in_time_wait = accept (Linux tcp_rfc1337 = 0) ends TIME-WAIT
// at an in-window RST; ignore keeps it to the end.
TEST(TcpTimeWait, RstPerKnob) {
  for (const auto knob : {utcp::RstInTimeWait::accept, utcp::RstInTimeWait::ignore}) {
    SCOPED_TRACE(knob == utcp::RstInTimeWait::accept ? "accept" : "ignore");
    StackConfig cfg = config(Side::b);
    cfg.tcp.rst_in_time_wait = knob;
    Tw tw(cfg);
    auto c = tw.connect(40100, true);
    ASSERT_TRUE(c);
    ASSERT_TRUE(tw.to_time_wait(*c));
    tw.d().run_for(1s);
    t::TcpSpec rst(Driven::peer(c->peer_port), tw.d().local());
    rst.seq = c->nxt;  // RCV.NXT
    rst.flags = w::tcp_rst;
    tw.d().send(rst);
    EXPECT_TRUE(tw.d().out().empty());
    if (knob == utcp::RstInTimeWait::accept) {
      EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 0u);
    } else {
      EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 1u);
      tw.d().run_for(59s - 1ns);  // not restarted by the RST
      EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 1u);
      tw.d().run_for(1ns);
      EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 0u);
    }
    tw.stack().debug_check();
  }
}

// RFC 6191 / Linux tcp_timewait_state_process: a SYN with a newer TSval, or
// (equal TSval or no timestamps) a higher SEQ, reopens the tuple through the
// listener with ISS = old SND.NXT + 65537; an older one gets the TIME-WAIT
// ACK, as does any SYN when no listener holds the port.
TEST(TcpTimeWait, SynInTimeWait) {
  struct Case {
    const char* what;
    bool ts;
    int ts_delta;   // the SYN's TSval minus TS.Recent
    int seq_delta;  // the SYN's SEQ minus RCV.NXT
    bool listener;
    bool accepted;
  };
  const Case cases[] = {
      {"newer TSval, lower SEQ", true, 10, -1000, true, true},
      {"equal TSval, higher SEQ", true, 0, 1000, true, true},
      {"equal TSval, lower SEQ", true, 0, -1000, true, false},
      {"older TSval, higher SEQ", true, -10, 1000, true, false},
      {"no TS, higher SEQ", false, 0, 1000, true, true},
      {"no TS, lower SEQ", false, 0, -1000, true, false},
      {"newer TSval, no listener", true, 10, 1000, false, false},
  };
  std::uint16_t peer_port = 41000;
  for (const Case& k : cases) {
    SCOPED_TRACE(k.what);
    Tw tw;
    auto c = tw.connect(++peer_port, k.ts);
    ASSERT_TRUE(c);
    ASSERT_TRUE(tw.to_time_wait(*c));
    const Seq32 old_snd_nxt = c->their;
    if (!k.listener) {
      ASSERT_TRUE(tw.stack().tcp_close(tw.listener()));
    }
    tw.d().run_for(1s);
    t::TcpSpec syn(Driven::peer(peer_port), tw.d().local());
    syn.seq = c->nxt + static_cast<std::uint32_t>(k.seq_delta);
    syn.flags = w::tcp_syn;
    syn.opt.mss = 1460;
    if (k.ts) {
      syn.opt.ts = w::Timestamps{c->tsval + static_cast<std::uint32_t>(k.ts_delta), 0};
    }
    tw.d().send(syn);
    const auto o = tw.out(*c);
    ASSERT_EQ(o.size(), 1u);
    if (k.accepted) {
      ASSERT_TRUE(is_synack(o[0].v));
      EXPECT_EQ(o[0].v.h.seq, old_snd_nxt + 65537);
      EXPECT_EQ(o[0].v.h.ack, syn.seq + 1);
      EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 0u);
      // The new connection completes.
      t::TcpSpec ack(Driven::peer(peer_port), tw.d().local());
      ack.seq = syn.seq + 1;
      ack.ack = o[0].v.h.seq + 1;
      ack.flags = w::tcp_ack;
      if (k.ts) {
        ack.opt.ts = w::Timestamps{syn.opt.ts->val + 1, o[0].v.opt.ts->val};
      }
      tw.d().send(ack);
      const auto h = tw.stack().tcp_accept(tw.listener());
      ASSERT_TRUE(h);
      EXPECT_EQ(state(tw.stack(), *h), TcpState::established);
    } else {
      // The TIME-WAIT ACK: <SEQ=SND.NXT><ACK=RCV.NXT>.
      ASSERT_TRUE(is_pure_ack(o[0].v));
      EXPECT_EQ(o[0].v.h.seq, old_snd_nxt);
      EXPECT_EQ(o[0].v.h.ack, c->nxt);
      EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 1u);
    }
    tw.stack().debug_check();
  }
}

// §4.12: TIME-WAIT ACKs carry the window scaled as the connection's last ACK
// and a current TSval with TSecr = TS.Recent (which only an in-window segment
// at RCV.NXT updates, Linux tcp_timewait_state_process: here the peer's first
// FIN); a retransmitted FIN restarts the 2 MSL timer.
TEST(TcpTimeWait, AckCarriesScaledWindowAndTsval) {
  Tw tw;
  auto c = tw.connect(42000, true);
  ASSERT_TRUE(c);
  const auto last = tw.to_time_wait(*c);
  ASSERT_TRUE(last);
  ASSERT_TRUE(last->v.opt.ts);
  const std::uint16_t window = last->v.h.window;
  const std::uint32_t ts_before = last->v.opt.ts->val;
  EXPECT_GT(window, 0);
  tw.d().run_for(30s);
  // The peer's FIN again (it did not see our ACK, say).
  const std::uint32_t ts_recent = c->tsval;
  ++c->tsval;
  t::TcpSpec fin = tw.spec(*c, w::tcp_ack | w::tcp_fin);
  fin.seq = c->nxt - 1;
  tw.d().send(fin);
  const auto o = tw.out(*c);
  ASSERT_EQ(o.size(), 1u);
  ASSERT_TRUE(is_pure_ack(o[0].v));
  EXPECT_EQ(o[0].v.h.window, window);
  ASSERT_TRUE(o[0].v.opt.ts);
  EXPECT_EQ(o[0].v.opt.ts->val, ts_before + 30'000);  // 1 ms ticks
  EXPECT_EQ(o[0].v.opt.ts->ecr, ts_recent);
  EXPECT_EQ(o[0].v.h.ack, c->nxt);
  // Restarted: 60 s from the retransmitted FIN.
  tw.d().run_for(60s - 1ns);
  EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 1u);
  tw.d().run_for(1ns);
  EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 0u);
}

// §4.12: an orphan in FIN-WAIT-2 is freed silently after
// orphan_fin_wait2_timeout (60 s linux_compat, Linux tcp_fin_timeout; 240 s
// rfc); a connection the application still holds waits for the FIN.
TEST(TcpTimeWait, OrphanFinWait2Timeout) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Tw tw(profile);
    auto c = tw.connect(43000, true);
    ASSERT_TRUE(c);
    ASSERT_TRUE(tw.stack().tcp_close(c->h));
    const auto fin = tw.out(*c);
    ASSERT_EQ(fin.size(), 1u);
    c->their = fin[0].v.h.seq + 1;
    ++c->tsval;
    tw.d().send(tw.spec(*c, w::tcp_ack));  // ACK of the FIN, no FIN back
    EXPECT_TRUE(tw.out(*c).empty());
    EXPECT_EQ(tw.stack().debug_usage().tcp_slots, 2u);
    const Duration tmo = profile == ProfileId::rfc ? Duration{240s} : Duration{60s};
    tw.d().run_for(tmo - 1ns);
    EXPECT_EQ(tw.stack().debug_usage().tcp_slots, 2u);
    tw.d().run_for(1ns);
    EXPECT_EQ(tw.stack().debug_usage().tcp_slots, 1u);
    EXPECT_EQ(tw.stack().debug_usage().time_wait_entries, 0u);
    EXPECT_TRUE(tw.out(*c).empty());  // silently
    EXPECT_EQ(tw.stack().stats().TcpOutRsts, 0u);

    // Not an orphan: shutdown(write) only.
    auto c2 = tw.connect(43001, true);
    ASSERT_TRUE(c2);
    ASSERT_TRUE(tw.stack().tcp_shutdown(c2->h, utcp::Shutdown::write));
    const auto fin2 = tw.out(*c2);
    ASSERT_EQ(fin2.size(), 1u);
    c2->their = fin2[0].v.h.seq + 1;
    ++c2->tsval;
    tw.d().send(tw.spec(*c2, w::tcp_ack));
    tw.d().run_for(10 * tmo);
    EXPECT_EQ(state(tw.stack(), c2->h), TcpState::fin_wait_2);
    tw.stack().debug_check();
  }
}

}  // namespace
