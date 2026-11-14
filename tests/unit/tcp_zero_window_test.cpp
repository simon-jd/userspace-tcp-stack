// m1-tcp-robust acceptance test 3: zero-window probing, the sender SWS
// override and zero-window acceptance (DESIGN §4.4 step 2, §4.8, §4.9;
// RFC 9293 §3.8.6.1, §3.8.6.2.1, §3.10.7.4; Linux tcp_probe_timer,
// tcp_write_wakeup, tcp_xmit_probe_skb, tcp_data_queue).
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "tcp_test_util.hpp"
#include "utcp/trace.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::Endpoint;
using utcp::Error;
using utcp::ProfileId;
using utcp::Seq32;
using utcp::StackConfig;
using utcp::TcpState;
using utcp::Time;
using utcp::TraceKind;
using utcp::TxKind;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;
using namespace utcp::test::tcpt;

std::string name(ProfileId p) { return p == ProfileId::rfc ? "rfc" : "linux_compat"; }

class Sink : public utcp::TraceSink {
public:
  void on_event(const utcp::TraceEvent& e) override {
    if (e.kind == TraceKind::rto) {
      ++rto_events;
    } else if (e.kind == TraceKind::tx) {
      txs.push_back(e.tx);
    }
  }
  std::size_t count(TxKind k) const {
    return static_cast<std::size_t>(std::count(txs.begin(), txs.end(), k));
  }
  std::size_t rto_events = 0;
  std::vector<TxKind> txs;
};

StackConfig traced(ProfileId profile) {
  StackConfig c = config(Side::b, profile);
  c.trace_mask = utcp::trace_bit(TraceKind::tx) | utcp::trace_bit(TraceKind::rto);
  return c;
}

// The probe times of a stack facing a closed window for `d`; each probe is
// answered with a window-0 ACK if `answer`. Stops at an RST.
struct Probing {
  std::vector<Time> probes;
  std::optional<Time> rst;
  std::size_t data = 0;
};

Probing probe_for(Scripted& c, Duration d, bool answer) {
  Probing r;
  const Time end = c.d().now() + d;
  while (c.d().now() < end && !r.rst) {
    // Step to the stack's next deadline, so send times are exact.
    const Time next = std::min(std::max(c.stack().next_deadline(), c.d().now()), end);
    c.d().run_for(next - c.d().now());
    for (const Parsed& p : c.out()) {
      if (is_rst(p.v)) {
        r.rst = c.d().now();
      } else if (is_data(p.v)) {
        ++r.data;
      } else {
        EXPECT_TRUE(is_pure_ack(p.v));
        EXPECT_EQ(p.v.h.seq, c.their - 1);  // <SEQ=SND.UNA-1>
        EXPECT_EQ(p.v.h.ack, c.nxt);
        r.probes.push_back(c.d().now());
        if (answer) {
          c.send(c.spec(w::tcp_ack));
        }
      }
    }
  }
  return r;
}

// §4.9: with data queued and a zero window the persist timer sends
// zero-length probes <SEQ=SND.UNA-1> at the RTO, doubling up to rto_max.
// Answered by window-0 ACKs they never abort (RFC 1122 §4.2.2.17), and as
// they carry no data they leave cwnd and ssthresh alone and are never
// rto_rexmit.
TEST(TcpZeroWindow, ProbesDoubleToRtoMaxAndNeverAbortWhenAnswered) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(traced(profile));
    Sink sink;
    c.stack().set_trace_sink(&sink);
    ASSERT_TRUE(c.accept(Seq32{10'000}, 0));  // the completing ACK closes the window
    const StackConfig& cfg = c.stack().config();
    const auto i0 = *c.stack().tcp_info(c.h);
    const Time t0 = c.d().now();
    ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(1000)));
    EXPECT_TRUE(c.out().empty());
    const Probing r = probe_for(c, 2000s, true);
    EXPECT_FALSE(r.rst.has_value());
    EXPECT_EQ(r.data, 0u);
    // More probes than data_retries, all answered.
    ASSERT_GT(r.probes.size(), std::size_t{cfg.tcp.data_retries} + 2);
    Duration expect = i0.rto;
    Time prev = t0;
    for (std::size_t k = 0; k < r.probes.size(); ++k) {
      EXPECT_EQ(r.probes[k] - prev, expect) << "probe " << k;
      prev = r.probes[k];
      expect = std::min(2 * expect, cfg.tcp.rto_max);
    }
    EXPECT_EQ(expect, cfg.tcp.rto_max);
    const auto i1 = *c.stack().tcp_info(c.h);
    EXPECT_EQ(i1.state, TcpState::established);
    EXPECT_EQ(i1.cwnd, i0.cwnd);
    EXPECT_EQ(i1.ssthresh, i0.ssthresh);
    EXPECT_EQ(i1.ca_state, utcp::CaState::open);
    EXPECT_EQ(i1.unacked, 0u);
    EXPECT_EQ(sink.count(TxKind::zwp), r.probes.size());
    EXPECT_EQ(sink.count(TxKind::rto_rexmit), 0u);
    EXPECT_EQ(sink.rto_events, 0u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPWinProbe, r.probes.size());
    EXPECT_EQ(c.stack().stats().TcpExtTCPTimeouts, 0u);
    // The window opens: the data goes out at once.
    c.window = 65535;
    c.send(c.spec(w::tcp_ack));
    const auto sent = c.out();
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].v.payload.size(), 1000u);
    c.stack().set_trace_sink(nullptr);
    c.stack().debug_check();
  }
}

// §4.8: unanswered probes count against data_retries (Linux tcp_probe_timer:
// icsk_probes_out >= tcp_retries2): after data_retries probes the next expiry
// aborts with an RST and timed_out.
TEST(TcpZeroWindow, UnansweredProbesAbortAfterDataRetries) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    ASSERT_TRUE(c.accept(Seq32{10'000}, 0));
    const StackConfig& cfg = c.stack().config();
    const Duration rto0 = c.stack().tcp_info(c.h)->rto;
    ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(1000)));
    const Probing r = probe_for(c, 3000s, false);
    ASSERT_TRUE(r.rst.has_value());
    ASSERT_EQ(r.probes.size(), std::size_t{cfg.tcp.data_retries});
    // The abort comes one (backed-off) interval after the last probe.
    const Duration last = std::min(rto0 * (1 << cfg.tcp.data_retries), cfg.tcp.rto_max);
    EXPECT_EQ(*r.rst - r.probes.back(), last);
    EXPECT_EQ(c.stack().take_error(c.h), Error::timed_out);
    EXPECT_EQ(c.stack().stats().TcpExtTCPAbortOnTimeout, 1u);
    c.stack().debug_check();
  }
}

// RFC 9293 §3.8.6.2.1: a usable window below the sender SWS threshold (less
// than an MSS and less than max_snd_wnd / 2) sends nothing until the persist
// timer, which then sends min(D, U) bytes inside the window (Linux
// tcp_write_wakeup); that data then has the RTO. No segment ever passes the
// peer's right edge.
TEST(TcpZeroWindow, SwsOverrideSendsWhatTheWindowTakes) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    Scripted c(profile);
    c.po.wscale = std::nullopt;
    ASSERT_TRUE(c.accept(Seq32{10'000}, 0));
    const Duration rto0 = c.stack().tcp_info(c.h)->rto;
    const t::Bytes data = t::pattern(2000, 3);
    ASSERT_TRUE(c.stack().tcp_send(c.h, data));
    // Three zero-window probes build up the probing backoff.
    std::vector<Time> probes;
    for (int ms = 0; ms < 60'000 && probes.size() < 3; ++ms) {
      c.d().run_for(1ms);
      for (const Parsed& p : c.out()) {
        ASSERT_FALSE(is_data(p.v));
        probes.push_back(c.d().now());
        c.send(c.spec(w::tcp_ack));
      }
    }
    ASSERT_EQ(probes.size(), 3u);
    // The window opens to 300 bytes: below an MSS and below max_snd_wnd / 2,
    // so the sender SWS rule holds the data until the persist timer.
    c.window = 300;
    c.send(c.spec(w::tcp_ack));
    EXPECT_TRUE(c.out().empty());
    const Time t1 = c.d().now();
    std::vector<Parsed> seg;
    for (int ms = 0; ms < 60'000 && seg.empty(); ++ms) {
      c.d().run_for(1ms);
      seg = c.out();
    }
    ASSERT_EQ(seg.size(), 1u);
    EXPECT_EQ(c.d().now() - t1, 8 * rto0);  // the backed-off persist interval
    EXPECT_EQ(seg[0].v.h.seq, c.their);
    EXPECT_EQ(seg[0].v.payload.size(), 300u);
    // The data is in flight: the RTO, without the probing backoff, resends
    // it (Linux tcp_send_probe0).
    c.d().run_for(rto0 - 1ms);
    EXPECT_TRUE(c.out().empty());
    c.d().run_for(1ms);
    const auto again = c.out();
    ASSERT_EQ(again.size(), 1u);
    EXPECT_EQ(again[0].v.h.seq, c.their);
    EXPECT_EQ(again[0].v.payload.size(), 300u);
    // The peer takes each segment with the window kept at 300 bytes; the
    // rest goes out 300 bytes at a time, each inside the window.
    t::Bytes got(seg[0].v.payload.begin(), seg[0].v.payload.end());
    c.their = c.their + 300;
    c.send(c.spec(w::tcp_ack));
    for (int ms = 0; ms < 60'000 && got.size() < data.size(); ms += 10) {
      c.d().run_for(10ms);
      for (const Parsed& p : c.out()) {
        if (!is_data(p.v)) {
          continue;
        }
        ASSERT_EQ(p.v.h.seq, c.their);
        ASSERT_LE(p.v.payload.size(), 300u);
        got.insert(got.end(), p.v.payload.begin(), p.v.payload.end());
        c.their = c.their + static_cast<std::uint32_t>(p.v.payload.size());
        c.send(c.spec(w::tcp_ack));
      }
    }
    EXPECT_EQ(got, data);
    EXPECT_EQ(c.stack().stats().TcpExtTCPWinProbe, 3u);
    c.stack().debug_check();
  }
}

// RFC 9293 §3.10.7.4 "special allowance", Linux tcp_data_queue: at a zero
// receive window a segment at RCV.NXT is acceptable for its ACK and window;
// its payload is dropped (TcpExtTCPZeroWindowDrop) and ACKed at once. A bare
// FIN at RCV.NXT is taken.
TEST(TcpZeroWindow, ZeroWindowSegmentAtRcvNxt) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    StackConfig cfg = config(Side::b, profile);
    cfg.tcp.rcv_buf_init = 16 * 1024;
    cfg.tcp.rcv_buf_max = 16 * 1024;
    Scripted c(cfg);
    ASSERT_TRUE(c.accept());
    // Fill the receive window; the application does not read.
    std::uint32_t wnd = 1;
    std::size_t filled = 0;
    for (int i = 0; i < 1000 && wnd > 0; ++i) {
      c.send_data(std::min<std::uint32_t>(wnd, 1000));
      c.d().run_for(250ms);
      for (const Parsed& p : c.out()) {
        ASSERT_TRUE(is_pure_ack(p.v));
        c.nxt = p.v.h.ack;
        wnd = std::uint32_t{p.v.h.window} << c.stack().tcp_info(c.h)->rcv_wscale;
      }
      filled = c.stack().tcp_info(c.h)->bytes_received;
    }
    ASSERT_EQ(wnd, 0u);
    ASSERT_GT(filled, 0u);
    // The stack has data in flight; the segment at RCV.NXT acknowledges it
    // and opens the stack's send window.
    ASSERT_TRUE(c.stack().tcp_send(c.h, t::pattern(100)));
    ASSERT_EQ(c.out().size(), 1u);
    c.their = c.their + 100;
    c.window = 1234;
    c.send_data(50);
    c.nxt = c.nxt - 50;  // not taken
    const auto reply = c.out();
    ASSERT_EQ(reply.size(), 1u);
    EXPECT_TRUE(is_pure_ack(reply[0].v));
    EXPECT_EQ(reply[0].v.h.ack, c.nxt);
    EXPECT_EQ(reply[0].v.h.window, 0u);
    const auto i = *c.stack().tcp_info(c.h);
    EXPECT_EQ(i.unacked, 0u);
    EXPECT_EQ(i.bytes_acked, 100u);
    EXPECT_EQ(i.snd_wnd, std::uint32_t{1234} << i.snd_wscale);
    EXPECT_EQ(i.bytes_received, filled);
    EXPECT_EQ(c.stack().stats().TcpExtTCPZeroWindowDrop, 1u);
    // A bare FIN at RCV.NXT is accepted.
    c.send(c.spec(w::tcp_fin | w::tcp_ack));
    c.nxt = c.nxt + 1;
    const auto fin_ack = c.out();
    ASSERT_EQ(fin_ack.size(), 1u);
    EXPECT_EQ(fin_ack[0].v.h.ack, c.nxt);
    EXPECT_EQ(state(c.stack(), c.h), TcpState::close_wait);
    EXPECT_EQ(drain(c.stack(), c.h).size(), filled);
    c.stack().debug_check();
  }
}

// A receiver that stops reading closes the window; the sender probes; once
// the receiver reads again the transfer resumes and completes.
TEST(TcpZeroWindow, ReadingResumesTheTransfer) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    t::TcpHarness h(config(Side::a, profile), config(Side::b, profile));
    h.set_delay(Side::a, 5ms);
    h.set_delay(Side::b, 5ms);
    utcp::TcpSocketOptions small;
    small.rcv_buf = 32 * 1024;
    const auto l = h.b().tcp_listen(Endpoint{{}, port}, 4, small);
    ASSERT_TRUE(l);
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, {});
    ASSERT_TRUE(c);
    h.run_for(100ms);
    const auto s = h.b().tcp_accept(*l);
    ASSERT_TRUE(s);
    const t::Bytes data = t::pattern(200'000, 9);
    std::size_t sent = 0;
    const auto push = [&] {
      if (sent < data.size()) {
        if (const auto n = h.a().tcp_send(*c, std::span(data).subspan(sent))) {
          sent += *n;
        }
      }
    };
    for (int i = 0; i < 3000; ++i) {  // 30 s, nobody reads
      push();
      h.run_for(10ms);
    }
    EXPECT_EQ(h.a().tcp_info(*c)->snd_wnd, 0u);
    EXPECT_GT(h.a().stats().TcpExtTCPWinProbe, 3u);
    EXPECT_EQ(h.a().stats().TcpExtTCPTimeouts, 0u);
    t::Bytes got;
    for (int i = 0; i < 6000 && got.size() < data.size(); ++i) {
      push();
      h.run_for(10ms);
      const t::Bytes part = drain(h.b(), *s);
      got.insert(got.end(), part.begin(), part.end());
    }
    EXPECT_EQ(got, data);
    EXPECT_EQ(state(h.a(), *c), TcpState::established);
    h.a().debug_check();
    h.b().debug_check();
  }
}

}  // namespace
