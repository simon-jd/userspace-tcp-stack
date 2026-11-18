// TcpInfo, limited-time accounting, zero-window probes and the trace events
// of the engine (DESIGN §4.9, §10.1, §10.2).
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "common/jsonl.hpp"
#include "tcp_test_util.hpp"
#include "utcp/trace.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::Endpoint;
using utcp::Handle;
using utcp::StackConfig;
using utcp::TraceKind;
using utcp::TxKind;
namespace t = utcp::test;
using t::Side;
using namespace utcp::test::tcpt;

class Sink : public utcp::TraceSink {
public:
  void on_event(const utcp::TraceEvent& e) override { events.push_back(e); }
  std::vector<utcp::TraceEvent> events;
};

// §10.1 chrono (Linux tcp_chrono_start/stop): a receiver that stops reading
// makes the sender rwnd_limited (its send buffer holds all the data, so the
// application is never refused; FullSendBufferBehindClosedWindowIsRwndLimited
// covers a refused one) and the persist timer probes the zero window
// (§4.9: <SEQ=SND.UNA-1>, TxKind::zwp); once it reads again the transfer
// finishes and the clocks stop with the queues empty.
TEST(TcpInfo, RwndLimitedAndZeroWindowProbes) {
  StackConfig ca = config(Side::a);
  ca.trace_mask = utcp::trace_bit(TraceKind::tx);
  t::TcpHarness h(ca, config(Side::b));
  Sink sink;
  h.a().set_trace_sink(&sink);
  h.set_delay(Side::a, 5ms);
  h.set_delay(Side::b, 5ms);
  utcp::TcpSocketOptions o;
  o.rcv_buf = 64 * 1024;
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 4, o);
  ASSERT_TRUE(l);
  utcp::TcpSocketOptions big;
  big.snd_buf = 1 << 20;
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, big);
  ASSERT_TRUE(c);
  h.run_for(100ms);
  const auto s = h.b().tcp_accept(*l);
  ASSERT_TRUE(s);
  const t::Bytes data = t::pattern(300'000, 8);
  std::size_t sent = 0;
  for (int i = 0; i < 300; ++i) {  // 3 s, nobody reads
    if (sent < data.size()) {
      if (const auto n = h.a().tcp_send(*c, std::span(data).subspan(sent))) {
        sent += *n;
      }
    }
    h.run_for(10ms);
  }
  auto ia = h.a().tcp_info(*c);
  EXPECT_EQ(ia->snd_wnd, 0u);
  EXPECT_EQ(sent, data.size());
  EXPECT_GT(ia->rwnd_limited, 2s);
  EXPECT_EQ(ia->sndbuf_limited, Duration::zero());
  EXPECT_GE(ia->busy_time, ia->rwnd_limited);
  EXPECT_GT(h.a().stats().TcpExtTCPWinProbe, 0u);
  std::size_t zwp = 0;
  for (const utcp::TraceEvent& e : sink.events) {
    zwp += e.kind == TraceKind::tx && e.tx == TxKind::zwp ? 1u : 0u;
  }
  EXPECT_EQ(zwp, h.a().stats().TcpExtTCPWinProbe);
  // The receiver reads again.
  t::Bytes got;
  for (int i = 0; i < 1000 && got.size() < data.size(); ++i) {
    if (sent < data.size()) {
      if (const auto n = h.a().tcp_send(*c, std::span(data).subspan(sent))) {
        sent += *n;
      }
    }
    h.run_for(10ms);
    const t::Bytes part = drain(h.b(), *s);
    got.insert(got.end(), part.begin(), part.end());
  }
  EXPECT_EQ(got, data);
  h.run_for(1s);
  ia = h.a().tcp_info(*c);
  const auto ib = h.b().tcp_info(*s);
  EXPECT_EQ(ia->bytes_acked, data.size());
  EXPECT_GE(ia->bytes_sent, data.size());
  EXPECT_EQ(ib->bytes_received, data.size());
  EXPECT_GE(ib->data_segs_in, data.size() / ia->snd_mss);
  EXPECT_EQ(ia->data_segs_out, ib->data_segs_in);  // nothing was lost
  EXPECT_EQ(ia->notsent_bytes, 0u);
  EXPECT_EQ(ia->unacked, 0u);
  EXPECT_EQ(ia->conn_id, 1u);
  EXPECT_EQ(ia->state, utcp::TcpState::established);
  EXPECT_EQ(std::string(ia->cc_name_view()), "newreno");
  // Idle: the clocks stand still.
  const Duration busy = ia->busy_time;
  h.run_for(5s);
  EXPECT_EQ(h.a().tcp_info(*c)->busy_time, busy);
  EXPECT_GE(h.a().tcp_info(*c)->last_data_sent, 5s);
  h.a().set_trace_sink(nullptr);
  h.a().debug_check();
  h.b().debug_check();
}

// §10.1 (Linux tcp_cwnd_validate): a full send buffer behind a closed
// receive window is rwnd_limited, not sndbuf_limited. The application is
// refused, but data is still unsent because of the window, so the send
// buffer is not what stops the transfer (interop case A-pause200-s2l: the
// stack sender reported 17.7 s sndbuf_limited and 0.84 s rwnd_limited where
// a Linux sender reported 0 s and 18.9 s).
TEST(TcpInfo, FullSendBufferBehindClosedWindowIsRwndLimited) {
  t::TcpHarness h(config(Side::a), config(Side::b));
  h.set_delay(Side::a, 5ms);
  h.set_delay(Side::b, 5ms);
  utcp::TcpSocketOptions o;
  o.rcv_buf = 64 * 1024;
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 4, o);
  ASSERT_TRUE(l);
  utcp::TcpSocketOptions small;
  small.snd_buf = 32 * 1024;
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, small);
  ASSERT_TRUE(c);
  h.run_for(100ms);
  const auto s = h.b().tcp_accept(*l);
  ASSERT_TRUE(s);
  const t::Bytes data = t::pattern(1'000'000, 10);
  std::size_t sent = 0;
  bool refused = false;
  for (int i = 0; i < 300; ++i) {  // 3 s, nobody reads, the writer keeps trying
    const auto n = h.a().tcp_send(*c, std::span(data).subspan(sent));
    if (n) {
      sent += *n;
    } else {
      refused = true;
    }
    h.run_for(10ms);
  }
  ASSERT_TRUE(refused);
  ASSERT_LT(sent, data.size());
  const auto ia = h.a().tcp_info(*c);
  EXPECT_EQ(ia->snd_wnd, 0u);
  EXPECT_GT(ia->notsent_bytes, 0u);
  EXPECT_GT(ia->rwnd_limited, 2s);
  EXPECT_EQ(ia->sndbuf_limited, Duration::zero());
  h.a().debug_check();
  h.b().debug_check();
}

// §10.1: an application refused by a full send buffer while everything it
// queued has been sent (not cwnd- or window-limited) makes the connection
// sndbuf_limited.
TEST(TcpInfo, SndbufLimited) {
  t::TcpHarness h;
  h.set_delay(Side::a, 20ms);
  h.set_delay(Side::b, 20ms);
  utcp::TcpSocketOptions o;
  o.snd_buf = 16 * 1024;
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 4, {});
  ASSERT_TRUE(l);
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, o);
  ASSERT_TRUE(c);
  h.run_for(100ms);
  const auto s = h.b().tcp_accept(*l);
  ASSERT_TRUE(s);
  const t::Bytes data = t::pattern(500'000, 9);
  std::size_t sent = 0, got = 0;
  for (int i = 0; i < 2000 && got < data.size(); ++i) {
    if (sent < data.size()) {
      if (const auto n = h.a().tcp_send(*c, std::span(data).subspan(sent))) {
        sent += *n;
      }
    }
    h.run_for(5ms);
    got += drain(h.b(), *s).size();
  }
  EXPECT_EQ(got, data.size());
  const auto i = h.a().tcp_info(*c);
  EXPECT_GT(i->sndbuf_limited, Duration::zero());
  EXPECT_EQ(i->rwnd_limited, Duration::zero());
  EXPECT_GT(i->busy_time, i->sndbuf_limited);
}

// §10.2: the engine traces each transmission with its TxKind; an RTO expiry
// is traced (TraceKind::rto) before the rto_rexmit it causes; state events
// carry the close cause.
TEST(TcpInfo, TraceKindsOfAConnection) {
  StackConfig ca = config(Side::a);
  ca.trace_mask = utcp::trace_mask_all;
  t::TcpHarness h(ca, config(Side::b));
  Sink sink;
  h.a().set_trace_sink(&sink);
  h.set_delay(Side::a, 5ms);
  h.set_delay(Side::b, 5ms);
  bool dropped = false;
  h.set_hook([&](Side from, t::Bytes& d) {
    const auto q = parse(d);
    if (from == Side::a && q && is_data(q->v) && !dropped) {
      dropped = true;
      return t::Verdict::drop;
    }
    return t::Verdict::deliver;
  });
  const auto p = open(h);
  ASSERT_TRUE(p);
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(500)));
  h.run_for(1s);
  EXPECT_EQ(drain(h.b(), p->server).size(), 500u);
  ASSERT_TRUE(h.a().tcp_close(p->client));
  ASSERT_TRUE(h.b().tcp_close(p->server));
  h.run_for(61s);
  std::vector<TxKind> tx;
  std::size_t rto_at = 0, rexmit_at = 0;
  for (std::size_t i = 0; i < sink.events.size(); ++i) {
    const utcp::TraceEvent& e = sink.events[i];
    if (e.kind == TraceKind::tx) {
      tx.push_back(e.tx);
      if (e.tx == TxKind::rto_rexmit) {
        rexmit_at = i;
      }
    }
    if (e.kind == TraceKind::rto) {
      rto_at = i;
    }
  }
  const std::vector<TxKind> want{TxKind::syn, TxKind::ack, TxKind::data, TxKind::rto_rexmit,
                                 TxKind::fin, TxKind::ack};
  EXPECT_EQ(tx, want);
  ASSERT_GT(rexmit_at, 0u);
  EXPECT_LT(rto_at, rexmit_at);
  // TIME-WAIT expiry is traced as a state event to closed.
  ASSERT_FALSE(sink.events.empty());
  const utcp::TraceEvent& last = sink.events.back();
  EXPECT_EQ(last.kind, TraceKind::state);
  EXPECT_EQ(last.state, utcp::TcpState::closed);
  EXPECT_EQ(last.cause, utcp::CloseCause::time_wait_expired);
  h.a().set_trace_sink(nullptr);
}

// ---- m2-found acceptance test 5 (M2-DESIGN §1.9, §2.6, §5.3).

// tcpi_reordering is recovery's (3: the stub's dupthresh), tcpi_delivery_rate
// and tcpi_delivery_rate_app_limited come from the tcp_rate_gen record
// (m2b-rate-pacing): every sample of these small writes is app-limited, so
// the record holds an app-limited sample with a rate; before any sample the
// flag is 1, as Linux tcp_init_sock sets it. utcp-bulk's JSONL sample lines
// (add_fields) carry all four.
TEST(TcpInfo, M2FieldsFromRecoveryAndTheRateRecord) {
  for (const utcp::ProfileId profile : {utcp::ProfileId::rfc, utcp::ProfileId::linux_compat}) {
    SCOPED_TRACE(profile == utcp::ProfileId::rfc ? "rfc" : "linux_compat");
    t::TcpHarness h(config(Side::a, profile), config(Side::b, profile));
    h.set_delay(Side::a, 5ms);
    h.set_delay(Side::b, 5ms);
    const auto p = open(h);
    ASSERT_TRUE(p);
    const auto i0 = h.a().tcp_info(p->client);
    ASSERT_TRUE(i0);
    EXPECT_EQ(i0->delivery_rate, 0u);  // no record yet
    EXPECT_TRUE(i0->app_limited);
    // Small writes with nothing in flight: application-limited (§5.4).
    for (int i = 0; i < 20; ++i) {
      ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(100)));
      h.run_for(50ms);
      drain(h.b(), p->server);
    }
    ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(100)));
    const auto i = h.a().tcp_info(p->client);
    ASSERT_TRUE(i);
    EXPECT_EQ(i->reordering, 3u);
    EXPECT_EQ(i->reord_seen, 0u);
    EXPECT_GT(i->delivery_rate, 0u);  // the record of an app-limited sample
    EXPECT_TRUE(i->app_limited);      // the record's flag
    EXPECT_GT(i->delivered, 0u);
    utcp::app::JsonLine line;
    utcp::app::add_fields(line, *i);
    const std::string js = line.str();
    const std::string rate = "\"delivery_rate\":" + std::to_string(i->delivery_rate);
    for (const char* f : {rate.c_str(), "\"app_limited\":true", "\"reordering\":3",
                          "\"reord_seen\":0"}) {
      EXPECT_NE(js.find(f), std::string::npos) << f << " in " << js;
    }
  }
}

// M2-DESIGN §5.3 (Linux tcp_cwnd_validate, tcp_output.c:2177-2180): the
// sndbuf-limited clock starts only after a transmit pass that sent data, was
// not cwnd-limited, left nothing unsent, with the application refused. A
// bulk writer that keeps a 64 MiB buffer full while cwnd limits the sender
// accumulates none; a writer whose small buffer empties into a cwnd that is
// not used up accumulates most of the transfer.
TEST(TcpInfo, SndbufLimitedOnlyWhenTheBufferStarvesTheNetwork) {
  struct Case {
    std::uint32_t snd_buf;
    bool starved;
  };
  for (const Case k : {Case{64u << 20, false}, Case{16u << 10, true}}) {
    SCOPED_TRACE(k.snd_buf);
    StackConfig ca = config(Side::a);
    ca.tcp.initial_ssthresh = 40;  // cwnd stays small: the 64 MiB writer is cwnd-limited
    t::TcpHarness h(ca, config(Side::b));
    h.set_delay(Side::a, 10ms);
    h.set_delay(Side::b, 10ms);
    utcp::TcpSocketOptions ro;
    ro.rcv_buf = 4u << 20;  // the receive window never limits
    const auto l = h.b().tcp_listen(Endpoint{{}, port}, 4, ro);
    ASSERT_TRUE(l);
    utcp::TcpSocketOptions so;
    so.snd_buf = k.snd_buf;
    const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, so);
    ASSERT_TRUE(c);
    h.run_for(100ms);
    const auto s = h.b().tcp_accept(*l);
    ASSERT_TRUE(s);
    const t::Bytes chunk = t::pattern(1u << 20, 3);
    bool refused = false;
    std::size_t got = 0;
    for (int i = 0; i < 400; ++i) {  // 2 s
      for (;;) {
        const auto n = h.a().tcp_send(*c, chunk);
        if (!n || *n < chunk.size()) {
          refused = true;
          break;
        }
      }
      h.run_for(5ms);
      got += drain(h.b(), *s).size();
    }
    ASSERT_TRUE(refused);
    const auto i = h.a().tcp_info(*c);
    EXPECT_GT(got, 1u << 20);
    EXPECT_GT(i->busy_time, 1900ms);
    EXPECT_EQ(i->rwnd_limited, Duration::zero());
    if (k.starved) {
      EXPECT_GT(i->sndbuf_limited, i->busy_time / 2);
    } else {
      EXPECT_GT(i->notsent_bytes, 32u << 20);  // the buffer stays full
      EXPECT_EQ(i->sndbuf_limited, Duration::zero());
    }
    h.a().debug_check();
  }
}

}  // namespace
