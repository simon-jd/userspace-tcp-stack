// m1-tcp-core acceptance test 3: half-close, close and abort rules (DESIGN
// §3.5, §4.4 step 3, §4.7, §4.12).
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "tcp_test_util.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Endpoint;
using utcp::Error;
using utcp::Handle;
using utcp::Seq32;
using utcp::Shutdown;
using utcp::TcpState;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;
using namespace utcp::test::tcpt;

// Sends `data` from (tx, txh) while reading at (rx, rxh), until all of it is
// read or `limit` passes.
t::Bytes stream(t::TcpHarness& h, utcp::Stack& tx, Handle txh, utcp::Stack& rx, Handle rxh,
                const t::Bytes& data, utcp::Duration limit = 30s) {
  t::Bytes got;
  std::size_t sent = 0;
  const utcp::Time end = h.now() + limit;
  while (got.size() < data.size() && h.now() < end) {
    if (sent < data.size()) {
      const auto n = tx.tcp_send(txh, std::span(data).subspan(sent));
      if (n) {
        sent += *n;
      }
    }
    h.run_for(10ms);
    const t::Bytes part = drain(rx, rxh);
    got.insert(got.end(), part.begin(), part.end());
  }
  return got;
}

// RFC 9293 §3.6: after one side's FIN the other direction keeps working; each
// side ends as its role says (the first FIN's sender in TIME-WAIT).
TEST(TcpClose, HalfCloseEachWayKeepsTheOtherDirection) {
  for (const bool client_first : {true, false}) {
    SCOPED_TRACE(client_first ? "client shuts down first" : "server shuts down first");
    t::TcpHarness h;
    h.set_delay(Side::a, 5ms);
    h.set_delay(Side::b, 5ms);
    const auto p = open(h);
    ASSERT_TRUE(p);
    utcp::Stack& x = client_first ? h.a() : h.b();
    utcp::Stack& y = client_first ? h.b() : h.a();
    const Handle xh = client_first ? p->client : p->server;
    const Handle yh = client_first ? p->server : p->client;

    // x sends a little, then its FIN follows the data.
    const t::Bytes before = t::pattern(3000, 1);
    EXPECT_EQ(stream(h, x, xh, y, yh, before), before);
    ASSERT_TRUE(x.tcp_shutdown(xh, Shutdown::write));
    EXPECT_EQ(state(x, xh), TcpState::fin_wait_1);
    h.run_for(100ms);
    EXPECT_EQ(state(x, xh), TcpState::fin_wait_2);
    EXPECT_EQ(state(y, yh), TcpState::close_wait);
    std::array<std::byte, 64> buf{};
    EXPECT_EQ(y.tcp_recv(yh, buf).value_or(99), 0u);  // end of stream
    EXPECT_TRUE(y.tcp_readiness(yh).read_closed);
    EXPECT_FALSE(y.tcp_readiness(yh).write_closed);
    EXPECT_EQ(x.tcp_send(xh, before).error(), Error::shut_down);

    // y keeps sending, x keeps reading.
    const t::Bytes after = t::pattern(200'000, 2);
    EXPECT_EQ(stream(h, y, yh, x, xh, after), after);
    EXPECT_EQ(state(x, xh), TcpState::fin_wait_2);

    ASSERT_TRUE(y.tcp_shutdown(yh, Shutdown::write));
    EXPECT_EQ(state(y, yh), TcpState::last_ack);
    h.run_for(100ms);
    EXPECT_EQ(x.tcp_recv(xh, buf).value_or(99), 0u);
    EXPECT_EQ(state(x, xh), TcpState::time_wait);  // the handle stays until tcp_close
    EXPECT_EQ(state(y, yh), TcpState::closed);
    EXPECT_EQ(x.debug_usage().time_wait_entries, 1u);
    EXPECT_EQ(y.debug_usage().time_wait_entries, 0u);
    ASSERT_TRUE(x.tcp_close(xh));
    ASSERT_TRUE(y.tcp_close(yh));
    EXPECT_EQ(h.a().stats().TcpOutRsts + h.b().stats().TcpOutRsts, 0u);
    h.run_for(61s);
    EXPECT_EQ(h.a().debug_usage().tcp_slots, 0u);
    EXPECT_EQ(h.b().debug_usage().tcp_slots, 1u);  // the listener
    EXPECT_EQ(h.a().debug_usage().time_wait_entries + h.b().debug_usage().time_wait_entries, 0u);
    h.a().debug_check();
    h.b().debug_check();
  }
}

// RFC 9293 §3.10.4 / RFC 2525 §2.17: close with unread data resets the
// connection instead of the FIN; the peer sees connection_reset.
TEST(TcpClose, CloseWithUnreadDataSendsRst) {
  t::TcpHarness h;
  const auto p = open(h);
  ASSERT_TRUE(p);
  ASSERT_TRUE(h.b().tcp_send(p->server, t::pattern(1000)));
  h.run_for(100ms);
  h.clear_log();
  ASSERT_TRUE(h.a().tcp_close(p->client));
  EXPECT_EQ(h.a().debug_usage().tcp_slots, 0u);  // freed at once, no TIME-WAIT
  EXPECT_EQ(h.a().debug_usage().time_wait_entries, 0u);
  h.run_for(100ms);
  const auto rst = find(h, Side::a, is_rst);
  ASSERT_EQ(rst.size(), 1u);
  EXPECT_TRUE(find(h, Side::a, is_fin).empty());
  EXPECT_EQ(h.a().stats().TcpExtTCPAbortOnClose, 1u);
  EXPECT_EQ(state(h.b(), p->server), TcpState::closed);
  std::array<std::byte, 64> buf{};
  EXPECT_EQ(h.b().tcp_recv(p->server, buf).error(), Error::connection_reset);
  EXPECT_EQ(h.b().tcp_send(p->server, buf).error(), Error::connection_reset);
  h.a().debug_check();
  h.b().debug_check();
}

// RFC 1122 §4.2.2.13 (Linux tcp_rcv_state_process, TCPAbortOnData): new data
// for a connection the application closed resets it. shutdown(read) alone in
// ESTABLISHED acknowledges and discards later data (§3.5).
TEST(TcpClose, DataAfterCloseSendsRst) {
  {
    t::TcpHarness h;
    const auto p = open(h);
    ASSERT_TRUE(p);
    ASSERT_TRUE(h.a().tcp_close(p->client));
    h.run_for(100ms);
    EXPECT_EQ(state(h.b(), p->server), TcpState::close_wait);
    EXPECT_EQ(h.a().debug_usage().tcp_slots, 1u);  // the orphan in FIN-WAIT-2
    h.clear_log();
    ASSERT_TRUE(h.b().tcp_send(p->server, t::pattern(500)));
    h.run_for(100ms);
    EXPECT_EQ(find(h, Side::a, is_rst).size(), 1u);
    EXPECT_EQ(h.a().stats().TcpExtTCPAbortOnData, 1u);
    EXPECT_EQ(h.a().debug_usage().tcp_slots, 0u);
    EXPECT_EQ(state(h.b(), p->server), TcpState::closed);
    EXPECT_EQ(h.b().tcp_send(p->server, t::pattern(10)).error(), Error::connection_reset);
    h.a().debug_check();
    h.b().debug_check();
  }
  {
    t::TcpHarness h;
    const auto p = open(h);
    ASSERT_TRUE(p);
    ASSERT_TRUE(h.a().tcp_shutdown(p->client, Shutdown::read));
    h.clear_log();
    ASSERT_TRUE(h.b().tcp_send(p->server, t::pattern(500)));
    h.run_for(500ms);
    EXPECT_TRUE(find(h, Side::a, is_rst).empty());
    EXPECT_EQ(h.b().tcp_info(p->server)->unacked, 0u);
    std::array<std::byte, 64> buf{};
    EXPECT_EQ(h.a().tcp_recv(p->client, buf).value_or(99), 0u);
    EXPECT_EQ(state(h.a(), p->client), TcpState::established);
    // The other direction still works.
    const t::Bytes x = t::pattern(700, 4);
    ASSERT_TRUE(h.a().tcp_send(p->client, x));
    h.run_for(500ms);
    EXPECT_EQ(drain(h.b(), p->server), x);
    h.a().debug_check();
    h.b().debug_check();
  }
}

// §3.5: tcp_abort sends <SEQ=SND.NXT><CTL=RST> and frees the connection.
TEST(TcpClose, AbortSendsRstAndFrees) {
  t::TcpHarness h;
  const auto p = open(h);
  ASSERT_TRUE(p);
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(2000)));
  h.run_for(100ms);
  const auto data = find(h, Side::a, is_data);
  ASSERT_FALSE(data.empty());
  const auto last = parse(data.back()->bytes);
  const Seq32 snd_nxt = last->v.h.seq + static_cast<std::uint32_t>(last->v.payload.size());
  h.clear_log();
  ASSERT_TRUE(h.a().tcp_abort(p->client));
  EXPECT_EQ(h.a().tcp_info(p->client).error(), Error::bad_handle);
  EXPECT_EQ(h.a().debug_usage().tcp_slots, 0u);
  h.run_for(100ms);
  const auto rst = find(h, Side::a, is_rst);
  ASSERT_EQ(rst.size(), 1u);
  EXPECT_EQ(parse(rst[0]->bytes)->v.h.seq, snd_nxt);
  EXPECT_EQ(state(h.b(), p->server), TcpState::closed);
  EXPECT_EQ(h.b().take_error(p->server), Error::connection_reset);
  EXPECT_EQ(h.b().stats().TcpEstabResets, 1u);
  h.a().debug_check();
  h.b().debug_check();
}

// RFC 9293 §3.10.7.4 step 3 (RFC 5961 §3.2): in SYN-RECEIVED of a
// simultaneous open, an RST at RCV.NXT fails the connect with
// connection_refused; one elsewhere in the window gets a challenge ACK.
TEST(TcpClose, RstInSimultaneousOpenSynReceivedRefuses) {
  Driven d;
  const auto c = d.stack().tcp_connect(Driven::peer(5000), {}, 4000);
  ASSERT_TRUE(c);
  const auto syn = d.out();
  ASSERT_EQ(syn.size(), 1u);
  const Seq32 iss = parse(syn[0])->v.h.seq;
  t::TcpSpec peer_syn(Driven::peer(5000), d.local(4000));
  peer_syn.seq = Seq32{7000};
  peer_syn.flags = w::tcp_syn;
  peer_syn.opt.mss = 1460;
  d.send(peer_syn);
  const auto synack = d.out();
  ASSERT_EQ(synack.size(), 1u);
  const auto sa = parse(synack[0]);
  ASSERT_TRUE(sa && is_synack(sa->v));
  EXPECT_EQ(sa->v.h.seq, iss);
  EXPECT_EQ(sa->v.h.ack, Seq32{7001});
  EXPECT_EQ(state(d.stack(), *c), TcpState::syn_received);

  t::TcpSpec rst(Driven::peer(5000), d.local(4000));
  rst.seq = Seq32{7101};
  rst.flags = w::tcp_rst;
  d.send(rst);
  const auto challenge = d.out();
  ASSERT_EQ(challenge.size(), 1u);
  EXPECT_TRUE(is_pure_ack(parse(challenge[0])->v));
  EXPECT_EQ(state(d.stack(), *c), TcpState::syn_received);

  rst.seq = Seq32{7001};
  d.send(rst);
  EXPECT_TRUE(d.out().empty());
  EXPECT_EQ(state(d.stack(), *c), TcpState::closed);
  EXPECT_NE(events_of(d.stack(), *c) & utcp::ev_error, 0);
  EXPECT_EQ(d.stack().take_error(*c), Error::connection_refused);
  EXPECT_EQ(d.stack().stats().TcpAttemptFails, 1u);
  ASSERT_TRUE(d.stack().tcp_close(*c));
  EXPECT_EQ(d.stack().debug_usage().tcp_slots, 0u);
  d.stack().debug_check();
}

// A connection reset while the application still holds it reaches CLOSED
// with every timer stopped: with data outstanding, no RTO fires later and
// nothing more is sent; tcp_close then frees it.
TEST(TcpClose, RstWithDataOutstandingStopsTimers) {
  t::TcpHarness h;
  const auto p = open(h);
  ASSERT_TRUE(p);
  h.set_hook([](Side from, t::Bytes&) {
    return from == Side::b ? t::Verdict::drop : t::Verdict::deliver;  // b's ACKs lost
  });
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(16'000)));
  h.settle();
  EXPECT_GT(h.a().tcp_info(p->client)->unacked, 0u);
  h.set_hook(nullptr);
  ASSERT_TRUE(h.b().tcp_abort(p->server));  // RST <SEQ=SND.NXT> = a's RCV.NXT
  h.settle();
  EXPECT_EQ(state(h.a(), p->client), TcpState::closed);
  EXPECT_EQ(h.a().take_error(p->client), Error::connection_reset);
  EXPECT_EQ(h.a().debug_usage().conn_timers_armed, 0u);
  h.clear_log();
  h.run_for(10s);
  EXPECT_TRUE(find(h, Side::a, [](const w::TcpView&) { return true; }).empty());
  ASSERT_TRUE(h.a().tcp_close(p->client));
  EXPECT_EQ(h.a().debug_usage().tcp_slots, 0u);
  EXPECT_EQ(h.a().debug_usage().conn_timers_armed, 0u);
  h.a().debug_check();
}

// A reset, held connection releases its send side at once (Linux tcp_reset
// purges the write queue): its chunks go back to the shared ChunkPool, and
// tcp_info shows nothing unacknowledged, while data received before the RST
// stays readable until tcp_close.
TEST(TcpClose, ResetReleasesTheSendQueueButKeepsReceivedData) {
  t::TcpHarness h;
  const auto p = open(h);
  ASSERT_TRUE(p);
  ASSERT_TRUE(h.b().tcp_send(p->server, t::pattern(500, 3)));
  h.settle();
  const std::uint32_t chunks0 = h.a().debug_usage().chunks - h.a().debug_usage().chunks_free;
  h.set_hook([](Side from, t::Bytes&) {
    return from == Side::b ? t::Verdict::drop : t::Verdict::deliver;  // b's ACKs lost
  });
  ASSERT_TRUE(h.a().tcp_send(p->client, t::pattern(16'000)));
  h.settle();
  EXPECT_GT(h.a().tcp_info(p->client)->unacked, 0u);
  const utcp::StackUsage u1 = h.a().debug_usage();
  EXPECT_GT(u1.chunks - u1.chunks_free, chunks0);
  h.set_hook(nullptr);
  ASSERT_TRUE(h.b().tcp_abort(p->server));
  h.settle();
  ASSERT_EQ(state(h.a(), p->client), TcpState::closed);
  const auto info = h.a().tcp_info(p->client);
  ASSERT_TRUE(info);
  EXPECT_EQ(info->unacked, 0u);
  EXPECT_EQ(info->notsent_bytes, 0u);
  const utcp::StackUsage u2 = h.a().debug_usage();
  EXPECT_EQ(u2.chunks - u2.chunks_free, chunks0);  // only the unread receive data
  h.a().debug_check();
  EXPECT_EQ(drain(h.a(), p->client), t::pattern(500, 3));
  EXPECT_EQ(h.a().take_error(p->client), Error::connection_reset);
  ASSERT_TRUE(h.a().tcp_close(p->client));
  const utcp::StackUsage u3 = h.a().debug_usage();
  EXPECT_EQ(u3.chunks_free, u3.chunks);
  h.a().debug_check();
}

}  // namespace
