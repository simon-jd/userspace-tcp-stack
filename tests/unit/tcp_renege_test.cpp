// m1-tcp-robust acceptance test 5: a receiver that reneges on SACKed data
// (RFC 2018 §8). The sender's RTO finds the head SACKed, clears every SACK
// mark, counts TCPSACKReneging and resends (DESIGN §5.3; Linux
// tcp_check_sack_reneging, tcp_timeout_mark_lost); the transfer completes.
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/sha256.hpp"
#include "tcp_test_util.hpp"
#include "utcp/trace.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Endpoint;
using utcp::ProfileId;
using utcp::Seq32;
using utcp::StackConfig;
using utcp::TxKind;
namespace t = utcp::test;
namespace w = utcp::wire;
using t::Side;
using namespace utcp::test::tcpt;

std::string name(ProfileId p) { return p == ProfileId::rfc ? "rfc" : "linux_compat"; }
std::string digest(std::span<const std::byte> d) { return utcp::app::sha256_hex(d); }

class TxSink : public utcp::TraceSink {
public:
  void on_event(const utcp::TraceEvent& e) override {
    if (e.kind == utcp::TraceKind::tx) {
      kinds.push_back(e.tx);
    }
  }
  std::vector<TxKind> kinds;
};

// A scripted receiver SACKs segments 2 and 3, then acknowledges only
// segment 1: it dropped what it had SACKed. The ACK that stops at a SACKed
// segment re-arms the RTO at max(SRTT/2, 10 ms); the RTO finds the head
// SACKed, clears the marks, counts the reneging and resends everything from
// SND.UNA, starting with the head as rto_rexmit.
TEST(TcpRenege, RtoFindsSackedHeadAndResends) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    StackConfig cfg = config(Side::b, profile);
    cfg.trace_mask = utcp::trace_bit(utcp::TraceKind::tx);
    // The scripted handshake's RTT is 0, so min_rtt is 0 and linux_compat's
    // RACK has a zero reorder window: the first SACK would mark segment 1
    // lost (as Linux would). RFC 6675 marking keeps the two SACKs below the
    // loss threshold, which this test is about (M2-DESIGN §1.2).
    cfg.tcp.rack_tlp = false;
    Scripted c(cfg);
    ASSERT_TRUE(c.accept());
    TxSink sink;
    c.stack().set_trace_sink(&sink);
    const std::uint32_t mss = c.stack().tcp_info(c.h)->snd_mss;
    const t::Bytes data = t::pattern(3 * std::size_t{mss}, 4);
    ASSERT_TRUE(c.stack().tcp_send(c.h, data));
    const auto segs = c.out();
    ASSERT_EQ(segs.size(), 3u);
    t::Bytes got(segs[0].v.payload.begin(), segs[0].v.payload.end());
    const Seq32 s2 = segs[1].v.h.seq, end = segs[2].v.h.seq + mss;
    // SACK for segments 2 and 3 (two duplicate ACKs, below dupthresh).
    for (const Seq32 sack_end : {s2 + mss, end}) {
      t::TcpSpec a = c.spec(w::tcp_ack);
      a.opt.sack[0] = {s2, sack_end};
      a.opt.sack_count = 1;
      c.send(a);
    }
    EXPECT_EQ(c.stack().tcp_info(c.h)->sacked, 2u);
    EXPECT_TRUE(c.out().empty());
    // Segment 1 is acknowledged, the SACKed ones are not: reneged.
    c.their = s2;
    c.send(c.spec(w::tcp_ack));
    EXPECT_TRUE(c.out().empty());
    const auto i0 = *c.stack().tcp_info(c.h);
    EXPECT_EQ(i0.unacked, 2u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPSACKReneging, 0u);
    // The receiver takes each resent segment in order and ACKs it.
    const utcp::Time acked = c.d().now();
    std::optional<utcp::Duration> first;
    for (int ms = 0; ms < 10'000 && c.their != end; ++ms) {
      c.d().run_for(1ms);
      for (const Parsed& p : c.out()) {
        if (!first && is_data(p.v)) {
          first = c.d().now() - acked;
        }
        if (is_data(p.v) && p.v.h.seq == c.their) {
          got.insert(got.end(), p.v.payload.begin(), p.v.payload.end());
          c.their = c.their + static_cast<std::uint32_t>(p.v.payload.size());
          c.send(c.spec(w::tcp_ack));
        }
      }
    }
    EXPECT_EQ(c.their, end);
    // SRTT is 0 (the handshake sample), so the timer runs 10 ms
    // (tcp_check_sack_reneging), not a full RTO.
    EXPECT_EQ(first, std::optional<utcp::Duration>{10ms});
    EXPECT_EQ(digest(got), digest(data));
    EXPECT_EQ(c.stack().stats().TcpExtTCPSACKReneging, 1u);
    EXPECT_EQ(c.stack().stats().TcpExtTCPTimeouts, 1u);
    EXPECT_EQ(sink.kinds.size(), 3u + 2u);
    ASSERT_GE(sink.kinds.size(), 4u);
    EXPECT_EQ(sink.kinds[3], TxKind::rto_rexmit);
    const auto i1 = *c.stack().tcp_info(c.h);
    EXPECT_EQ(i1.unacked, 0u);
    EXPECT_EQ(i1.sacked, 0u);
    EXPECT_EQ(i1.ca_state, utcp::CaState::open);
    c.stack().set_trace_sink(nullptr);
    c.stack().debug_check();
  }
}

// End to end with the test_renege_ppm knob (DESIGN §7.2): stack b drops all
// its out-of-order data with probability 1/2 after storing a segment, so
// SACKed blocks vanish; a's RTOs find the head SACKed. 2 MB arrive intact.
TEST(TcpRenege, RenegingReceiverTransferCompletes) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(name(profile));
    StackConfig cb = config(Side::b, profile);
    cb.tcp.test_renege_ppm = 500'000;
    t::TcpHarness h(config(Side::a, profile), cb);
    h.set_delay(Side::a, 5ms);
    h.set_delay(Side::b, 5ms);
    const auto p = open(h);
    ASSERT_TRUE(p);
    // Every 40th data segment from a is lost once, which leaves
    // out-of-order data at b.
    std::size_t n = 0;
    h.set_hook([&](Side from, t::Bytes& d) {
      const auto q = parse(d);
      if (from == Side::a && q && is_data(q->v) && ++n % 40 == 0) {
        return t::Verdict::drop;
      }
      return t::Verdict::deliver;
    });
    const t::Bytes data = t::pattern(2'000'000, 6);
    std::size_t sent = 0;
    t::Bytes got;
    for (int i = 0; i < 120'000 && got.size() < data.size(); ++i) {
      if (sent < data.size()) {
        if (const auto r = h.a().tcp_send(p->client, std::span(data).subspan(sent))) {
          sent += *r;
        }
      }
      h.run_for(1ms);
      const t::Bytes part = drain(h.b(), p->server);
      got.insert(got.end(), part.begin(), part.end());
      h.clear_log();
    }
    ASSERT_EQ(got.size(), data.size());
    EXPECT_EQ(digest(got), digest(data));
    EXPECT_GT(h.a().stats().TcpExtTCPSACKReneging, 0u);
    EXPECT_EQ(h.a().stats().TcpExtTCPSACKDiscard, 0u);
    h.a().debug_check();
    h.b().debug_check();
  }
}

}  // namespace
