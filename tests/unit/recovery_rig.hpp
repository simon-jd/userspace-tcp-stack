// A sender's loss recovery driven by scripted ACKs through process_ack, for
// the m2a tests (prr_test.cpp, rack_test.cpp, sack_scoreboard_test.cpp,
// recovery_test.cpp; M2-DESIGN §4.1). Packet k (1-based) is the stream bytes
// [(k - 1) * mss, k * mss). transmit() does what the engine's transmit does
// for data (DESIGN §4.9): lost segments through the cwnd gate (or exempt),
// new data up to cwnd, then RFC 6675 NextSeg rules 3-4, then on_burst_end;
// it returns what it sent as "R<k>" (retransmission) and "N<k>" (new data).
#pragma once

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/buffer/chunk_pool.hpp"
#include "core/tcp/ack_pipeline.hpp"
#include "core/tcp/cc.hpp"
#include "core/tcp/recovery.hpp"

namespace utcp::test::rig {

using namespace std::chrono_literals;

inline constexpr std::uint32_t mss = 1000;

[[nodiscard]] constexpr std::uint64_t off_of(std::uint32_t k) { return std::uint64_t{k - 1} * mss; }

// A CC whose ssthresh is fixed and whose cong_avoid does nothing, so cwnd
// changes only through recovery (M2-TASKS m2a: "a fake CC with fixed
// ssthresh").
class FixedCc final : public CongestionControl {
public:
  explicit FixedCc(std::uint32_t ss) : ss_(ss) {}
  [[nodiscard]] std::string_view name() const override { return "fixed"; }
  std::uint32_t ssthresh(const CcConn&) override { return ss_; }
  void cong_avoid(CcConn&, const AckOutcome&) override { ++cong_avoids; }
  int cong_avoids = 0;

private:
  std::uint32_t ss_;
};

struct Rig {
  // `cfg` selects the recovery (rack_tlp, recovery_reduction); srtt 100 ms
  // and min_rtt 40 ms unless the test primes others.
  explicit Rig(TcpConfig config, std::uint32_t ssthresh = 14, bool sack_ok = true)
      : cfg(config), rtt(cfg), algo(ssthresh), sack(sack_ok) {
    q.set_sack_ok(sack_ok);
    cc.cwnd = 20;
    cc.ssthresh = cwnd_infinite;
    cc.mss = mss;
    rtt.on_srtt_sample(100ms, 0, 0);
    rtt.on_min_rtt_sample(40ms, false, now);
  }

  RecoveryCtx rctx() {
    RecoveryCtx c{q, cc, algo, rtt, cfg, now, wnd, stats, sack, backoff, rto_count};
    c.max_snd_wnd = max_snd_wnd;
    c.total_retrans = ctr.total_retrans;
    c.dsack_dups = ctr.dsack_dups;
    c.delivered = rate.delivered;
    c.pacing_delay = pacing_delay;
    return c;
  }

  // The application writes `n` more packets.
  void write(std::uint32_t n) {
    const std::vector<std::byte> data(std::size_t{n} * mss);
    ASSERT_EQ(q.write(data), data.size());
  }

  // One transmission of the TxSeg at `off` (new data if off == nxt()).
  void send_at(std::uint64_t off, TxKind kind) {
    const bool fresh = off == q.nxt();
    const TxSeg* old = q.find(off);
    const std::uint32_t len = fresh ? mss : old->len;
    rate_on_send(rate, q.counters().packets_out, now);
    const TxSeg& s = q.on_transmit(off, len, false, now, rate);
    auto c = rctx();
    rec.on_transmit(c, s, kind);
    if (!fresh) {
      ++ctr.total_retrans;
    }
  }

  // Writes and sends `n` new packets at `now`.
  void send_new(std::uint32_t n) {
    write(n);
    for (std::uint32_t i = 0; i < n; ++i) {
      send_at(q.nxt(), TxKind::data);
    }
  }

  [[nodiscard]] std::uint32_t in_flight() const { return packets_in_flight(q.counters()); }
  static std::string name(char kind, std::uint64_t off) {
    return kind + std::to_string(off / mss + 1);
  }

  // The engine's transmit() for data (DESIGN §4.9, M2-DESIGN §1.4).
  std::vector<std::string> transmit() {
    std::vector<std::string> sent;
    bool cwnd_limited = false;
    for (std::size_t i = 0; i < q.segs().size(); ++i) {
      const TxSeg seg = q.segs()[i];
      if (!seg.lost || seg.retrans_inflight || seg.sacked) {
        continue;
      }
      const auto c = rctx();
      const bool exempt = rec.exempt_from_cwnd(c, seg);
      if (!exempt && in_flight() >= cc.cwnd) {
        cwnd_limited = true;
        break;
      }
      send_at(seg.off, exempt ? TxKind::fast_rexmit : TxKind::rexmit);
      sent.push_back(name('R', seg.off));
    }
    bool new_sent = false;
    while (!cwnd_limited && q.nxt() < q.end()) {
      if (in_flight() >= cc.cwnd) {
        cwnd_limited = true;
        break;
      }
      sent.push_back(name('N', q.nxt()));
      send_at(q.nxt(), TxKind::data);
      new_sent = true;
    }
    while (!cwnd_limited && in_flight() < cc.cwnd) {
      auto c = rctx();
      const std::optional<std::uint64_t> off = rec.next_seg_extra(c);
      if (!off || q.find(*off) == nullptr || q.find(*off)->sacked) {
        break;
      }
      sent.push_back(name('R', *off));
      send_at(*off, TxKind::rexmit);
    }
    auto c = rctx();
    rec.on_burst_end(c, new_sent);
    return sent;
  }

  // An ACK of everything below packet `cum` (1-based: cum = k acknowledges
  // packets 1..k-1), SACKing the packet ranges [first, last] given.
  AckOutcome ack(std::uint32_t cum, std::vector<std::pair<std::uint32_t, std::uint32_t>> sacked = {},
                 std::optional<Range> dsack = std::nullopt, std::optional<std::uint32_t> tsecr = {}) {
    std::vector<Range> blocks;
    for (const auto& [first, last] : sacked) {
      blocks.push_back(Range{off_of(first), off_of(last + 1)});
    }
    AckInput in;
    in.now = now;
    in.prior_una = q.una();
    in.new_una = std::max(off_of(cum), q.una());
    in.sack = blocks;
    in.dsack = dsack;
    in.tsecr = tsecr;
    in.now_ts = static_cast<std::uint32_t>(now.ns / 1'000'000) + ts_offset;
    in.dupack = in.new_una == q.una() && q.counters().packets_out > 0;
    ctx = std::make_unique<AckContext>(AckContext{q, rec, rtt, cc, algo, rate, cfg, stats, ctr,
                                                  wnd, sack, backoff, rto_count, max_snd_wnd,
                                                  ts_offset, pacing_delay});
    const AckOutcome out = process_ack(*ctx, in);
    if (out.seq_rtt >= Duration::zero()) {
      backoff = 0;
    }
    if ((out.flags & ack_una_advanced) != 0) {
      rto_count = 0;
    }
    return out;
  }

  // The xmit timer as the engine sees it.
  std::pair<XmitTimer, Time> timer() {
    const auto c = rctx();
    return rec.xmit_timer(c);
  }

  // The engine's xmit expiry for REO (tcp_timers.cpp): recovery, then transmit.
  std::vector<std::string> fire_reo() {
    auto c = rctx();
    rec.on_xmit_timer(c, XmitTimer::reo);
    return transmit();
  }

  // The engine's RTO expiry (tcp_timers.cpp on_rto): recovery marks, backoff
  // and rto_count rise, the head goes out as rto_rexmit, then transmit.
  std::vector<std::string> fire_rto() {
    auto c = rctx();
    rec.on_rto(c);
    ++backoff;
    ++rto_count;
    std::vector<std::string> sent{name('R', q.una())};
    send_at(q.una(), TxKind::rto_rexmit);
    for (std::string& s : transmit()) {
      sent.push_back(std::move(s));
    }
    return sent;
  }

  const TxSeg& pkt(std::uint32_t k) const {
    const TxSeg* s = q.find(off_of(k));
    EXPECT_NE(s, nullptr) << "packet " << k;
    return *s;
  }

  TcpConfig cfg;
  ChunkPool pool{256};
  SendQueue q{pool, 1 << 22};
  RttEstimator rtt;
  FixedCc algo;
  CcConn cc;
  RateState rate;
  StackStats stats;
  TcpCounters ctr;
  LossRecovery rec;
  bool sack;
  Time now{1'000'000'000};
  std::uint32_t wnd = 1 << 22;
  std::uint8_t backoff = 0, rto_count = 0;
  std::uint32_t max_snd_wnd = 1 << 22;
  std::uint32_t ts_offset = 0;
  Duration pacing_delay{0};
  std::unique_ptr<AckContext> ctx;
};

// linux_compat's recovery (RACK-TLP, PRR) and the rfc profile's (RFC 6675
// scoreboard, cwnd = ssthresh), M2-DESIGN §1.2.
inline TcpConfig linux_cfg() { return tcp_config(ProfileId::linux_compat); }
inline TcpConfig rfc_cfg() { return tcp_config(ProfileId::rfc); }

}  // namespace utcp::test::rig
