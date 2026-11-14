// Directed simulator scenarios for RFC 5961 (m1-tcp-robust acceptance tests
// 1 and 6): while a 10 MB transfer runs both ways over links with loss and
// reordering, segments forged in the name of node a are delivered to node
// b's stack. The Tap records b's counters around each forged segment, so
// each check sees exactly what b did with that segment; the transfer must
// still complete with every byte intact.
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

// What the forger knows about the connection, from the segments b sends and
// receives.
struct View {
  Endpoint a, b;
  Seq32 rcv_nxt{0};   // b's RCV.NXT (the ACK field of b's latest segment)
  Seq32 snd_nxt{0};   // b's highest sequence sent + 1
  Seq32 a_ack{0};     // the ACK field of a's latest segment (b's SND.UNA, as a knows it)
  std::optional<std::uint32_t> b_tsval, a_tsval;
  std::optional<std::uint8_t> b_ws, a_ws;  // from the SYNs
  std::uint32_t wnd = 0;  // b's latest advertised window, bytes
  bool synced = false;

  // A sequence number inside b's window even if RCV.NXT moved on by up to
  // half a window since b's latest segment.
  [[nodiscard]] Seq32 in_window() const { return rcv_nxt + std::max<std::uint32_t>(wnd / 2, 1); }

  void on_b_egress(const Seg& g) {
    if (g.has(wire::tcp_syn)) {
      b_ws = g.opt.wscale;
      return;
    }
    if (g.has(wire::tcp_rst)) {
      return;
    }
    wnd = std::uint32_t{g.h.window} << (a_ws && b_ws ? *b_ws : 0);
    b = g.src;
    a = g.dst;
    if (g.has(wire::tcp_ack)) {
      rcv_nxt = g.h.ack;
    }
    const Seq32 end = g.h.seq + g.seq_len();
    if (!synced || after(end, snd_nxt)) {
      snd_nxt = end;
    }
    synced = true;
    if (g.opt.ts) {
      b_tsval = g.opt.ts->val;
    }
  }
  void on_b_ingress(const Seg& g) {
    if (g.has(wire::tcp_syn)) {
      a_ws = g.opt.wscale;
    }
    if (g.has(wire::tcp_ack) && !g.has(wire::tcp_rst)) {
      a_ack = g.h.ack;
    }
    if (g.opt.ts && (!a_tsval || after(Seq32(g.opt.ts->val), Seq32(*a_tsval)))) {
      a_tsval = g.opt.ts->val;
    }
  }

  // A segment from a to b with a's latest TSval (so PAWS passes).
  [[nodiscard]] std::vector<std::byte> forge(std::uint16_t flags, Seq32 seq, Seq32 ack,
                                             std::span<const std::byte> payload = {}) const {
    TcpSegmentSpec t;
    t.src = a;
    t.dst = b;
    t.seq = seq.raw();
    t.ack = ack.raw();
    t.flags = flags;
    t.window = 1000;
    if (a_tsval) {
      t.opt.ts = wire::Timestamps{*a_tsval, b_tsval.value_or(0)};
    }
    t.payload = payload;
    return build_tcp(t);
  }
};

std::uint64_t delta(const Tap::Injected& i, std::uint64_t StackStats::* f) {
  return i.after.*f - i.before.*f;
}

enum class Kind : std::uint8_t {
  rst_in_window,
  rst_out_of_window,
  syn,
  ack_above_snd_nxt,
  ack_below_window,
  oow_ack_burst,     // 10 out-of-window pure ACKs within 100 ms
  dup_data_burst,    // 10 duplicate data segments within 100 ms
  rst_burst,         // 5 in-window RSTs within 100 ms
};

TEST(TcpRfc5961Sim, ForgedSegmentsDuringATransfer) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    for (const bool ts : {true, false}) {
      SCOPED_TRACE(std::to_string(static_cast<int>(profile)) + (ts ? " ts" : " no ts"));
      // a's pure ACKs are not reordered behind its data: a reordered pure ACK
      // below RCV.NXT is unacceptable (RFC 9293 §3.10.7.4) and its rate-limited
      // duplicate ACK would share the limiter with the challenge ACKs checked
      // here. b's direction reorders.
      LinkParams ab = impaired(5ms, 10'000);
      ab.jitter = 0ms;
      ab.allow_reorder = false;
      ab.rate_bps = 10'000'000;
      ab.queue_bytes = 200'000;
      LinkParams ba = impaired(5ms, 10'000);
      ba.rate_bps = 10'000'000;
      ba.queue_bytes = 200'000;
      Scenario s = two_node_scenario(9000 + (ts ? 1 : 0) + (profile == ProfileId::rfc ? 2 : 0), ab, ba);
      for (NodeSpec& n : s.node) {
        n.profile = profile;
        n.timestamps = ts;
      }
      s.conn.push_back(bulk(10'000'000, 3'000'000));
      View v;
      Tap* tap_b = nullptr;
      // (kind, index of the first injection, count)
      std::vector<std::tuple<Kind, std::size_t, std::size_t>> plan;
      RunSpec spec;
      spec.setup = [&](std::vector<Tap*>& taps) {
        tap_b = taps[1];
        Tap& b = *taps[1];
        b.egress = [&](Tap&, Time t, std::span<const std::byte> d) {
          if (const auto g = parse_seg(1, true, t, d)) {
            v.on_b_egress(*g);
          }
          return true;
        };
        b.ingress = [&](Tap&, Time t, std::span<const std::byte> d) {
          if (const auto g = parse_seg(1, false, t, d)) {
            v.on_b_ingress(*g);
          }
          return true;
        };
        Time at = s.start + 1s;
        const auto add = [&](Kind k, std::size_t count, Duration spacing,
                             std::function<std::vector<std::byte>()> f) {
          plan.emplace_back(k, b.injected().size(), count);
          for (std::size_t i = 0; i < count; ++i) {
            b.inject_at(at + spacing * static_cast<std::int64_t>(i), f);
          }
          at = at + 700ms;  // beyond the 500 ms per-connection limiter
        };
        add(Kind::rst_in_window, 1, 0ms, [&] { return v.forge(wire::tcp_rst, v.in_window(), Seq32(0)); });
        add(Kind::rst_out_of_window, 1, 0ms,
            [&] { return v.forge(wire::tcp_rst, v.rcv_nxt + (1u << 30), Seq32(0)); });
        add(Kind::syn, 1, 0ms, [&] { return v.forge(wire::tcp_syn, v.in_window(), Seq32(0)); });
        add(Kind::ack_above_snd_nxt, 1, 0ms,
            [&] { return v.forge(wire::tcp_ack, v.in_window(), v.snd_nxt + 1'000'000); });
        add(Kind::ack_below_window, 1, 0ms,
            [&] { return v.forge(wire::tcp_ack, v.in_window(), v.snd_nxt - (1u << 28)); });
        add(Kind::oow_ack_burst, 10, 10ms,
            [&] { return v.forge(wire::tcp_ack, v.rcv_nxt + (1u << 30), v.a_ack); });
        static const std::vector<std::byte> junk(1000, std::byte{0x5a});
        add(Kind::dup_data_burst, 10, 10ms,
            [&] { return v.forge(wire::tcp_ack, v.rcv_nxt - 3000, v.a_ack, junk); });
        add(Kind::rst_burst, 5, 20ms, [&] { return v.forge(wire::tcp_rst, v.in_window(), Seq32(0)); });
      };
      const Outcome o = run_sim(s, spec);
      ASSERT_TRUE(o.ok()) << o.violations();
      EXPECT_EQ(o.counts[1].tcp_bytes_received, 10'000'000u);
      EXPECT_EQ(o.counts[0].tcp_bytes_received, 3'000'000u);
      ASSERT_NE(tap_b, nullptr);
      const auto& inj = tap_b->injected();
      for (const auto& [kind, first, count] : plan) {
        SCOPED_TRACE(static_cast<int>(kind));
        std::uint64_t challenge = 0, skipped_challenge = 0, out = 0, skipped_seq = 0, dsack = 0,
                      syn_challenge = 0, rsts = 0;
        for (std::size_t i = first; i < first + count; ++i) {
          ASSERT_TRUE(inj[i].delivered);
          challenge += delta(inj[i], &StackStats::TcpExtTCPChallengeACK);
          skipped_challenge += delta(inj[i], &StackStats::TcpExtTCPACKSkippedChallenge);
          out += delta(inj[i], &StackStats::TcpOutSegs);
          skipped_seq += delta(inj[i], &StackStats::TcpExtTCPACKSkippedSeq);
          dsack += delta(inj[i], &StackStats::TcpExtTCPDSACKOldSent);
          syn_challenge += delta(inj[i], &StackStats::TcpExtTCPSYNChallenge);
          rsts += delta(inj[i], &StackStats::TcpOutRsts);
          if (kind == Kind::dup_data_burst) {
            // RFC 5961 §5 exempts data: every duplicate is ACKed with a D-SACK.
            EXPECT_EQ(delta(inj[i], &StackStats::TcpOutSegs), 1u) << i;
            EXPECT_EQ(delta(inj[i], &StackStats::TcpExtTCPDSACKOldSent), 1u) << i;
          }
        }
        EXPECT_EQ(rsts, 0u);
        switch (kind) {
          case Kind::rst_in_window:      // §3.2: challenge ACK
          case Kind::ack_above_snd_nxt:  // §5.2: ACK (a challenge ACK) and drop
          case Kind::ack_below_window:   // §5.2: below SND.UNA - MAX.SND.WND
            EXPECT_EQ(challenge, 1u);
            EXPECT_EQ(out, 1u);
            break;
          case Kind::syn:  // §4.2: challenge ACK
            EXPECT_EQ(syn_challenge, 1u);
            EXPECT_EQ(challenge, 1u);
            EXPECT_EQ(out, 1u);
            break;
          case Kind::rst_out_of_window:  // §3.2: dropped silently
            EXPECT_EQ(out, 0u);
            EXPECT_EQ(challenge + skipped_challenge, 0u);
            break;
          case Kind::oow_ack_burst:  // §3.9 oow_ack_interval: one ACK in 500 ms
            EXPECT_EQ(out, 1u);
            EXPECT_EQ(skipped_seq, 9u);
            break;
          case Kind::dup_data_burst:
            EXPECT_EQ(out, 10u);
            EXPECT_EQ(dsack, 10u);
            break;
          case Kind::rst_burst:  // at most one challenge ACK per 500 ms
            EXPECT_EQ(challenge, 1u);
            EXPECT_EQ(skipped_challenge, 4u);
            EXPECT_EQ(out, 1u);
            break;
        }
      }
    }
  }
}

}  // namespace
}  // namespace utcp::sim
