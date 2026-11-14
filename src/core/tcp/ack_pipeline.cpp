#include "core/tcp/ack_pipeline.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <limits>
#include <optional>

#include "core/tcp/tx_policy.hpp"
#include "utcp/check.hpp"

namespace utcp {
namespace {

// Linux tcp_ack_update_rtt: delta < INT_MAX / (USEC_PER_SEC / TCP_TS_HZ).
constexpr std::uint32_t tsecr_max_delta = 2'147'483;

std::uint32_t saturate_u32(std::uint64_t v) {
  return v > std::numeric_limits<std::uint32_t>::max() ? std::numeric_limits<std::uint32_t>::max()
                                                       : static_cast<std::uint32_t>(v);
}

void refresh_views(AckContext& c, Time now) {
  const Counters& k = c.q.counters();
  c.cc.ca_state = c.recovery.state();
  c.cc.in_flight = packets_in_flight(k);
  c.cc.packets_out = k.packets_out;
  c.cc.snd_una = c.q.una();
  c.cc.snd_nxt = c.q.nxt();
  c.cc.delivered = c.rate.delivered;
  c.cc.lost = c.q.lost_total();
  c.cc.now = now;
  c.cc.delivered_time = c.rate.delivered_time;
  c.cc.srtt = c.rtt.srtt();
  c.cc.min_rtt = c.rtt.min_rtt();
  c.cc.app_limited = c.rate.app_limited;  // one value (M2-DESIGN §2.1 item 7)
}

// Linux tcp_dsack_seen (tcp_input.c:1233): the number of segments a D-SACK
// block counts as delivered, 0 if it is dubious. Flags go to out.
std::uint32_t dsack_seen(AckContext& c, const LossRecovery& rec, Range d, AckOutcome& out) {
  if (d.empty()) {
    return 0;
  }
  const std::uint64_t len = d.end - d.begin;
  // Dubious: longer than the largest window the peer advertised.
  if (len > c.max_snd_wnd) {
    return 0;
  }
  const std::uint64_t mss = std::max<std::uint64_t>(c.cc.mss, 1);
  std::uint64_t dup_segs = 1;
  if (len > mss) {
    dup_segs = (len + mss - 1) / mss;
  } else if (const auto tlp = rec.tlp_high_seq(); tlp && *tlp == d.end) {
    out.flags |= ack_dsack_tlp;  // FLAG_DSACK_TLP
  }
  // Counted before the test, as Linux: the sum stays above total_retrans
  // once duplicates the sender did not cause have arrived.
  c.ctr.dsack_dups += dup_segs;
  if (c.ctr.dsack_dups > c.ctr.total_retrans) {
    return 0;  // not caused by our retransmissions
  }
  out.flags |= ack_dsack;  // FLAG_DSACKING_ACK
  return saturate_u32(dup_segs);
}

}  // namespace

AckOutcome process_ack(AckContext& c, const AckInput& in) {
  return process_ack(c, in, [](const TxSeg&, bool) {});
}

AckOutcome process_ack(AckContext& c, const AckInput& in, DeliveredFn observe) {
  SendQueue& q = c.q;
  const Time now = in.now;
  UTCP_DCHECK(c.sack_ok == q.sack_ok());
  UTCP_DCHECK(in.prior_una == q.una());
  AckOutcome out;

  // The seq/offset boundary (§3.2): SEG.ACK = end() + 1 covers our FIN.
  // fin_acked: this ACK is the first to cover it.
  const std::uint64_t prior_una = q.una();
  const std::uint64_t prior_una_fin = q.una_with_fin();
  bool fin_acked = false;
  std::uint64_t new_una = in.new_una;
  if (new_una > q.end()) {
    fin_acked = q.fin_sent() && !q.fin_acked();
    new_una = q.end();
  }
  new_una = std::clamp(new_una, prior_una, q.nxt());
  std::array<Range, max_sack_ranges> blocks{};
  std::size_t nblocks = 0;
  for (const Range& b : in.sack) {
    if (nblocks == blocks.size()) {
      break;
    }
    // Linux tcp_is_sackblock_valid checks against the updated SND.UNA: a
    // block must start above it. Above end() (our FIN) it is clipped.
    const Range r{b.begin, std::min(b.end, q.end())};
    if (b.begin > new_una && !r.empty()) {
      blocks[nblocks++] = r;
    }
  }
  // D-SACK (RFC 2883; Linux tcp_check_dsack, tcp_dsack_seen; M2-DESIGN §1.6).
  // TCPDSACKRecv counts D-SACK blocks; a valid one counts its segments as
  // delivered ("a spurious retransmission is delivered").
  std::uint32_t dsack_delivered = 0;
  if (in.dsack) {
    ++c.stats.TcpExtTCPDSACKRecv;
    dsack_delivered = dsack_seen(c, c.recovery, *in.dsack, out);
    if (dsack_delivered > 0) {
      c.stats.TcpExtTCPDSACKRecvSegs += dsack_delivered;
    } else {
      ++c.stats.TcpExtTCPDSACKIgnoredDubious;
    }
  }

  const std::uint32_t prior_packets = q.counters().packets_out;
  const std::uint64_t prior_lost = q.lost_total();
  const bool prior_sack_reneg = c.recovery.sack_reneg();
  out.prior_in_flight = packets_in_flight(q.counters());

  RecoveryCtx rctx{q,       c.cc,     c.algo,  c.rtt,   c.cfg,      now,
                   c.snd_wnd, c.stats, c.sack_ok, c.backoff, c.rto_count};
  rctx.in = &in;
  rctx.ts_offset = c.ts_offset;
  rctx.max_snd_wnd = c.max_snd_wnd;
  rctx.total_retrans = c.ctr.total_retrans;
  rctx.dsack_dups = c.ctr.dsack_dups;
  rctx.delivered = c.rate.delivered;
  rctx.pacing_delay = c.pacing_delay;
  const std::optional<std::uint64_t> recover = c.recovery.recover();

  // Per newly delivered segment (tcp_sacktag_one, tcp_clean_rtx_queue).
  RateAck rack;
  std::optional<Time> first_ackt, last_ackt, first_sackt, last_sackt;
  std::uint32_t cum_delivered = 0;
  bool orig_acked = false;
  auto on_delivered = [&](const TxSeg& seg, bool via_sack) {
    observe(seg, via_sack);
    c.recovery.on_delivered(rctx, seg, via_sack);
    rate_on_delivered(c.rate, rack, seg, now);
    if (!via_sack) {
      ++cum_delivered;
    }
    if (seg.ever_retrans) {
      return;  // Karn (RFC 6298 §3): no timing from a retransmitted segment
    }
    std::optional<Time>& first = via_sack ? first_sackt : first_ackt;
    std::optional<Time>& last = via_sack ? last_sackt : last_ackt;
    if (!first) {
      first = seg.last_tx;
    }
    last = seg.last_tx;
    if (!recover || seg.end() <= *recover) {
      orig_acked = true;
    }
  };

  // SACK tagging before the cumulative cleanup (Linux tcp_ack order).
  out.newly_sacked =
      q.on_sack(std::span<const Range>(blocks.data(), nblocks), now, on_delivered).newly_sacked;
  const std::uint32_t sacked_before_cum = q.counters().sacked_out;
  const AckedSummary acked = q.on_cumulative_ack(new_una, fin_acked, now, on_delivered);
  out.acked_pkts = acked.pkts;
  if (!c.sack_ok && acked.pkts > 0) {
    // tcp_remove_reno_sacks: one ACK acked the hole, the rest ate dupacks.
    cum_delivered = std::max(acked.pkts - std::min(acked.pkts, sacked_before_cum), 1u);
  }
  out.delivered = out.newly_sacked + cum_delivered + dsack_delivered;
  const std::uint64_t una_fin = q.una_with_fin();
  if (una_fin > prior_una_fin) {
    out.flags |= ack_una_advanced;
  }
  if (acked.retrans_acked) {
    out.flags |= ack_retrans_data_acked;
  }
  if (orig_acked && !(!c.sack_ok && acked.retrans_acked)) {
    out.flags |= ack_orig_sack_acked;
  }
  if (acked.stopped_at_sacked) {
    out.flags |= ack_sack_reneging;
  }
  if (fin_acked) {
    out.flags |= ack_fin_acked;
  }
  // Packets delivered so far count this ACK's (Linux tcp_count_delivered).
  const std::uint32_t delivered_before_recovery = out.delivered;
  c.rate.delivered += delivered_before_recovery;

  // RTT samples (tcp_clean_rtx_queue, tcp_ack_update_rtt).
  Duration seq_rtt{-1}, ca_rtt{-1}, sack_rtt{-1};
  if (first_ackt && !acked.retrans_acked) {
    seq_rtt = now - *first_ackt;
    ca_rtt = now - *last_ackt;
    // Not with FLAG_CA_ALERT: newly SACKed data or a D-SACK.
    if (acked.pkts == 1 && sacked_before_cum == 0 && una_fin - prior_una_fin < c.cc.mss &&
        rack.has_prior && rack.prior_delivered + 1 == c.rate.delivered && out.newly_sacked == 0 &&
        (out.flags & ack_dsack) == 0) {
      out.flags |= ack_maybe_delayed;  // a lone runt, likely a delayed ACK
    }
  }
  if (first_sackt) {
    sack_rtt = now - *first_sackt;
    ca_rtt = now - *last_sackt;
  }
  if (seq_rtt < Duration::zero()) {
    seq_rtt = sack_rtt;
  }
  if (in.old_ack) {
    seq_rtt = ca_rtt = Duration{-1};  // the old_ack path takes no RTT sample
  }
  if (seq_rtt < Duration::zero() && in.tsecr && *in.tsecr != 0 && acked.pkts > 0) {
    // RFC 7323 §4 (Linux tcp_rtt_tsopt_us), 1 ms TS ticks.
    const std::uint32_t delta = in.now_ts - *in.tsecr;
    if (delta < tsecr_max_delta) {
      seq_rtt = ca_rtt = std::chrono::milliseconds{std::max(delta, 1u)};
    }
  }
  if (seq_rtt >= Duration::zero()) {
    c.rtt.on_min_rtt_sample(ca_rtt, (out.flags & ack_maybe_delayed) != 0, now);
    c.rtt.on_srtt_sample(seq_rtt, q.una_with_fin(), q.nxt_with_fin());
    rctx.backoff = 0;  // RFC 6298 §5.7; the engine resets its own (§4.8)
  }
  out.seq_rtt = seq_rtt;
  out.ca_rtt = ca_rtt;

  // The rate snapshot recovery reads (tcp_rack_update_reo_wnd).
  rctx.has_prior = rack.has_prior;
  rctx.prior_delivered = rack.prior_delivered;
  rctx.delivered = c.rate.delivered;

  refresh_views(c, now);
  if (prior_packets > 0 && !in.old_ack) {
    AckSample sample;
    sample.pkts_acked = acked.pkts;
    sample.rtt = ca_rtt;
    const std::uint64_t prior_delivered = rack.has_prior ? rack.prior_delivered : 0;
    sample.in_flight = saturate_u32(std::uint64_t{c.cc.mss} * (c.rate.delivered - prior_delivered));
    c.algo.pkts_acked(c.cc, sample);
  }

  // Loss detection and the CaState (tcp_fastretrans_alert), timers.
  c.recovery.on_ack(rctx, in, out);
  c.rate.delivered += out.delivered - delivered_before_recovery;  // reno dupacks
  rctx.delivered = c.rate.delivered;
  out.newly_lost = saturate_u32(q.lost_total() - prior_lost);
  out.in_flight = packets_in_flight(q.counters());
  c.stats.TcpExtTCPDelivered += out.delivered;

  if (in.old_ack) {
    return out;  // Linux old_ack: tcp_newly_delivered only, no rate sample, no CC
  }
  // tcp_rate_gen (Linux 7.0 tcp_input.c:1724), with rs.rtt = ca_rtt
  // (tcp_ack_update_rtt) and rs.is_ack_delayed (tcp_ack, 4404).
  c.sample = rate_gen(c.rate, rack, out.delivered, out.newly_lost, out.prior_in_flight,
                      prior_sack_reneg, c.rtt.min_rtt(), out.ca_rtt,
                      (out.flags & ack_maybe_delayed) != 0, now);
  out.rs = &c.sample;
  const RateSample& rs = c.sample;

  // tcp_cong_control (tcp_input.c:3858).
  refresh_views(c, now);
  if (c.algo.has_cong_control()) {
    c.algo.cong_control(c.cc, out, rs);
    c.rate.app_limited = c.cc.app_limited;  // BBR's PROBE_RTT write (§2.1 item 7)
    return out;  // the CC set the pacing rate itself
  }
  const CaState s = c.recovery.state();
  if (s == CaState::cwr || s == CaState::recovery) {  // tcp_in_cwnd_reduction
    c.recovery.cwnd_reduction(rctx, out.delivered, rs.losses, out.flags);
  } else if (c.recovery.may_raise_cwnd(rctx, out)) {
    const bool limited = c.cc.cwnd_limited;
    if (!c.cfg.cwnd_growth_needs_cwnd_limited) {
      c.cc.cwnd_limited = true;
    }
    c.algo.cong_avoid(c.cc, out);
    c.cc.cwnd_limited = limited;
  }
  c.cc.pacing_rate = pacing_rate_for(c.cc, q.counters().packets_out, c.cfg);  // tcp_update_pacing_rate
  return out;
}

}  // namespace utcp
