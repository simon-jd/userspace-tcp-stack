#include "core/tcp/tx_policy.hpp"

#include <algorithm>
#include <limits>

#include "utcp/check.hpp"

namespace utcp {
namespace {

__extension__ using U128 = unsigned __int128;

constexpr std::uint64_t ns_per_s = 1'000'000'000;

constexpr std::uint64_t saturate_u64(U128 v) noexcept {
  return v > std::numeric_limits<std::uint64_t>::max() ? std::numeric_limits<std::uint64_t>::max()
                                                       : static_cast<std::uint64_t>(v);
}

}  // namespace

TxPolicy::TxPolicy(const TcpConfig& cfg)
    : nagle_(cfg.nagle),
      pacing_(cfg.pacing),
      sender_sws_(cfg.sender_sws),
      fixed_rate_(cfg.test_fixed_pacing_rate) {}

bool TxPolicy::sws_allows(const SendCheck& c) const {
  if (c.unsent == 0) {
    return c.fin;  // nothing to send but a FIN
  }
  if (!sender_sws_) {
    return true;
  }
  const std::uint64_t m = std::min<std::uint64_t>(c.unsent, c.usable_window);
  if (m == 0) {
    return false;  // no window: the persist timer probes (§4.9)
  }
  // RFC 9293 §3.8.6.2.1 (1): a maximum-sized segment can be sent.
  if (m >= c.mss) {
    return true;
  }
  // (2): all queued data can be sent now [and Nagle].
  if (c.unsent <= c.usable_window && nagle_allows(c)) {
    return true;
  }
  // (3): at least Fs = 1/2 of the largest window offered [and Nagle].
  return c.max_snd_wnd > 0 && 2 * m >= c.max_snd_wnd && nagle_allows(c);
}

bool TxPolicy::nagle_allows(const SendCheck& c) const {
  // Full segments, FIN and TCP_NODELAY are never held (tcp_nagle_test).
  if (c.nodelay || c.fin || c.seg_len >= c.mss) {
    return true;
  }
  if (nagle_ == Nagle::rfc896) {
    // RFC 9293 §3.7.4: hold a small segment while any data is unacknowledged.
    return c.snd_nxt == c.snd_una;
  }
  // tcp_minshall_check: hold while a segment shorter than mss is unacknowledged.
  const bool small_unacked = snd_sml_ > c.snd_una && snd_sml_ <= c.snd_nxt;
  return !small_unacked;
}

void TxPolicy::on_data_sent(std::uint64_t off, std::uint32_t len, std::uint32_t mss) {
  if (len < mss) {
    snd_sml_ = off + len;  // tcp_minshall_update
  }
}

bool TxPolicy::pacing_applies(const CcConn& cc, std::uint64_t data_segs_out) const {
  // sch_fq and Linux internal pacing do not pace the first 10 segments
  // (tcp_update_skb_after_send: data_segs_out >= 10).
  if (data_segs_out < 10) {
    return false;
  }
  if (fixed_rate_.has_value()) {
    return true;
  }
  switch (pacing_) {
    case Pacing::always: return true;
    case Pacing::never: return false;
    case Pacing::cc_requested: return cc.pacing_needed;
  }
  return false;
}

std::uint64_t TxPolicy::gate_rate(const CcConn& cc) const {
  return fixed_rate_.value_or(cc.pacing_rate);
}

// As Linux tcp_tso_autosize() with sk_pacing_shift 10 and tcp_tso_rtt_log 9.
std::uint32_t pacing_burst_segments(std::uint64_t rate, Duration min_rtt,
                                    std::uint32_t gso_max_size, std::uint32_t mss,
                                    std::uint32_t min_tso_segs) {
  UTCP_CHECK(mss > 0);
  std::uint64_t bytes = rate >> 10;  // about 1 ms of data at the pacing rate
  // tcp_min_rtt() is a u32 of microseconds, ~0U before a sample.
  const std::int64_t us = min_rtt.count() < 0 ? 0 : min_rtt.count() / 1000;
  const std::uint64_t min_rtt_us = std::min<std::uint64_t>(static_cast<std::uint64_t>(us),
                                                           std::numeric_limits<std::uint32_t>::max());
  const std::uint64_t r = min_rtt_us >> 9;
  if (r < 32) {
    bytes += gso_max_size >> r;  // short RTTs get larger bursts
  }
  bytes = std::min<std::uint64_t>(bytes, gso_max_size);
  return std::max(static_cast<std::uint32_t>(bytes / mss), min_tso_segs);
}

Time pacing_next_after_send(Time pacing_next, Time now, std::uint64_t len, std::uint64_t rate) {
  const Time base = std::max(pacing_next, now);
  if (rate == 0) {
    return base;
  }
  std::uint64_t len_ns = saturate_u64(U128{len} * ns_per_s / rate);
  // Lateness is credited up to half of this burst's own interval (OS jitter).
  const Duration late = now - pacing_next;
  const std::uint64_t credit = late.count() > 0 ? static_cast<std::uint64_t>(late.count()) : 0;
  len_ns -= std::min(len_ns / 2, credit);
  const auto max_ns = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  return base + Duration{static_cast<std::int64_t>(std::min(len_ns, max_ns))};
}

std::uint64_t pacing_rate_for(const CcConn& cc, std::uint32_t packets_out, const TcpConfig& cfg) {
  if (cc.srtt <= Duration{0}) {
    return 0;
  }
  // 200 % of mss * cwnd / srtt in slow start, 120 % in congestion avoidance;
  // cwnd >= ssthresh / 2 counts as approaching the end of slow start.
  const std::uint32_t ratio = cc.cwnd < cc.ssthresh / 2 ? cfg.pacing_ss_ratio : cfg.pacing_ca_ratio;
  const U128 num = U128{cc.mss} * ratio * std::max(cc.cwnd, packets_out) * ns_per_s;
  const U128 den = U128{100} * static_cast<std::uint64_t>(cc.srtt.count());
  std::uint64_t rate = saturate_u64(num / den);
  if (cc.max_pacing_rate != 0) {
    rate = std::min(rate, cc.max_pacing_rate);
  }
  return rate;
}

}  // namespace utcp
