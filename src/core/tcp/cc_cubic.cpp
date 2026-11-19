// SPDX-License-Identifier: GPL-2.0-only
// Linux fixed-point model and root table from v7.0 net/ipv4/tcp_cubic.c.
#include "core/tcp/cc_cubic.hpp"

#include <algorithm>
#include <bit>
#include <limits>

#include "core/tcp/cc_newreno.hpp"

namespace utcp {
namespace {
constexpr auto max_window = std::numeric_limits<std::uint32_t>::max();
constexpr std::uint64_t one = std::uint64_t{1} << 32;
constexpr std::uint64_t max_q32 = std::uint64_t{max_window} * one;

std::uint32_t bounded(std::uint64_t n) {
  return static_cast<std::uint32_t>(std::min<std::uint64_t>(n, max_window));
}

std::uint64_t to_cubic_ticks(std::uint64_t ms) { return ms * 1024 / 1000; }

// RFC 9438 §4.2, W_cubic(t), in Q32 packets. Saturate before long epochs
// can wrap the polynomial; offsets >= 2^22 exceed every representable cwnd.
std::uint64_t curve(std::uint32_t origin, std::uint32_t k, std::uint64_t ticks) {
  const auto offset = ticks < k ? k - ticks : ticks - k;
  if (offset >= (1u << 22)) return ticks < k ? 0 : max_q32;
  const auto delta = (__uint128_t{cube_rtt_scale} * offset * offset * offset) >> 8;
  const auto base = std::uint64_t{origin} * one;
  if (ticks < k) return delta < base ? base - static_cast<std::uint64_t>(delta) : 0;
  return base + static_cast<std::uint64_t>(std::min<__uint128_t>(delta, max_q32 - base));
}
}  // namespace

std::uint32_t cubic_root(std::uint64_t value) {
  constexpr std::uint8_t table[] = {
      0,54,54,54,118,118,118,118,123,129,134,138,143,147,151,156,
      157,161,164,168,170,173,176,179,181,185,187,190,192,194,197,199,
      200,202,204,206,209,211,213,215,217,219,221,222,224,225,227,229,
      231,232,234,236,237,239,240,242,244,245,246,248,250,251,252,254};
  const auto bits = static_cast<std::uint32_t>(std::bit_width(value));
  if (bits < 7) return (table[value] + 35u) >> 6;
  const auto shift = ((bits * 84) >> 8) - 1;
  const auto index = value >> (3 * shift);
  auto x = ((table[index] + 10u) << shift) >> 6;
  x = 2 * x + static_cast<std::uint32_t>(value / (std::uint64_t{x} * (x - 1)));
  return (x * 341) >> 10;
}

std::string_view Cubic::name() const { return "cubic"; }
void Cubic::init(CcConn& c) {
  *this = Cubic{};
  classic_.reset_round(c);
}
void emplace_cubic(CcStorage& s) { s.emplace<Cubic>(); }

std::uint32_t Cubic::ssthresh(const CcConn& c) {
  // RFC 9438 §§4.6-4.7; Linux cubictcp_recalc_ssthresh.
  plus_.end();
  epoch_.reset();
  pause_.reset();
  prior_ = c.cwnd;
  last_max_ = c.cwnd < last_max_ ? bounded(std::uint64_t{c.cwnd} * (1024 + cubic_beta) / 2048)
                                 : c.cwnd;
  const auto flight = c.flavor == CcFlavor::rfc ? c.packets_out : c.cwnd;
  return std::max(bounded(std::uint64_t{flight} * cubic_beta / 1024), 2u);
}

void Cubic::begin_epoch(const CcConn& c) {
  epoch_ = jiffies(c.now);
  origin_ = std::max(last_max_, c.cwnd);
  k_ = cubic_root(cube_factor * (origin_ - c.cwnd));
  tcp_cwnd_ = c.cwnd;
  estimate_ = std::uint64_t{c.cwnd} * one;
  fraction_ = 0;
  // RFC 9438 §4.10: first loss-free exit from slow start.
  if (prior_ == 0) prior_ = c.cwnd;
}

void Cubic::linux_update(CcConn& c, std::uint32_t acked) {
  const auto now = jiffies(c.now);
  ack_cnt_ += acked;
  if (cnt_ != 0 && last_cwnd_ == c.cwnd && static_cast<std::int32_t>(now - last_time_) <= 31) {
    cong_avoid_ai(c, cnt_, acked);
    return;
  }
  if (!epoch_ || now != last_time_) {
    last_cwnd_ = c.cwnd;
    last_time_ = now;
    if (!epoch_) {
      begin_epoch(c);
      ack_cnt_ = acked;
    }
    const auto ms = std::uint64_t{now - *epoch_} + (std::uint64_t{delay_min_us_} + 999) / 1000;
    const auto ticks = to_cubic_ticks(ms);
    // Preserve bictcp_update's u64 polynomial and u32 target. In
    // particular a long epoch has exactly the kernel's unsigned wrap.
    const auto offset = ticks < k_ ? k_ - ticks : ticks - k_;
    const auto delta = static_cast<std::uint32_t>((cube_rtt_scale * offset * offset * offset) >> 40);
    const auto target = ticks < k_ ? origin_ - delta : origin_ + delta;
    cnt_ = target > c.cwnd ? c.cwnd / (target - c.cwnd) : 100u * c.cwnd;
    if (last_max_ == 0) cnt_ = std::min(cnt_, 20u);
  }
  // bictcp_update uses a strict '>' when spending Reno credits.
  const auto threshold = std::max<std::uint64_t>(1, std::uint64_t{c.cwnd} * cubic_beta_scale / 8);
  if (ack_cnt_ > threshold) {
    const auto increments = (ack_cnt_ - 1) / threshold;
    ack_cnt_ -= increments * threshold;
    tcp_cwnd_ = bounded(tcp_cwnd_ + increments);
  }
  if (tcp_cwnd_ > c.cwnd) cnt_ = std::min(cnt_, c.cwnd / (tcp_cwnd_ - c.cwnd));
  cnt_ = std::max(cnt_, 2u);
  cong_avoid_ai(c, cnt_, acked);
}

void Cubic::rfc_update(CcConn& c, std::uint32_t acked) {
  if (!epoch_) begin_epoch(c);
  const auto elapsed = jiffies(c.now) - *epoch_;
  // RFC 9438 §4.3: W_est += alpha * segments_acked / cwnd; alpha becomes
  // one when W_est reaches the window before the last reduction.
  constexpr auto alpha = one * 3 * (1024 - cubic_beta) / (1024 + cubic_beta);
  const auto gain = estimate_ >= std::uint64_t{prior_} * one ? one : alpha;
  const auto window = std::max(c.cwnd, 1u);
  estimate_ += std::min(gain * acked / window, max_q32 - estimate_);
  auto current = std::uint64_t{c.cwnd} * one + fraction_;
  if (curve(origin_, k_, to_cubic_ticks(elapsed)) < estimate_) {
    current = std::max(current, estimate_);
  } else {
    // §§4.2, 4.4-4.5: use SRTT for the target. The cubic increase is per
    // new ACK, whereas the Reno estimate above counts delivered segments.
    const auto srtt_ns = static_cast<std::uint64_t>(std::max(c.srtt.count(), std::int64_t{0}));
    const auto ticks = to_cubic_ticks(elapsed) + srtt_ns / 1'000'000'000 * 1024
        + (srtt_ns % 1'000'000'000) * 1024 / 1'000'000'000;
    const auto target = curve(origin_, k_, ticks);
    const auto gap = target > current ? target - current : 0;
    const auto increment = std::min(gap / window, one / 2);
    current += std::min(increment, max_q32 - current);
  }
  current = std::min(current, std::uint64_t{effective_cwnd_clamp(c)} * one);
  c.cwnd = static_cast<std::uint32_t>(current >> 32);
  fraction_ = current % one;
}

void Cubic::cong_avoid(CcConn& c, const AckOutcome& out) {
  const bool rfc = c.flavor == CcFlavor::rfc;
  const auto now = jiffies(c.now);
  if (!is_cwnd_limited(c)) {
    if (rfc && epoch_ && !pause_) pause_ = now;
    return;
  }
  if (pause_) {
    shift_epoch(now, now - *pause_);
    pause_.reset();
  }
  auto acked = out.delivered;
  if (c.cwnd < c.ssthresh) {
    const auto limit = c.hystart == Hystart::hystart_pp && plus_.active(c)
        ? plus_.growth(c, acked) : (rfc ? 1u : acked);
    acked = slow_start(c, acked, limit);
  }
  if (acked == 0) return;
  if (rfc) rfc_update(c, acked);
  else linux_update(c, acked);
}

void Cubic::shift_epoch(std::uint32_t now, std::uint32_t idle) {
  if (epoch_) *epoch_ += std::min(now - *epoch_, idle);
}

void Cubic::cwnd_event(CcConn& c, CaEvent event) {
  if (event == CaEvent::cwnd_restart && c.flavor == CcFlavor::rfc) {
    // RFC 5681 §4.1: the caller applies RW after this event. Let the first
    // avoidance ACK seed the curve, Reno estimate and fraction from that window.
    epoch_.reset();
    pause_.reset();
    return;
  }
  if (event != CaEvent::tx_start || !epoch_) return;
  const auto now = jiffies(c.now);
  const auto idle = now - jiffies(c.lsndtime);
  if (static_cast<std::int32_t>(idle) <= 0) return;
  // On RFC flows a pause observed by cong_avoid and a send-side idle
  // period may overlap. Exclude their union once.
  if (pause_) {
    shift_epoch(now, std::max(idle, now - *pause_));
    pause_ = now;
  } else {
    shift_epoch(now, idle);
  }
}

void Cubic::set_state(CcConn& c, CaState state) {
  if (state == CaState::loss) {
    // §4.8: forget W_max on RTO but preserve cwnd_prior for Reno friendliness.
    const auto previous = prior_;
    init(c);
    plus_.end();
    if (c.flavor == CcFlavor::rfc) prior_ = previous;
  }
}

void Cubic::pkts_acked(CcConn& c, const AckSample& sample) {
  if (c.hystart == Hystart::hystart_pp && plus_.active(c) && c.cwnd < c.ssthresh)
    plus_.sample(c, sample.rtt);
  if (sample.rtt.count() < 0) return;
  if (epoch_ && static_cast<std::int32_t>(jiffies(c.now) - *epoch_) < 1000) return;
  const auto us = bounded(static_cast<std::uint64_t>(sample.rtt.count()) / 1000);
  if (delay_min_us_ == 0 || us < delay_min_us_) delay_min_us_ = std::max(us, 1u);
  if (c.hystart == Hystart::hystart_classic && c.cwnd < c.ssthresh)
    classic_.sample(c, std::max(us, 1u), delay_min_us_);
}

}  // namespace utcp
