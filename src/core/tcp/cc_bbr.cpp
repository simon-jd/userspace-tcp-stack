#include "core/tcp/cc_bbr.hpp"

#include <algorithm>
#include <array>
#include <limits>

#include "core/tcp/cc_newreno.hpp"
#include "utcp/check.hpp"

namespace utcp {
namespace {
using U32 = std::uint32_t;
using U64 = std::uint64_t;
using Wide = __uint128_t;
constexpr U32 bw_unit = 1u << 24;  // packets/us
constexpr U32 unit = 256;          // gain
constexpr U32 high_gain = 739;
constexpr U32 drain_gain = 88;
constexpr U32 min_window = 4;
constexpr U32 initial_window = 10;
constexpr std::array<U32, 8> cycle_gains{320, 192, unit, unit, unit, unit, unit, unit};
constexpr U32 max32 = std::numeric_limits<U32>::max();

U32 packets(Wide n) { return static_cast<U32>(std::min<Wide>(n, max32)); }
U64 microseconds(Duration d) {
  return static_cast<U64>(std::max<std::int64_t>(0, d.count()) / 1000);
}

// Delivered timestamps are already in whole us in the Linux model.
U64 elapsed_us(Time end, Time start) {
  return static_cast<U64>(std::max<std::int64_t>(0, end.ns / 1000 - start.ns / 1000));
}
bool after_tick(U32 now, U32 deadline) { return static_cast<std::int32_t>(now - deadline) > 0; }
U32 bw_sample(U64 count, U64 us) { return packets(Wide{count} * bw_unit / us); }

// Keep Linux's intermediate Q8 truncation before the one-percent pacing margin.
U64 bytes_per_second(U32 bw, U32 mss, U32 gain) {
  const Wide rate = ((Wide{bw} * mss * gain) / unit) * 990'000 / bw_unit;
  return static_cast<U64>(std::min<Wide>(rate, std::numeric_limits<U64>::max()));
}
U64 pacing_rate(const CcConn& c, U32 bw, U32 gain) {
  const auto rate = bytes_per_second(bw, c.mss, gain);
  return c.max_pacing_rate ? std::min(c.max_pacing_rate, rate) : rate;
}
}  // namespace

U32 Bbr::bandwidth() const { return lt_active_ ? lt_bw_ : max_bw_.get(); }

Bbr::Info Bbr::info() const {
  return {mode_, lt_active_, bandwidth(), min_rtt_us_, pacing_gain_, cwnd_gain_};
}

void Bbr::init(CcConn& c) {
  *this = Bbr{};
  c.ssthresh = cwnd_infinite;
  c.pacing_needed = true;
  next_round_ = c.delivered;
  min_stamp_ = jiffies(c.now);
  min_rtt_us_ = c.min_rtt == Duration::max() ? max32 : packets(microseconds(c.min_rtt));
  epoch_ = c.now;
  start_lt_interval(c);
  init_rate(c);
}

void Bbr::init_rate(CcConn& c) {
  seen_srtt_ = c.srtt.count() > 0;
  const auto us = seen_srtt_ ? std::max<U64>(1, microseconds(c.srtt)) : 1000;
  c.pacing_rate = pacing_rate(c, bw_sample(c.cwnd, us), high_gain);
}

void Bbr::pace(CcConn& c, U32 gain) {
  const auto rate = pacing_rate(c, bandwidth(), gain);
  if (!seen_srtt_ && c.srtt.count() > 0) {
    init_rate(c);
  }
  if (full_pipe_ || rate > c.pacing_rate) {
    c.pacing_rate = rate;
  }
}

U32 Bbr::min_tso_segs(const CcConn& c) const { return c.pacing_rate < 150'000 ? 1 : 2; }

U32 Bbr::tso_goal(const CcConn& c) const {
  UTCP_CHECK(c.mss > 0);
  const auto bytes = static_cast<U32>(std::min<U64>(c.pacing_rate >> 10, 65536 - 1 - 320));
  return std::clamp(bytes / c.mss, min_tso_segs(c), 127u);
}

U32 Bbr::flight_target(const CcConn& c, U32 bw, U32 gain, U32 bonus) const {
  const auto scaled = Wide{bw} * min_rtt_us_ * gain / unit;
  const auto bdp =
      min_rtt_us_ == max32 ? initial_window : packets((scaled + bw_unit - 1) / bw_unit);
  // Three TSO bursts, then round up to even to tolerate delayed ACKs. The
  // high PROBE_BW phase adds two more packets even on a short path.
  const U64 with_bursts = U64{bdp} + bonus + 3 * tso_goal(c);
  const U32 probe = mode_ == Mode::probe_bw && phase_ == 0 ? 2 : 0;
  return packets(((with_bursts + 1) & ~U64{1}) + probe);
}

U32 Bbr::flight_at_edt(const CcConn& c, U32 flight) const {
  const auto leaving = Wide{bandwidth()} * microseconds(c.wstamp - c.now) / bw_unit;
  const U64 queued = U64{flight} + (pacing_gain_ > unit ? tso_goal(c) : 0);
  return leaving >= queued ? 0 : packets(queued - leaving);
}

void Bbr::save_window(const CcConn& c) {
  saved_cwnd_ = previous_ca_ < CaState::recovery && mode_ != Mode::probe_rtt
                    ? c.cwnd
                    : std::max(saved_cwnd_, c.cwnd);
}

U32 Bbr::ssthresh(const CcConn& c) {
  save_window(c);
  return c.ssthresh;
}

U32 Bbr::undo_cwnd(const CcConn& c) {
  plateau_bw_ = 0;
  plateau_rounds_ = 0;
  reset_lt(c);
  return c.cwnd;
}

void Bbr::set_state(CcConn& c, CaState state) {
  if (state == CaState::loss) {
    previous_ca_ = state;
    plateau_bw_ = 0;  // Loss does not clear the full-pipe latch.
    round_start_ = true;
    RateSample loss;
    loss.losses = 1;
    sample_lt(c, loss);
  }
}

void Bbr::cwnd_event(CcConn& c, CaEvent event) {
  if (event != CaEvent::tx_start || c.app_limited == 0) {
    return;
  }
  idle_ = true;
  epoch_ = c.now;
  epoch_acked_ = 0;
  if (mode_ == Mode::probe_bw) {
    pace(c, unit);
  }
  if (mode_ == Mode::probe_rtt) {
    finish_probe_rtt(c);
  }
}

void Bbr::start_lt_interval(const CcConn& c) {
  lt_start_ = c.delivered_time;
  lt_delivered_ = c.delivered;
  lt_lost_ = c.lost;
  lt_rounds_ = 0;
}

void Bbr::reset_lt(const CcConn& c) {
  lt_sampling_ = false;
  lt_active_ = false;
  lt_bw_ = 0;
  start_lt_interval(c);
}

void Bbr::sample_lt(const CcConn& c, const RateSample& rs) {
  if (lt_active_) {
    if (mode_ == Mode::probe_bw && round_start_ && ++lt_rounds_ >= 48) {
      reset_lt(c);
      start_probe_bw(c);
    }
    return;
  }
  if (!lt_sampling_) {
    if (!rs.losses) {
      return;
    }
    start_lt_interval(c);
    lt_sampling_ = true;
  }
  if (rs.is_app_limited) {
    reset_lt(c);
    return;
  }
  if (round_start_) {
    ++lt_rounds_;
  }
  if (lt_rounds_ > 16) {
    reset_lt(c);
    return;
  }
  if (lt_rounds_ < 4 || !rs.losses) {
    return;
  }

  const U64 delivered = c.delivered - lt_delivered_;
  const U64 lost = c.lost - lt_lost_;
  if (!delivered || Wide{lost} * unit < Wide{delivered} * 50) {
    return;
  }
  const auto ms = c.delivered_time.ns / 1'000'000 - lt_start_.ns / 1'000'000;
  if (ms < 1) {
    return;
  }
  if (ms >= max32 / 1000) {
    reset_lt(c);
    return;
  }
  const auto estimate = bw_sample(delivered, static_cast<U64>(ms) * 1000);
  const auto diff = std::max(estimate, lt_bw_) - std::min(estimate, lt_bw_);
  if (lt_bw_ && (U64{diff} * 8 <= lt_bw_ || bytes_per_second(diff, c.mss, unit) <= 500)) {
    lt_bw_ = static_cast<U32>((U64{lt_bw_} + estimate) / 2);
    lt_active_ = true;
    pacing_gain_ = unit;
    lt_rounds_ = 0;
    return;
  }
  lt_bw_ = estimate;
  start_lt_interval(c);
}

void Bbr::sample_bw(const CcConn& c, const RateSample& rs) {
  if (rs.prior_delivered >= next_round_) {
    next_round_ = c.delivered;
    ++rounds_;
    round_start_ = true;
    conserve_ = false;
  }
  sample_lt(c, rs);
  const auto rate = bw_sample(rs.delivered, microseconds(rs.interval));
  if (!rs.is_app_limited || rate >= max_bw_.get()) {
    max_bw_.update(10, rounds_, rate);
  }
}

void Bbr::sample_aggregation(const CcConn& c, const RateSample& rs) {
  if (!rs.acked_sacked) {
    return;
  }
  if (round_start_ && ++bucket_rounds_ == 5) {
    bucket_rounds_ = 0;
    bucket_ ^= 1;
    extra_[bucket_] = 0;
  }
  auto expected = Wide{bandwidth()} * elapsed_us(c.delivered_time, epoch_) / bw_unit;
  constexpr U32 epoch_limit = 1u << 20;
  if (epoch_acked_ <= expected || U64{epoch_acked_} + rs.acked_sacked >= epoch_limit) {
    expected = 0;
    epoch_acked_ = 0;
    epoch_ = c.delivered_time;
  }
  epoch_acked_ =
      static_cast<U32>(std::min<U64>(epoch_limit - 1, U64{epoch_acked_} + rs.acked_sacked));
  const auto extra = std::min(c.cwnd, epoch_acked_ - static_cast<U32>(expected));
  if (extra > extra_[bucket_]) {
    extra_[bucket_] = static_cast<std::uint16_t>(extra);
  }
}

void Bbr::check_plateau(const RateSample& rs) {
  if (full_pipe_ || !round_start_ || rs.is_app_limited) {
    return;
  }
  if (max_bw_.get() >= U64{plateau_bw_} * 320 / unit) {
    plateau_bw_ = max_bw_.get();
    plateau_rounds_ = 0;
  } else {
    full_pipe_ = ++plateau_rounds_ >= 3;
  }
}

void Bbr::start_probe_bw(const CcConn& c) {
  UTCP_CHECK(c.rng != nullptr);
  mode_ = Mode::probe_bw;
  phase_ = (8 - c.rng->below(7)) % 8;
  phase_start_ = c.delivered_time;
}

void Bbr::cycle(const CcConn& c, const RateSample& rs) {
  if (mode_ != Mode::probe_bw) {
    return;
  }
  const bool elapsed = elapsed_us(c.delivered_time, phase_start_) > min_rtt_us_;
  bool advance = elapsed;
  if (pacing_gain_ > unit) {
    advance = elapsed && (rs.losses || flight_at_edt(c, rs.prior_in_flight) >=
                                           flight_target(c, max_bw_.get(), pacing_gain_));
  } else if (pacing_gain_ < unit) {
    advance =
        elapsed || flight_at_edt(c, rs.prior_in_flight) <= flight_target(c, max_bw_.get(), unit);
  }
  if (advance) {
    phase_ = (phase_ + 1) % 8;
    phase_start_ = c.delivered_time;
  }
}

void Bbr::check_drain(CcConn& c) {
  if (mode_ == Mode::startup && full_pipe_) {
    mode_ = Mode::drain;
    c.ssthresh = flight_target(c, max_bw_.get(), unit);
  }
  if (mode_ == Mode::drain &&
      flight_at_edt(c, c.in_flight) <= flight_target(c, max_bw_.get(), unit)) {
    start_probe_bw(c);
  }
}

void Bbr::finish_probe_rtt(CcConn& c) {
  const auto now = jiffies(c.now);
  if (!probe_deadline_ || !after_tick(now, *probe_deadline_)) {
    return;
  }
  min_stamp_ = now;
  c.cwnd = std::max(c.cwnd, saved_cwnd_);
  if (full_pipe_) {
    start_probe_bw(c);
  } else {
    mode_ = Mode::startup;
  }
}

void Bbr::probe_rtt(CcConn& c, const RateSample& rs) {
  const auto now = jiffies(c.now);
  const bool expired = after_tick(now, min_stamp_ + 10'000);
  if (rs.rtt.count() >= 0) {
    const auto sample = packets(microseconds(rs.rtt));
    if (sample < min_rtt_us_ || (expired && !rs.is_ack_delayed)) {
      min_rtt_us_ = sample;
      min_stamp_ = now;
    }
  }
  if (expired && !idle_ && mode_ != Mode::probe_rtt) {
    mode_ = Mode::probe_rtt;
    save_window(c);
    probe_deadline_.reset();
  }
  if (mode_ == Mode::probe_rtt) {
    c.app_limited = std::max<U64>(1, c.delivered + c.in_flight);
    if (!probe_deadline_ && c.in_flight <= min_window) {
      probe_deadline_ = now + 200;
      probe_round_ = false;
      next_round_ = c.delivered;
    } else if (probe_deadline_) {
      probe_round_ |= round_start_;
      if (probe_round_) {
        finish_probe_rtt(c);
      }
    }
  }
  if (rs.delivered > 0) {
    idle_ = false;
  }
}

void Bbr::update_gains() {
  switch (mode_) {
    case Mode::startup:
      pacing_gain_ = cwnd_gain_ = high_gain;
      break;
    case Mode::drain:
      pacing_gain_ = drain_gain;
      cwnd_gain_ = high_gain;
      break;
    case Mode::probe_bw:
      pacing_gain_ = lt_active_ ? unit : cycle_gains[phase_];
      cwnd_gain_ = 2 * unit;
      break;
    case Mode::probe_rtt:
      pacing_gain_ = cwnd_gain_ = unit;
      break;
  }
}

void Bbr::update_window(CcConn& c, const RateSample& rs) {
  const U32 acked = rs.acked_sacked;
  U32 window = c.cwnd;
  if (acked) {
    if (rs.losses) {
      window = window > rs.losses ? window - rs.losses : 1;
    }
    const auto flight_plus_ack = packets(U64{c.in_flight} + acked);
    if (c.ca_state == CaState::recovery && previous_ca_ != CaState::recovery) {
      conserve_ = true;
      next_round_ = c.delivered;
      window = flight_plus_ack;
    } else if (c.ca_state < CaState::recovery && previous_ca_ >= CaState::recovery) {
      window = std::max(window, saved_cwnd_);
      conserve_ = false;
    }
    previous_ca_ = c.ca_state;
    if (conserve_) {
      window = std::max(window, flight_plus_ack);
    } else {
      const auto max_extra = packets(U64{bandwidth()} * 100'000 / bw_unit);
      const auto bonus = full_pipe_ ? std::min<U32>(max_extra, std::max(extra_[0], extra_[1])) : 0;
      const auto target = flight_target(c, bandwidth(), cwnd_gain_, bonus);
      const auto growth = packets(U64{window} + acked);
      if (full_pipe_) {
        window = std::min(growth, target);
      } else if (window < target || c.delivered < initial_window) {
        window = growth;
      }
      window = std::max(window, min_window);
    }
  }
  c.cwnd = std::min(window, effective_cwnd_clamp(c));
  if (mode_ == Mode::probe_rtt) {
    c.cwnd = std::min(c.cwnd, min_window);
  }
}

void Bbr::cong_control(CcConn& c, const AckOutcome&, const RateSample& rs) {
  round_start_ = false;
  if (rs.valid && microseconds(rs.interval) > 0) {
    sample_bw(c, rs);
    sample_aggregation(c, rs);
  }
  cycle(c, rs);
  check_plateau(rs);
  check_drain(c);
  probe_rtt(c, rs);
  update_gains();
  pace(c, pacing_gain_);
  update_window(c, rs);
}

void emplace_bbr(CcStorage& s) { s.emplace<Bbr>(); }
}  // namespace utcp
