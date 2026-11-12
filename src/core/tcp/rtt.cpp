#include "core/tcp/rtt.hpp"

#include <algorithm>

#include "utcp/check.hpp"

namespace utcp {
namespace {

using namespace std::chrono_literals;

// RFC 6298 §2: clock granularity G (1 ms, the TCP timestamp tick).
constexpr Duration rfc6298_granularity = 1ms;
// Linux tcp_min_rtt_wlen = 300 s.
constexpr Duration min_rtt_window = 300s;

}  // namespace

RttEstimator::RttEstimator(const TcpConfig& cfg)
    : kind_(cfg.rtt_estimator),
      rto_min_(cfg.rto_min),
      rto_max_(cfg.rto_max),
      rto_after_syn_(cfg.rto_after_syn_rexmit),
      rto_(std::min(cfg.rto_initial, cfg.rto_max)) {
  UTCP_CHECK(rto_min_ > Duration{0} && rto_max_ >= rto_min_);
}

bool RttEstimator::has_sample() const { return has_sample_; }

void RttEstimator::on_srtt_sample(Duration seq_rtt, std::uint64_t snd_una, std::uint64_t snd_nxt) {
  if (seq_rtt < Duration{0}) {
    return;  // no sample
  }
  if (kind_ == RttEstimatorKind::rfc6298) {
    if (!has_sample_) {
      // RFC 6298 §2.2.
      srtt_ = seq_rtt;
      rttvar_ = seq_rtt / 2;
    } else {
      // RFC 6298 §2.3, beta = 1/4, alpha = 1/8; RTTVAR uses the old SRTT.
      const Duration err = srtt_ > seq_rtt ? srtt_ - seq_rtt : seq_rtt - srtt_;
      rttvar_ = (3 * rttvar_ + err) / 4;
      srtt_ = (7 * srtt_ + seq_rtt) / 8;
    }
    has_sample_ = true;
    update_rto();
    return;
  }
  // As Linux tcp_rtt_estimator(), in nanoseconds instead of microseconds.
  std::int64_t m = seq_rtt.count();
  std::int64_t srtt = srtt_.count();  // 8 * srtt
  if (has_sample_) {
    m -= srtt / 8;  // m is now the error in the estimate
    srtt += m;      // srtt = 7/8 srtt + 1/8 new
    if (m < 0) {
      m = -m;  // |error|
      m -= mdev_.count() / 4;
      // A sample below SRTT updates mdev with gain 1/32 instead of 1/4.
      if (m > 0) {
        m /= 8;
      }
    } else {
      m -= mdev_.count() / 4;
    }
    mdev_ += Duration{m};  // mdev = 3/4 mdev + 1/4 |error|
    if (mdev_ > mdev_max_) {
      mdev_max_ = mdev_;
      if (mdev_max_ > rttvar_) {
        rttvar_ = mdev_max_;  // a new round maximum raises rttvar at once
      }
    }
    if (snd_una > rtt_seq_) {
      // End of a round (SND.UNA passed rtt_seq): rttvar decays by a quarter
      // of its excess over the round's maximum deviation.
      if (mdev_max_ < rttvar_) {
        rttvar_ -= (rttvar_ - mdev_max_) / 4;
      }
      rtt_seq_ = snd_nxt;
      mdev_max_ = rto_min_;
    }
  } else {
    // First sample: srtt = m, mdev = 2m (RTO = 3m), rttvar = max(2m, rto_min).
    srtt = 8 * m;
    mdev_ = Duration{2 * m};
    rttvar_ = std::max(mdev_, rto_min_);
    mdev_max_ = rttvar_;
    rtt_seq_ = snd_nxt;
  }
  srtt_ = Duration{std::max<std::int64_t>(1, srtt)};
  has_sample_ = true;
  update_rto();
}

void RttEstimator::update_rto() {
  Duration rto{};
  if (kind_ == RttEstimatorKind::rfc6298) {
    // RFC 6298 §2.3-2.4: RTO = max(SRTT + max(G, K * RTTVAR), rto_min).
    rto = std::max(srtt_ + std::max(rfc6298_granularity, 4 * rttvar_), rto_min_);
  } else {
    // __tcp_set_rto: srtt + rttvar; rttvar >= rto_min keeps it above rto_min.
    rto = std::max(srtt_ / 8 + rttvar_, rto_min_);
  }
  rto_ = std::min(rto, rto_max_);  // tcp_bound_rto, RFC 6298 §2.5
}

void RttEstimator::on_min_rtt_sample(Duration ca_rtt, bool maybe_delayed, Time now) {
  if (ca_rtt < Duration{0}) {
    return;
  }
  // tcp_update_rtt_min: skip a suspected delayed ACK above the current min,
  // or the filter would pick it up when the real minimum expires.
  if (maybe_delayed && has_min_ && ca_rtt > min_[0].v) {
    return;
  }
  // minmax_running_min (lib/win_minmax.c), window 300 s.
  const MinSample val{now, ca_rtt};
  if (!has_min_ || val.v <= min_[0].v || val.t - min_[2].t > min_rtt_window) {
    min_ = {val, val, val};  // new minimum, or nothing left in the window
    has_min_ = true;
    return;
  }
  if (val.v <= min_[1].v) {
    min_[2] = min_[1] = val;
  } else if (val.v <= min_[2].v) {
    min_[2] = val;
  }
  // minmax_subwin_update.
  const Duration dt = val.t - min_[0].t;
  if (dt > min_rtt_window) {
    // The best choice left the window: promote the second and third.
    min_[0] = min_[1];
    min_[1] = min_[2];
    min_[2] = val;
    if (val.t - min_[0].t > min_rtt_window) {
      min_[0] = min_[1];
      min_[1] = min_[2];
      min_[2] = val;
    }
  } else if (min_[1].t == min_[0].t && dt > min_rtt_window / 4) {
    // A quarter of the window without a new second choice.
    min_[2] = min_[1] = val;
  } else if (min_[2].t == min_[1].t && dt > min_rtt_window / 2) {
    // Half the window without a new third choice.
    min_[2] = val;
  }
}

Duration RttEstimator::srtt() const {
  return kind_ == RttEstimatorKind::rfc6298 ? srtt_ : srtt_ / 8;
}

Duration RttEstimator::rttvar() const {
  return kind_ == RttEstimatorKind::rfc6298 ? rttvar_ : mdev_ / 4;
}

Duration RttEstimator::min_rtt() const { return has_min_ ? min_[0].v : Duration::max(); }

Duration RttEstimator::rto() const { return rto_; }

Duration RttEstimator::rto_backed_off(std::uint8_t backoff) const {
  // RFC 6298 §5.5 doubling, capped at rto_max (no overflow: compare first).
  if (backoff >= 62 || rto_.count() > (rto_max_.count() >> backoff)) {
    return rto_max_;
  }
  return std::min(Duration{rto_.count() << backoff}, rto_max_);
}

void RttEstimator::reset_after_syn_rexmit() {
  if (!has_sample_) {
    rto_ = std::min(rto_after_syn_, rto_max_);
  }
}

}  // namespace utcp
