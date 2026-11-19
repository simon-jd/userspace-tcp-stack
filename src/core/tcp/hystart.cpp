#include "core/tcp/hystart.hpp"

#include <algorithm>
#include <chrono>
#include <limits>

#include "utcp/stats.hpp"

namespace utcp {
using namespace std::chrono_literals;

void ClassicHyStart::reset_round(const CcConn& c) {
  end_ = c.snd_nxt;
  start_ = last_ack_ = c.now;
  round_min_ = std::numeric_limits<std::uint32_t>::max();
  samples_ = 0;
}

void ClassicHyStart::sample(CcConn& c, std::uint32_t delay_us, std::uint32_t min_us) {
  if (found_) return;
  if (c.snd_una > end_) reset_round(c);
  if (c.cwnd < c.hystart_low_window) return;
  // Linux v7.0 hystart_update: a gap breaks the train for the rest of this round.
  const auto now_us = c.now.ns / 1000;
  if (now_us - last_ack_.ns / 1000 <= c.hystart_ack_delta.count() / 1000) {
    last_ack_ = c.now;
    const auto cushion = c.pacing_rate == 0 ? 0 :
        std::min<std::uint64_t>(1000, std::uint64_t{c.gso_max_size} * 4'000'000 / c.pacing_rate);
    const auto threshold = (std::uint64_t{min_us} + cushion) / (c.paced ? 1u : 2u);
    if (now_us - start_.ns / 1000 > static_cast<std::int64_t>(threshold)) {
      found_ = true;
      c.ssthresh = c.cwnd;
      if (c.stats) {
        ++c.stats->TcpExtTCPHystartTrainDetect;
        c.stats->TcpExtTCPHystartTrainCwnd += c.cwnd;
      }
    }
  }
  round_min_ = std::min(round_min_, delay_us);
  if (samples_ < 8) {
    ++samples_;
  } else if (round_min_ > std::uint64_t{min_us} + std::clamp(min_us / 8, 4000u, 16000u)) {
    found_ = true;
    c.ssthresh = c.cwnd;
    if (c.stats) {
      ++c.stats->TcpExtTCPHystartDelayDetect;
      c.stats->TcpExtTCPHystartDelayCwnd += c.cwnd;
    }
  }
}

void HyStartPlusPlus::sample(CcConn& c, Duration rtt) {
  // RFC 9406 §4.2: the ACK covering windowEnd starts a new sample round.
  if (waiting_for_flight_) {
    if (c.snd_nxt <= end_) return;
    end_ = c.snd_nxt;
    waiting_for_flight_ = false;
  }
  if (c.snd_una >= end_) {
    // A draining ACK completes the round immediately. Its duplicates cannot
    // complete another until there is a new flight with its own windowEnd.
    waiting_for_flight_ = c.snd_nxt == c.snd_una;
    end_ = c.snd_nxt;
    previous_ = current_;
    current_ = Duration::max();
    samples_ = 0;
    if (baseline_ != Duration::max() && ++rounds_ == 5) {
      c.ssthresh = c.cwnd;
      end();
      return;
    }
  }
  // The RFC applies this ACK's increase before evaluating its sample.
  css_ack_ = baseline_ != Duration::max();
  if (rtt.count() < 0) return;
  current_ = std::min(current_, rtt);
  if (samples_ < 8) ++samples_;
  if (samples_ < 8) return;
  if (css_ack_) {
    if (current_ < baseline_) {
      baseline_ = Duration::max();
      rounds_ = 0;
    }
  } else if (previous_ != Duration::max()) {
    const auto threshold = std::clamp(previous_ / 8, Duration{4ms}, Duration{16ms});
    if (current_ - previous_ >= threshold) {
      baseline_ = current_;
      rounds_ = carry_ = 0;
    }
  }
}

std::uint32_t HyStartPlusPlus::growth(const CcConn& c, std::uint32_t delivered) {
  const auto n = c.paced ? delivered : std::min(delivered, 8u);
  if (!css_ack_) return n;
  const auto credit = std::uint64_t{n} + carry_;
  carry_ = static_cast<std::uint32_t>(credit % 4);
  return static_cast<std::uint32_t>(credit / 4);
}

}  // namespace utcp
