#include "core/tcp/cc.hpp"

#include <algorithm>

#include "utcp/check.hpp"

namespace utcp {

std::uint32_t current_ssthresh(const CcConn& c) {
  if (c.ca_state == CaState::cwr || c.ca_state == CaState::recovery) {
    return c.ssthresh;
  }
  return std::max(c.ssthresh, (c.cwnd >> 1) + (c.cwnd >> 2));
}

bool cwnd_restart(CcConn& c, CongestionControl& algo, IdleRestart mode, Duration idle,
                  Duration rto, std::uint32_t iw) {
  UTCP_CHECK(rto > Duration::zero());
  // Linux tcp_slow_start_after_idle_check: BBR keeps its own model.
  if (idle <= rto || algo.has_cong_control()) {
    return false;
  }
  algo.cwnd_event(c, CaEvent::cwnd_restart);
  const std::uint32_t restart = std::min(iw, c.cwnd);  // RFC 5681 §4.1 RW
  switch (mode) {
    case IdleRestart::rfc5681:
      c.cwnd = restart;
      break;
    case IdleRestart::linux: {
      // tcp_cwnd_restart: one halving per RTO of idle time past the first.
      c.ssthresh = current_ssthresh(c);
      std::uint32_t cwnd = c.cwnd;
      Duration left = idle;
      while ((left -= rto) > Duration::zero() && cwnd > restart) {
        cwnd >>= 1;
      }
      c.cwnd = std::max(cwnd, restart);
      break;
    }
  }
  return true;
}

}  // namespace utcp
