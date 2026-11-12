#include "core/tcp/cc.hpp"

#include <algorithm>

namespace utcp {

std::uint32_t current_ssthresh(const CcConn& c) {
  if (c.ca_state == CaState::cwr || c.ca_state == CaState::recovery) {
    return c.ssthresh;
  }
  return std::max(c.ssthresh, (c.cwnd >> 1) + (c.cwnd >> 2));
}

}  // namespace utcp
