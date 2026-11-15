#include "core/tcp/prr.hpp"

#include <algorithm>

namespace utcp {

void prr_init(PrrState& p, std::uint32_t cwnd) {
  p.prior_cwnd = cwnd;
  p.delivered = 0;
  p.out = 0;
}

std::optional<std::uint32_t> prr_cwnd(PrrState& p, std::uint32_t ssthresh, std::uint32_t in_flight,
                                      std::uint32_t newly_acked_sacked, std::uint32_t newly_lost,
                                      bool una_advanced) {
  if (newly_acked_sacked == 0 || p.prior_cwnd == 0) {
    return std::nullopt;
  }
  p.delivered += newly_acked_sacked;
  // Signed as Linux's int delta and sndcnt.
  const std::int64_t delta = std::int64_t{ssthresh} - std::int64_t{in_flight};
  std::int64_t sndcnt = 0;
  if (delta < 0) {
    // RFC 9937 §6.2 proportional part (Linux divides by prior_cwnd), rounded up.
    const std::uint64_t dividend =
        std::uint64_t{ssthresh} * std::uint64_t{p.delivered} + p.prior_cwnd - 1;
    sndcnt = static_cast<std::int64_t>(dividend / p.prior_cwnd) - std::int64_t{p.out};
  } else {
    // Packet conservation; SafeACK (RFC 9937 §6.2): one more when SND.UNA
    // advanced and nothing new was lost, slow-starting towards ssthresh.
    sndcnt = std::max(std::int64_t{p.delivered} - std::int64_t{p.out},
                      std::int64_t{newly_acked_sacked});
    if (una_advanced && newly_lost == 0) {
      ++sndcnt;
    }
    sndcnt = std::min(delta, sndcnt);
  }
  // Force the fast retransmit on entering recovery; never below 0, so cwnd
  // never drops below in_flight.
  sndcnt = std::max<std::int64_t>(sndcnt, p.out == 0 ? 1 : 0);
  // Linux warns if in_flight + sndcnt is not positive (tcp_snd_cwnd_set);
  // that needs ssthresh 0. The stack keeps cwnd >= 1.
  const std::int64_t cwnd = std::max<std::int64_t>(std::int64_t{in_flight} + sndcnt, 1);
  return static_cast<std::uint32_t>(std::min<std::int64_t>(cwnd, 0xffff'ffff));
}

}  // namespace utcp
