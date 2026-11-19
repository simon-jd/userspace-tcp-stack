#include "core/tcp/cc_newreno.hpp"

#include <algorithm>

#include "utcp/check.hpp"

namespace utcp {

std::uint32_t slow_start(CcConn& c, std::uint32_t acked, std::uint32_t limit) {
  const auto growth = std::min({acked, limit, c.ssthresh - c.cwnd});
  const auto next = c.cwnd + growth;
  c.cwnd = std::min(next, effective_cwnd_clamp(c));
  return next == c.ssthresh ? acked - growth : 0;
}

// Linux tcp_cong_avoid_ai: apply credit earned at a higher window gently,
// then retain the remainder of this ACK for the next window.
void cong_avoid_ai(CcConn& c, std::uint32_t window, std::uint32_t acked) {
  std::uint64_t next = c.cwnd;
  if (c.cwnd_cnt >= window) {
    c.cwnd_cnt = 0;
    ++next;
  }
  const auto credit = std::uint64_t{c.cwnd_cnt} + acked;
  next += credit / window;
  c.cwnd_cnt = static_cast<std::uint32_t>(credit % window);
  c.cwnd = static_cast<std::uint32_t>(std::min<std::uint64_t>(next, effective_cwnd_clamp(c)));
}

std::string_view NewReno::name() const { return "newreno"; }

std::uint32_t NewReno::ssthresh(const CcConn& c) {
  // RFC 5681 §3.1 eq. 4: ssthresh = max(FlightSize / 2, 2 * SMSS).
  const auto window = c.flavor == CcFlavor::rfc ? c.packets_out : c.cwnd;
  return std::max(window / 2, 2u);
}

void NewReno::cong_avoid(CcConn& c, const AckOutcome& out) {
  // Linux tcp_reno_cong_avoid: no growth unless cwnd limits sending, or in
  // slow start below twice the packets out (tcp_is_cwnd_limited, RFC 7661).
  if (!is_cwnd_limited(c)) {
    return;
  }
  std::uint32_t acked = out.delivered;
  if (c.cwnd < c.ssthresh) {  // tcp_in_slow_start
    // RFC 5681 §3.1 limits slow-start growth to one SMSS per ACK.
    acked = slow_start(c, acked, c.flavor == CcFlavor::rfc ? 1u : acked);
    if (acked == 0) {
      return;
    }
  }
  cong_avoid_ai(c, std::max(c.cwnd, 1u), acked);
}

CongestionControl& cc_of(CcStorage& s) {
  return std::visit([](auto& algo) -> CongestionControl& { return algo; }, s);
}

void cc_select(CcStorage& s, CcAlgo algo) {
  switch (algo) {
    case CcAlgo::newreno: s.emplace<NewReno>(); return;
    case CcAlgo::cubic: emplace_cubic(s); return;
    case CcAlgo::bbr: emplace_bbr(s); return;
  }
  UTCP_CHECK(false);  // not a CcAlgo value
}

}  // namespace utcp
