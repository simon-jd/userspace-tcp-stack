#include "core/tcp/cc_newreno.hpp"

#include <algorithm>

#include "utcp/check.hpp"

namespace utcp {
namespace {

// Linux tcp_slow_start: cwnd += acked up to ssthresh; returns what is left.
std::uint32_t slow_start(CcConn& c, std::uint32_t acked) {
  const std::uint32_t cwnd = std::min(c.cwnd + acked, c.ssthresh);
  acked -= cwnd - c.cwnd;
  c.cwnd = std::min(cwnd, effective_cwnd_clamp(c));
  return acked;
}

// Linux tcp_cong_avoid_ai: cwnd += 1 per w packets delivered (RFC 5681 §3.1
// eq. 3 in packet counting).
void cong_avoid_ai(CcConn& c, std::uint32_t w, std::uint32_t acked) {
  // Credits accumulated at a higher w are applied gently now.
  if (c.cwnd_cnt >= w) {
    c.cwnd_cnt = 0;
    ++c.cwnd;
  }
  c.cwnd_cnt += acked;
  if (c.cwnd_cnt >= w) {
    const std::uint32_t delta = c.cwnd_cnt / w;
    c.cwnd_cnt -= delta * w;
    c.cwnd += delta;
  }
  c.cwnd = std::min(c.cwnd, effective_cwnd_clamp(c));
}

}  // namespace

std::string_view NewReno::name() const { return "newreno"; }

std::uint32_t NewReno::ssthresh(const CcConn& c) {
  // RFC 5681 §3.1 eq. 4: ssthresh = max(FlightSize / 2, 2 * SMSS).
  return std::max(c.packets_out / 2, 2u);
}

void NewReno::cong_avoid(CcConn& c, const AckOutcome& out) {
  // Linux tcp_reno_cong_avoid: no growth unless cwnd limits sending, or in
  // slow start below twice the packets out (tcp_is_cwnd_limited, RFC 7661).
  if (!is_cwnd_limited(c)) {
    return;
  }
  std::uint32_t acked = out.delivered;
  if (c.cwnd < c.ssthresh) {  // tcp_in_slow_start
    acked = slow_start(c, acked);
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
