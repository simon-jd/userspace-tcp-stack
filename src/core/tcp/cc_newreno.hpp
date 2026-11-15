// NewReno congestion control (RFC 5681, RFC 6582; DESIGN §5.3) and the
// storage that holds a connection's algorithm. Interface declared by
// m1-found; implemented by m1-tx, then m2b-cc (the NewReno methods in
// cc_newreno.cpp). cc_select and cc_of are m2-found's: cc_select reaches
// CUBIC and BBR through emplace_cubic and emplace_bbr (cc_cubic.cpp,
// cc_bbr.cpp), so m2b-cc and m2c-bbr do not edit them.
#pragma once

#include <cstdint>
#include <string_view>
#include <variant>

#include "core/tcp/cc.hpp"
#include "core/tcp/cc_bbr.hpp"
#include "core/tcp/cc_cubic.hpp"
#include "utcp/config.hpp"

namespace utcp {

// RFC 5681 slow start (cwnd += delivered, capped at ssthresh, Linux
// tcp_slow_start), congestion avoidance with cwnd_cnt (tcp_cong_avoid_ai),
// growth only while is_cwnd_limited(), ssthresh = max(FlightSize / 2, 2) (RFC 5681
// eq. 4, FlightSize = CcConn::packets_out; Linux reno uses cwnd / 2).
class NewReno final : public CongestionControl {
public:
  [[nodiscard]] std::string_view name() const override;
  std::uint32_t ssthresh(const CcConn& c) override;
  void cong_avoid(CcConn& c, const AckOutcome& out) override;
};

// CcStorage (cc.hpp) is std::variant<NewReno, Cubic, Bbr>; this header
// includes all three, so it is complete here.

// The algorithm in `s` as its interface (std::visit).
[[nodiscard]] CongestionControl& cc_of(CcStorage& s);
// Replaces the algorithm in `s` by `algo` (newreno here, cubic through
// emplace_cubic, bbr through emplace_bbr; those abort until m2b-cc and
// m2c-bbr implement them). The caller then calls init().
void cc_select(CcStorage& s, CcAlgo algo);

}  // namespace utcp
