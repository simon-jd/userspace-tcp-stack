// NewReno congestion control (RFC 5681, RFC 6582; DESIGN §5.3) and the
// storage that holds a connection's algorithm. Interface declared by
// m1-found; implemented by m1-tx (cc_newreno.cpp).
#pragma once

#include <cstdint>
#include <string_view>
#include <variant>

#include "core/tcp/cc.hpp"
#include "utcp/config.hpp"

namespace utcp {

// RFC 5681 slow start (cwnd += delivered, capped at ssthresh, Linux
// tcp_slow_start), congestion avoidance with cwnd_cnt (tcp_cong_avoid_ai),
// growth only while cwnd-limited, ssthresh = max(FlightSize / 2, 2) (RFC 5681
// eq. 4; Linux reno uses cwnd / 2).
class NewReno final : public CongestionControl {
public:
  [[nodiscard]] std::string_view name() const override;
  std::uint32_t ssthresh(const CcConn& c) override;
  void cong_avoid(CcConn& c, const AckOutcome& out) override;
};

// The algorithm of one connection, in the TCB (no heap). M2b adds Cubic and
// M2c Bbr to the list.
using CcStorage = std::variant<NewReno>;

// The algorithm in `s` as its interface (std::visit).
[[nodiscard]] CongestionControl& cc_of(CcStorage& s);
// Replaces the algorithm in `s` by `algo` (M1: only CcAlgo::newreno;
// others abort). The caller then calls init().
void cc_select(CcStorage& s, CcAlgo algo);

}  // namespace utcp
