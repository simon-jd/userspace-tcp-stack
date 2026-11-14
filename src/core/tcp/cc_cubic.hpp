// CUBIC congestion control (RFC 9438 for cc_flavor rfc, a port of Linux
// tcp_cubic.c for linux; M2-DESIGN §2.3-2.4). Declared by m2-found as a stub;
// m2b-cc owns this file and cc_cubic.cpp and adds the state and the hooks.
// Includes only cc.hpp, so cc_newreno.hpp can hold the CcStorage variant.
#pragma once

#include <cstdint>
#include <string_view>

#include "core/tcp/cc.hpp"

namespace utcp {

class Cubic final : public CongestionControl {
public:
  [[nodiscard]] std::string_view name() const override;
  std::uint32_t ssthresh(const CcConn& c) override;
  void cong_avoid(CcConn& c, const AckOutcome& out) override;
};

// Puts a Cubic in `s` (cc_select). Aborts until m2b-cc implements CUBIC.
void emplace_cubic(CcStorage& s);

}  // namespace utcp
