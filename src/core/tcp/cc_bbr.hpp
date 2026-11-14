// BBRv1 as the server kernel's tcp_bbr.c (M2-DESIGN §3). Declared by
// m2-found as a stub; m2c-bbr owns this file and cc_bbr.cpp and adds the
// state and the hooks (cong_control, min_tso_segs, sndbuf_expand, ...).
// Includes only cc.hpp, so cc_newreno.hpp can hold the CcStorage variant.
#pragma once

#include <cstdint>
#include <string_view>

#include "core/tcp/cc.hpp"

namespace utcp {

class Bbr final : public CongestionControl {
public:
  [[nodiscard]] std::string_view name() const override;
  std::uint32_t ssthresh(const CcConn& c) override;
  void cong_avoid(CcConn& c, const AckOutcome& out) override;
};

// Puts a Bbr in `s` (cc_select). Aborts until m2c-bbr implements BBR.
void emplace_bbr(CcStorage& s);

}  // namespace utcp
