// CUBIC (M2-DESIGN §2.3): stub from m2-found. emplace_cubic aborts, so no
// Cubic is ever selected and the hooks below never run; m2b-cc replaces
// this file.
#include "core/tcp/cc_cubic.hpp"

#include "core/tcp/cc_newreno.hpp"
#include "utcp/check.hpp"

namespace utcp {
namespace {
constexpr bool cubic_implemented = false;  // m2b-cc
}  // namespace

std::string_view Cubic::name() const { return "cubic"; }

std::uint32_t Cubic::ssthresh(const CcConn& c) {
  UTCP_CHECK(cubic_implemented);
  return c.ssthresh;
}

void Cubic::cong_avoid(CcConn&, const AckOutcome&) { UTCP_CHECK(cubic_implemented); }

void emplace_cubic(CcStorage& s) {
  UTCP_CHECK(cubic_implemented);
  s.emplace<Cubic>();
}

}  // namespace utcp
