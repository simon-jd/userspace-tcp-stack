// BBRv1 (M2-DESIGN §3): stub from m2-found. emplace_bbr aborts, so no Bbr is
// ever selected and the hooks below never run; m2c-bbr replaces this file.
#include "core/tcp/cc_bbr.hpp"

#include "core/tcp/cc_newreno.hpp"
#include "utcp/check.hpp"

namespace utcp {
namespace {
constexpr bool bbr_implemented = false;  // m2c-bbr
}  // namespace

std::string_view Bbr::name() const { return "bbr"; }

std::uint32_t Bbr::ssthresh(const CcConn& c) {
  UTCP_CHECK(bbr_implemented);
  return c.ssthresh;
}

void Bbr::cong_avoid(CcConn&, const AckOutcome&) { UTCP_CHECK(bbr_implemented); }

void emplace_bbr(CcStorage& s) {
  UTCP_CHECK(bbr_implemented);
  s.emplace<Bbr>();
}

}  // namespace utcp
