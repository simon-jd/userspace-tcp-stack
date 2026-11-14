// A scriptable LossRecovery test seam (M2-TASKS m2-found): set the hook
// functions a test needs, attach with LossRecovery::set_script, and read the
// call log. An unset function lets the real hook run (RecoveryScript in
// core/tcp/recovery.hpp). Used by the engine tests and m2-sim's checker tests.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "core/tcp/recovery.hpp"

namespace utcp::test {

class ScriptedRecovery final : public RecoveryScript {
public:
  using Ctx = RecoveryCtx;

  std::function<std::optional<bool>(const Ctx&, const TxSeg&)> exempt;
  std::function<std::optional<bool>(const Ctx&, const AckOutcome&)> may_raise;
  std::function<bool(Ctx&, std::uint32_t, std::uint32_t, std::uint32_t)> reduce;
  std::function<std::optional<std::optional<std::uint64_t>>(Ctx&)> extra;
  std::function<std::optional<TlpAction>(Ctx&)> pto;
  std::function<bool(Ctx&, TlpAction, bool)> tlp_sent;
  std::function<bool(Ctx&, bool)> burst_end;
  std::function<std::optional<std::pair<XmitTimer, Time>>(const Ctx&)> timer;
  std::function<bool(Ctx&, XmitTimer)> timer_fired;

  // One entry per hook call, in order: the hook name and, where the hook
  // has them, its arguments ("cwnd_reduction 3 0 1", "on_tlp_sent 1 1", ...).
  std::vector<std::string> calls;

  std::optional<bool> exempt_from_cwnd(const Ctx& c, const TxSeg& seg) override {
    calls.push_back("exempt_from_cwnd " + std::to_string(seg.off));
    return exempt ? exempt(c, seg) : std::nullopt;
  }
  std::optional<bool> may_raise_cwnd(const Ctx& c, const AckOutcome& out) override {
    calls.emplace_back("may_raise_cwnd");
    return may_raise ? may_raise(c, out) : std::nullopt;
  }
  bool cwnd_reduction(Ctx& c, std::uint32_t acked_sacked, std::uint32_t lost,
                      std::uint32_t flags) override {
    calls.push_back("cwnd_reduction " + std::to_string(acked_sacked) + " " + std::to_string(lost) +
                    " " + std::to_string(flags));
    return reduce ? reduce(c, acked_sacked, lost, flags) : false;
  }
  std::optional<std::optional<std::uint64_t>> next_seg_extra(Ctx& c) override {
    calls.emplace_back("next_seg_extra");
    return extra ? extra(c) : std::nullopt;
  }
  std::optional<TlpAction> on_pto(Ctx& c) override {
    calls.emplace_back("on_pto");
    return pto ? pto(c) : std::nullopt;
  }
  bool on_tlp_sent(Ctx& c, TlpAction a, bool sent) override {
    calls.push_back("on_tlp_sent " + std::to_string(static_cast<int>(a)) + " " +
                    std::to_string(sent ? 1 : 0));
    return tlp_sent ? tlp_sent(c, a, sent) : false;
  }
  bool on_burst_end(Ctx& c, bool new_data_sent) override {
    calls.push_back(std::string("on_burst_end ") + (new_data_sent ? "1" : "0"));
    return burst_end ? burst_end(c, new_data_sent) : false;
  }
  std::optional<std::pair<XmitTimer, Time>> xmit_timer(const Ctx& c) override {
    return timer ? timer(c) : std::nullopt;  // not logged: the engine asks often
  }
  bool on_xmit_timer(Ctx& c, XmitTimer kind) override {
    calls.push_back("on_xmit_timer " + std::to_string(static_cast<int>(kind)));
    return timer_fired ? timer_fired(c, kind) : false;
  }

  // The calls whose name starts with `prefix`.
  [[nodiscard]] std::vector<std::string> calls_of(const std::string& prefix) const {
    std::vector<std::string> out;
    for (const std::string& s : calls) {
      if (s.starts_with(prefix)) {
        out.push_back(s);
      }
    }
    return out;
  }
};

}  // namespace utcp::test
