// TIME-WAIT entries (DESIGN §4.3, §4.4, §4.12). Interface declared by
// m1-found; implemented by m1-ip (time_wait.cpp); used by the TCP engine.
//
// The TCB is freed on entry to TIME-WAIT and replaced by a compact entry with
// what TIME-WAIT processing needs: ACKs to retransmitted FINs and SYNs carry
// a scaled window and a TSval; a new SYN may reuse the tuple with ISS = old
// SND.NXT + 65537 (RFC 6191, §4.4). Lookup by the same keyed hash as
// ConnTable, never iterated. Entries expire through the timer heap
// (TimerKind::time_wait, owner = entry index); the expiry time is that
// timer's deadline.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "core/timer/timer_heap.hpp"
#include "utcp/random.hpp"
#include "utcp/seq.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

struct TimeWaitEntry {  // 64 bytes; §12 item 4 targets <= 64
  FourTuple tuple;
  Time ts_recent_stamp;       // when ts_recent was set (RFC 7323 §5.5, 24-day rule)
  Time last_oow_ack;          // oow_ack_interval limiter for TIME-WAIT ACKs (§4.7)
  bool has_oow_ack = false;   // last_oow_ack is set
  Seq32 snd_nxt, rcv_nxt;
  std::uint32_t rcv_wnd = 0;  // bytes, as last advertised
  std::uint32_t ts_recent = 0;
  std::uint32_t ts_offset = 0;
  TimerId timer = 0;          // the time_wait timer
  std::uint8_t rcv_wscale = 0;
  bool ts_ok = false;

  bool operator==(const TimeWaitEntry&) const = default;
};
static_assert(sizeof(TimeWaitEntry) <= 64);

class TimeWaitTable {
public:
  explicit TimeWaitTable(const SipKey& hash_key);

  // Adds an entry and returns its index, stable until erase. Indices are
  // reused lowest-first. Precondition (checked): the tuple is not present.
  std::uint32_t insert(const TimeWaitEntry& e);
  [[nodiscard]] std::optional<std::uint32_t> find(const FourTuple& tuple) const;
  [[nodiscard]] TimeWaitEntry& entry(std::uint32_t index);
  [[nodiscard]] const TimeWaitEntry& entry(std::uint32_t index) const;
  void erase(std::uint32_t index);
  [[nodiscard]] std::size_t size() const;

  void check_invariants() const;

private:
  // Implementation state is m1-ip's.
};

}  // namespace utcp
