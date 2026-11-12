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
#include <vector>

#include "core/tcp/conn_table.hpp"
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
  Seq32 snd_nxt, rcv_nxt;
  std::uint32_t rcv_wnd = 0;  // bytes, as last advertised
  std::uint32_t ts_recent = 0;
  std::uint32_t ts_offset = 0;
  std::uint32_t conn_id = 0;  // Tcb::conn_id, so TIME-WAIT trace events name the connection
  TimerId timer = no_timer;   // the time_wait timer
  std::uint8_t rcv_wscale = 0;
  bool ts_ok : 1 = false;
  bool has_oow_ack : 1 = false;  // last_oow_ack is set

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

  // With the timer: insert() plus a time_wait timer (owner = the index)
  // created in `timers` and armed at `expiry`; e.timer is ignored and set.
  std::uint32_t insert(const TimeWaitEntry& e, TimerHeap& timers, Time expiry);
  // Re-arms the entry's timer at `expiry` (a retransmitted FIN restarts
  // TIME-WAIT, §4.12). Precondition (checked): the entry has a timer.
  void restart(std::uint32_t index, TimerHeap& timers, Time expiry);
  // erase() after destroying the entry's timer, if it has one. The timer
  // handler calls this when the timer fires (TIME-WAIT is over).
  void erase(std::uint32_t index, TimerHeap& timers);
  // The entry's expiry: its timer's deadline; Time::never() without a timer.
  [[nodiscard]] Time expiry(std::uint32_t index, const TimerHeap& timers) const;
  // The entry at `index` is live.
  [[nodiscard]] bool live(std::uint32_t index) const noexcept {
    return index < live_.size() && live_[index] != 0;
  }

  // Indices, the tuple index and the free list consistent; aborts on failure.
  void check_invariants() const;
  // As check_invariants(), and every live entry's timer is a time_wait timer
  // of `timers` whose owner is the entry's index.
  void check_invariants(const TimerHeap& timers) const;

private:
  ConnTable index_;                    // tuple -> entry index
  std::vector<TimeWaitEntry> entries_;
  std::vector<std::uint8_t> live_;     // by index
  std::vector<std::uint32_t> free_;    // min-heap of free indices (lowest reused first)
  std::size_t count_ = 0;
};

}  // namespace utcp
