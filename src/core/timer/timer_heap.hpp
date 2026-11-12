// The stack's single timer structure (DESIGN §6).
//
// An indexed 4-ary min-heap ordered by the key (deadline, arm_seq). arm_seq is
// a heap-wide counter taken at every arm call, so timers with equal deadlines
// fire in arming order: a total order that depends only on inputs.
//
// Owners create one TimerId per timer kind they use (a connection: xmit,
// delack, pace, fin_wait2, keepalive) and keep it; the heap maps ids to heap
// positions, so cancel and re-arm are O(log n) and the heap holds no stale
// entries. Ids are reused lowest-first, so they depend only on input history.
//
// Lazy re-arm: arming an armed timer to a later key (the RTO on every ACK)
// only records the wanted key; the entry keeps its earlier heap key, a lower
// bound, and is repaired when it reaches the top. The effective key is always
// (wanted deadline, arm_seq of the last arm call). Every call leaves the top
// entry exact (a lazily re-armed top, or a stale entry that a cancel, destroy
// or pop_due exposes, is repaired at once), so next_deadline() is exact at all
// times. fix_up() is that repair as a separate step; it finds nothing to do
// unless the invariant is broken.
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "utcp/time.hpp"

namespace utcp {

// DESIGN §6 table. The heap does not interpret kinds; the Stack dispatches.
enum class TimerKind : std::uint8_t {
  xmit,         // connection: rto, persist, reo or pto (LossRecovery::xmit_timer)
  delack,       // connection: delayed ACK
  pace,         // connection: pacing gate
  fin_wait2,    // connection: orphan FIN-WAIT-2 timeout
  keepalive,    // connection: reserved, never armed in M1
  time_wait,    // TIME_WAIT entry: 2*MSL
  pmtu_expiry,  // stack: earliest PMTU cache expiry
};
inline constexpr int timer_kind_count = 7;

using TimerId = std::uint32_t;
// Never returned by create(): owners use it for "no timer yet". destroy() and
// cancel() abort on it.
inline constexpr TimerId no_timer = 0xffff'ffff;

struct TimerKey {
  Time deadline;
  std::uint64_t arm_seq = 0;

  constexpr auto operator<=>(const TimerKey&) const = default;
};

struct FiredTimer {
  TimerId id;
  std::uint32_t owner;
  TimerKind kind;
  TimerKey key;  // effective key at firing
};

class TimerHeap {
public:
  // A new, unarmed timer. `owner` is opaque to the heap (slot index, TIME_WAIT
  // entry index, 0 for the stack) and returned when the timer fires.
  [[nodiscard]] TimerId create(std::uint32_t owner, TimerKind kind);
  // Cancels the timer and frees its id.
  void destroy(TimerId id) noexcept;

  // (Re)arms the timer at `deadline` with a new arm_seq.
  void arm(TimerId id, Time deadline);
  void cancel(TimerId id) noexcept;

  [[nodiscard]] bool armed(TimerId id) const noexcept;
  // Effective deadline; Time::never() if unarmed.
  [[nodiscard]] Time deadline(TimerId id) const noexcept;
  [[nodiscard]] std::uint32_t owner(TimerId id) const noexcept;
  [[nodiscard]] TimerKind kind(TimerId id) const noexcept;

  // Repairs stale entries at the top (a no-op while the top is exact, which
  // every other call guarantees).
  void fix_up() noexcept;
  // Earliest effective deadline, Time::never() if nothing is armed. Exact
  // after any sequence of calls.
  [[nodiscard]] Time next_deadline() const noexcept;
  // Removes and returns the armed timer with the smallest effective key if its
  // deadline is <= now. The timer stays allocated (unarmed).
  std::optional<FiredTimer> pop_due(Time now) noexcept;

  [[nodiscard]] std::size_t armed_count() const noexcept { return heap_.size(); }
  [[nodiscard]] std::size_t timer_count() const noexcept { return nodes_.size() - free_.size(); }

  // Verifies the heap order, the position index, key <= wanted and an exact
  // top; aborts on failure (Stack::debug_check).
  void check_invariants() const;

private:
  static constexpr std::uint32_t npos = 0xffff'ffff;

  struct Node {
    TimerKey key;     // heap order; key <= want while armed
    TimerKey want;    // effective key
    std::uint32_t owner = 0;
    std::uint32_t pos = npos;  // index in heap_, npos if unarmed
    TimerKind kind = TimerKind::xmit;
    bool live = false;
  };

  [[nodiscard]] bool less(std::uint32_t a, std::uint32_t b) const noexcept {
    return nodes_[heap_[a]].key < nodes_[heap_[b]].key;
  }
  void place(std::uint32_t pos, TimerId id) noexcept;
  void sift_up(std::uint32_t pos) noexcept;
  void sift_down(std::uint32_t pos) noexcept;
  void remove_at(std::uint32_t pos) noexcept;

  std::vector<Node> nodes_;
  std::vector<TimerId> heap_;
  std::vector<TimerId> free_;  // min-heap of free ids (lowest reused first)
  std::uint64_t next_seq_ = 0;
};

}  // namespace utcp
