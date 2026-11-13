#include "core/tcp/time_wait.hpp"

#include <algorithm>
#include <functional>

#include "utcp/check.hpp"

namespace utcp {

TimeWaitTable::TimeWaitTable(const SipKey& hash_key) : index_(hash_key) {}

std::uint32_t TimeWaitTable::insert(const TimeWaitEntry& e) {
  std::uint32_t i = 0;
  if (!free_.empty()) {
    std::pop_heap(free_.begin(), free_.end(), std::greater<>{});
    i = free_.back();
    free_.pop_back();
  } else {
    i = static_cast<std::uint32_t>(entries_.size());
    entries_.emplace_back();
    live_.push_back(0);
  }
  UTCP_CHECK(index_.insert(e.tuple, i));
  entries_[i] = e;
  live_[i] = 1;
  ++count_;
  return i;
}

std::optional<std::uint32_t> TimeWaitTable::find(const FourTuple& tuple) const {
  return index_.find(tuple);
}

TimeWaitEntry& TimeWaitTable::entry(std::uint32_t index) {
  UTCP_CHECK(live(index));
  return entries_[index];
}

const TimeWaitEntry& TimeWaitTable::entry(std::uint32_t index) const {
  UTCP_CHECK(live(index));
  return entries_[index];
}

void TimeWaitTable::erase(std::uint32_t index) {
  UTCP_CHECK(live(index));
  UTCP_CHECK(index_.erase(entries_[index].tuple));
  entries_[index] = TimeWaitEntry{};
  live_[index] = 0;
  free_.push_back(index);
  std::push_heap(free_.begin(), free_.end(), std::greater<>{});
  --count_;
}

std::size_t TimeWaitTable::size() const { return count_; }

std::uint32_t TimeWaitTable::insert(const TimeWaitEntry& e, TimerHeap& timers, Time expiry) {
  TimeWaitEntry copy = e;
  copy.timer = no_timer;
  const std::uint32_t i = insert(copy);
  // §6: the TIME_WAIT entry's timer, owner = entry index.
  entries_[i].timer = timers.create(i, TimerKind::time_wait);
  timers.arm(entries_[i].timer, expiry);
  return i;
}

void TimeWaitTable::restart(std::uint32_t index, TimerHeap& timers, Time expiry) {
  const TimeWaitEntry& e = entry(index);
  UTCP_CHECK(e.timer != no_timer);
  timers.arm(e.timer, expiry);
}

void TimeWaitTable::erase(std::uint32_t index, TimerHeap& timers) {
  const TimeWaitEntry& e = entry(index);
  if (e.timer != no_timer) {
    timers.destroy(e.timer);
  }
  erase(index);
}

Time TimeWaitTable::expiry(std::uint32_t index, const TimerHeap& timers) const {
  const TimeWaitEntry& e = entry(index);
  return e.timer != no_timer ? timers.deadline(e.timer) : Time::never();
}

void TimeWaitTable::check_invariants() const {
  index_.check_invariants();
  UTCP_CHECK(entries_.size() == live_.size());
  UTCP_CHECK(std::is_heap(free_.begin(), free_.end(), std::greater<>{}));
  std::vector<std::uint8_t> is_free(entries_.size(), 0);
  for (const std::uint32_t f : free_) {
    UTCP_CHECK(f < entries_.size() && live_[f] == 0 && is_free[f] == 0);
    is_free[f] = 1;
  }
  std::size_t n = 0;
  for (std::uint32_t i = 0; i < entries_.size(); ++i) {
    if (live_[i] == 0) {
      UTCP_CHECK(is_free[i] == 1);
      continue;
    }
    ++n;
    const auto found = index_.find(entries_[i].tuple);
    UTCP_CHECK(found.has_value() && *found == i);
  }
  UTCP_CHECK(n == count_ && index_.size() == count_);
}

void TimeWaitTable::check_invariants(const TimerHeap& timers) const {
  check_invariants();
  for (std::uint32_t i = 0; i < entries_.size(); ++i) {
    if (live_[i] != 0 && entries_[i].timer != no_timer) {
      UTCP_CHECK(timers.kind(entries_[i].timer) == TimerKind::time_wait);
      UTCP_CHECK(timers.owner(entries_[i].timer) == i);
    }
  }
}

}  // namespace utcp
