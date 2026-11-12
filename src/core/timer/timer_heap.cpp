#include "core/timer/timer_heap.hpp"

#include <algorithm>
#include <functional>

#include "utcp/check.hpp"

namespace utcp {

TimerId TimerHeap::create(std::uint32_t owner, TimerKind kind) {
  TimerId id = 0;
  if (!free_.empty()) {
    std::pop_heap(free_.begin(), free_.end(), std::greater<>{});
    id = free_.back();
    free_.pop_back();
  } else {
    UTCP_CHECK(nodes_.size() < no_timer);
    id = static_cast<TimerId>(nodes_.size());
    nodes_.emplace_back();
  }
  Node& n = nodes_[id];
  n = Node{};
  n.owner = owner;
  n.kind = kind;
  n.live = true;
  return id;
}

void TimerHeap::destroy(TimerId id) noexcept {
  UTCP_CHECK(id < nodes_.size() && nodes_[id].live);
  cancel(id);
  nodes_[id].live = false;
  free_.push_back(id);
  std::push_heap(free_.begin(), free_.end(), std::greater<>{});
}

void TimerHeap::arm(TimerId id, Time deadline) {
  UTCP_CHECK(id < nodes_.size() && nodes_[id].live);
  Node& n = nodes_[id];
  const TimerKey k{deadline, next_seq_++};
  n.want = k;
  if (n.pos == npos) {
    n.key = k;
    const auto pos = static_cast<std::uint32_t>(heap_.size());
    heap_.push_back(id);
    n.pos = pos;
    sift_up(pos);
  } else if (k < n.key) {
    n.key = k;
    sift_up(n.pos);
  } else if (n.pos == 0) {
    // A later key for the top: repair now, so that the top stays exact.
    fix_up();
  }
  // Otherwise the entry keeps its earlier key (a lower bound): lazy re-arm.
  // It is repaired when it reaches the top.
}

void TimerHeap::cancel(TimerId id) noexcept {
  UTCP_CHECK(id < nodes_.size() && nodes_[id].live);
  if (nodes_[id].pos != npos) {
    remove_at(nodes_[id].pos);
  }
}

bool TimerHeap::armed(TimerId id) const noexcept { return nodes_[id].pos != npos; }

Time TimerHeap::deadline(TimerId id) const noexcept {
  return armed(id) ? nodes_[id].want.deadline : Time::never();
}

std::uint32_t TimerHeap::owner(TimerId id) const noexcept { return nodes_[id].owner; }

TimerKind TimerHeap::kind(TimerId id) const noexcept { return nodes_[id].kind; }

void TimerHeap::fix_up() noexcept {
  while (!heap_.empty()) {
    Node& top = nodes_[heap_[0]];
    if (top.key == top.want) {
      return;
    }
    top.key = top.want;
    sift_down(0);
  }
}

Time TimerHeap::next_deadline() const noexcept {
  if (heap_.empty()) {
    return Time::never();
  }
  const Node& top = nodes_[heap_[0]];
  UTCP_DCHECK(top.key == top.want);
  return top.want.deadline;
}

std::optional<FiredTimer> TimerHeap::pop_due(Time now) noexcept {
  while (!heap_.empty()) {
    const TimerId id = heap_[0];
    Node& top = nodes_[id];
    if (top.key != top.want) {
      top.key = top.want;
      sift_down(0);
      continue;
    }
    if (top.key.deadline > now) {
      return std::nullopt;
    }
    const FiredTimer fired{id, top.owner, top.kind, top.key};
    remove_at(0);  // repairs the new top
    return fired;
  }
  return std::nullopt;
}

void TimerHeap::place(std::uint32_t pos, TimerId id) noexcept {
  heap_[pos] = id;
  nodes_[id].pos = pos;
}

void TimerHeap::sift_up(std::uint32_t pos) noexcept {
  const TimerId id = heap_[pos];
  const TimerKey key = nodes_[id].key;
  while (pos > 0) {
    const std::uint32_t parent = (pos - 1) / 4;
    if (!(key < nodes_[heap_[parent]].key)) {
      break;
    }
    place(pos, heap_[parent]);
    pos = parent;
  }
  place(pos, id);
}

void TimerHeap::sift_down(std::uint32_t pos) noexcept {
  const TimerId id = heap_[pos];
  const TimerKey key = nodes_[id].key;
  const auto n = static_cast<std::uint32_t>(heap_.size());
  for (;;) {
    const std::uint32_t first = 4 * pos + 1;
    if (first >= n) {
      break;
    }
    std::uint32_t best = first;
    const std::uint32_t end = std::min(first + 4, n);
    for (std::uint32_t c = first + 1; c < end; ++c) {
      if (less(c, best)) {
        best = c;
      }
    }
    if (!(nodes_[heap_[best]].key < key)) {
      break;
    }
    place(pos, heap_[best]);
    pos = best;
  }
  place(pos, id);
}

void TimerHeap::remove_at(std::uint32_t pos) noexcept {
  const TimerId id = heap_[pos];
  const auto last = static_cast<std::uint32_t>(heap_.size() - 1);
  if (pos != last) {
    place(pos, heap_[last]);
    heap_.pop_back();
    if (pos > 0 && nodes_[heap_[pos]].key < nodes_[heap_[(pos - 1) / 4]].key) {
      sift_up(pos);
    } else {
      sift_down(pos);
    }
  } else {
    heap_.pop_back();
  }
  nodes_[id].pos = npos;
  // Only removing the top can change it (every other entry's key is above the
  // top's, keys are unique); the new top may be a lazily re-armed entry.
  if (pos == 0) {
    fix_up();
  }
}

void TimerHeap::check_invariants() const {
  if (!heap_.empty()) {
    const Node& top = nodes_[heap_[0]];
    UTCP_CHECK(top.key == top.want);
  }
  for (std::size_t pos = 0; pos < heap_.size(); ++pos) {
    const Node& n = nodes_[heap_[pos]];
    UTCP_CHECK(n.live);
    UTCP_CHECK(n.pos == pos);
    UTCP_CHECK(n.key <= n.want);
    if (pos > 0) {
      UTCP_CHECK(nodes_[heap_[(pos - 1) / 4]].key <= n.key);
    }
  }
  std::size_t armed_nodes = 0;
  for (const Node& n : nodes_) {
    if (n.pos != npos) {
      UTCP_CHECK(n.live);
      ++armed_nodes;
    }
  }
  UTCP_CHECK(armed_nodes == heap_.size());
  for (const TimerId id : free_) {
    UTCP_CHECK(id < nodes_.size() && !nodes_[id].live);
  }
}

}  // namespace utcp
