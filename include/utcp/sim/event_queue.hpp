// The simulator's event queue (DESIGN §7.1): a min-heap of events ordered by
// (time, seq), where seq is a global insertion counter, so events at the same
// virtual time run in the order they were scheduled.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "utcp/check.hpp"
#include "utcp/time.hpp"

namespace utcp::sim {

enum class EventType : std::uint8_t {
  packet,      // a datagram at the entrance of a link segment (a = path, b = segment, c = packet id)
  node_wake,   // a node's next_deadline() (a = node, c = generation)
  app_wake,    // a node's next application action (a = node, c = generation)
  host_drain,  // the host drains more packets after host_delay (a = node, c = generation)
};

struct SimEvent {
  Time t;
  std::uint64_t seq = 0;
  EventType type = EventType::packet;
  std::uint32_t a = 0, b = 0;
  std::uint64_t c = 0;
};

class EventQueue {
public:
  void push(Time t, EventType type, std::uint32_t a, std::uint32_t b, std::uint64_t c) {
    heap_.push_back(SimEvent{t, next_seq_++, type, a, b, c});
    std::push_heap(heap_.begin(), heap_.end(), later);
  }
  [[nodiscard]] bool empty() const noexcept { return heap_.empty(); }
  [[nodiscard]] std::size_t size() const noexcept { return heap_.size(); }
  [[nodiscard]] const SimEvent& top() const {
    UTCP_CHECK(!heap_.empty());
    return heap_.front();
  }
  SimEvent pop() {
    UTCP_CHECK(!heap_.empty());
    std::pop_heap(heap_.begin(), heap_.end(), later);
    SimEvent e = heap_.back();
    heap_.pop_back();
    return e;
  }
  // Events pushed so far.
  [[nodiscard]] std::uint64_t pushed() const noexcept { return next_seq_; }

private:
  // Heap order: the earliest (t, seq) on top.
  static bool later(const SimEvent& x, const SimEvent& y) noexcept {
    return x.t != y.t ? x.t > y.t : x.seq > y.seq;
  }

  std::vector<SimEvent> heap_;
  std::uint64_t next_seq_ = 0;
};

}  // namespace utcp::sim
