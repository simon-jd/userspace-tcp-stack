#include "core/events.hpp"

#include <utility>

#include "utcp/check.hpp"

namespace utcp {
namespace {

constexpr std::size_t proto_index(Proto p) noexcept { return p == Proto::tcp ? 0 : 1; }

}  // namespace

EventQueue::EventQueue() : ring_(64) {}

const EventQueue::State* EventQueue::find(Handle h) const noexcept {
  const auto& v = states_[proto_index(h.proto)];
  return h.slot < v.size() ? &v[h.slot] : nullptr;
}

EventQueue::State& EventQueue::state(Handle h) {
  auto& v = states_[proto_index(h.proto)];
  if (h.slot >= v.size()) {
    v.resize(std::size_t{h.slot} + 1);
  }
  return v[h.slot];
}

bool EventQueue::valid(const Entry& e) const noexcept {
  const State* s = find(e.h);
  return s != nullptr && s->bits != 0 && s->seq == e.seq;
}

void EventQueue::raise(Handle h, std::uint16_t ev) {
  if (ev == 0) {
    return;
  }
  State& s = state(h);
  if (s.bits != 0 && s.gen == h.gen) {
    s.bits = static_cast<std::uint16_t>(s.bits | ev);  // coalesced, keeps its FIFO position
    return;
  }
  if (s.bits != 0) {
    --queued_;  // bits of an older handle of this slot: replaced, its entry goes stale
  }
  s.gen = h.gen;
  s.bits = ev;
  s.seq = next_seq_++;
  if (count_ == ring_.size()) {
    std::vector<Entry> bigger(ring_.size() * 2);
    for (std::uint32_t i = 0; i < count_; ++i) {
      bigger[i] = ring_[(head_ + i) & (ring_.size() - 1)];
    }
    ring_ = std::move(bigger);
    head_ = 0;
  }
  ring_[(head_ + count_) & (ring_.size() - 1)] = Entry{h, s.seq};
  ++count_;
  ++queued_;
}

void EventQueue::drop(Handle h) noexcept {
  auto& v = states_[proto_index(h.proto)];
  if (h.slot < v.size()) {
    State& s = v[h.slot];
    if (s.bits != 0 && s.gen == h.gen) {
      s.bits = 0;
      --queued_;
    }
  }
}

std::optional<SocketEvent> EventQueue::poll() noexcept {
  while (count_ > 0) {
    const Entry e = ring_[head_];
    head_ = static_cast<std::uint32_t>((head_ + 1) & (ring_.size() - 1));
    --count_;
    if (!valid(e)) {
      continue;  // dropped or replaced
    }
    State& s = states_[proto_index(e.h.proto)][e.h.slot];
    const SocketEvent out{e.h, s.bits};
    s.bits = 0;
    --queued_;
    return out;
  }
  return std::nullopt;
}

std::uint16_t EventQueue::pending(Handle h) const noexcept {
  const State* s = find(h);
  return s != nullptr && s->gen == h.gen ? s->bits : std::uint16_t{0};
}

void EventQueue::check_invariants() const {
  UTCP_CHECK(!ring_.empty() && (ring_.size() & (ring_.size() - 1)) == 0);
  UTCP_CHECK(count_ <= ring_.size());
  std::uint32_t valid_entries = 0;
  for (std::uint32_t i = 0; i < count_; ++i) {
    const Entry& e = ring_[(head_ + i) & (ring_.size() - 1)];
    if (valid(e)) {
      ++valid_entries;
      UTCP_CHECK(find(e.h)->gen == e.h.gen);
    }
  }
  std::uint32_t pending_sockets = 0;
  for (const auto& v : states_) {
    for (const State& s : v) {
      pending_sockets += s.bits != 0 ? 1u : 0u;
    }
  }
  UTCP_CHECK(valid_entries == queued_);
  UTCP_CHECK(pending_sockets == queued_);
}

}  // namespace utcp
