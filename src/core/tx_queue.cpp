#include "core/tx_queue.hpp"

#include <utility>

#include "utcp/check.hpp"

namespace utcp {

// --- TxQueue

TxQueue::TxQueue(std::uint32_t capacity) : ring_(capacity) { UTCP_CHECK(capacity > 0); }

void TxQueue::push(TxPacket&& p, std::optional<std::uint32_t> owner_slot) {
  UTCP_CHECK(!full());
  const auto cap = static_cast<std::uint32_t>(ring_.size());
  Slot& s = ring_[(head_ + count_) % cap];
  s.p = std::move(p);
  s.owner = no_owner;
  if (owner_slot.has_value()) {
    const std::uint32_t o = *owner_slot;
    UTCP_CHECK(o != no_owner);
    if (o >= per_owner_.size()) {
      per_owner_.resize(std::size_t{o} + 1, 0);
    }
    ++per_owner_[o];
    s.owner = o;
  }
  ++count_;
}

std::optional<TxPacket> TxQueue::pop() noexcept {
  if (count_ == 0) {
    return std::nullopt;
  }
  Slot& s = ring_[head_];
  if (s.owner != no_owner) {
    --per_owner_[s.owner];
    s.owner = no_owner;
  }
  std::optional<TxPacket> out(std::move(s.p));
  s.p = TxPacket{};
  head_ = (head_ + 1) % static_cast<std::uint32_t>(ring_.size());
  --count_;
  return out;
}

std::uint32_t TxQueue::queued_for(std::uint32_t slot) const noexcept {
  return slot < per_owner_.size() ? per_owner_[slot] : 0;
}

void TxQueue::check_invariants() const {
  const auto cap = static_cast<std::uint32_t>(ring_.size());
  UTCP_CHECK(head_ < cap && count_ <= cap);
  std::vector<std::uint32_t> recount(per_owner_.size(), 0);
  for (std::uint32_t i = 0; i < cap; ++i) {
    const Slot& s = ring_[(head_ + i) % cap];
    if (i < count_) {
      UTCP_CHECK(s.p.buf.valid());
      if (s.owner != no_owner) {
        UTCP_CHECK(s.owner < recount.size());
        ++recount[s.owner];
      }
    } else {
      UTCP_CHECK(!s.p.buf.valid() && s.owner == no_owner);
    }
  }
  UTCP_CHECK(recount == per_owner_);
}

// --- BlockedFifo

void BlockedFifo::push(std::uint32_t slot) {
  if (contains(slot)) {
    return;
  }
  if (slot >= queued_.size()) {
    queued_.resize(std::size_t{slot} + 1, 0);
  }
  if (count_ == ring_.size()) {
    // Grow by doubling, keeping FIFO order.
    std::vector<std::uint32_t> bigger(ring_.empty() ? 16 : ring_.size() * 2);
    for (std::uint32_t i = 0; i < count_; ++i) {
      bigger[i] = ring_[(head_ + i) & (ring_.size() - 1)];
    }
    ring_ = std::move(bigger);
    head_ = 0;
  }
  ring_[(head_ + count_) & (ring_.size() - 1)] = slot;
  ++count_;
  queued_[slot] = 1;
}

std::optional<std::uint32_t> BlockedFifo::pop() noexcept {
  if (count_ == 0) {
    return std::nullopt;
  }
  const std::uint32_t slot = ring_[head_];
  head_ = static_cast<std::uint32_t>((head_ + 1) & (ring_.size() - 1));
  --count_;
  queued_[slot] = 0;
  return slot;
}

bool BlockedFifo::erase(std::uint32_t slot) noexcept {
  if (!contains(slot)) {
    return false;
  }
  const std::size_t mask = ring_.size() - 1;
  std::uint32_t out = 0;
  for (std::uint32_t i = 0; i < count_; ++i) {
    const std::uint32_t s = ring_[(head_ + i) & mask];
    if (s != slot) {
      ring_[(head_ + out) & mask] = s;
      ++out;
    }
  }
  count_ = out;
  queued_[slot] = 0;
  return true;
}

void BlockedFifo::check_invariants() const {
  UTCP_CHECK(ring_.empty() || (ring_.size() & (ring_.size() - 1)) == 0);
  UTCP_CHECK(count_ <= ring_.size());
  std::vector<std::uint8_t> seen(queued_.size(), 0);
  for (std::uint32_t i = 0; i < count_; ++i) {
    const std::uint32_t slot = ring_[(head_ + i) & (ring_.size() - 1)];
    UTCP_CHECK(slot < seen.size() && seen[slot] == 0);
    seen[slot] = 1;
  }
  UTCP_CHECK(seen == queued_);
}

}  // namespace utcp
