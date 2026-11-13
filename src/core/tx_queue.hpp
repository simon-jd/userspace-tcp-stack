// The transmit queue and the FIFO of blocked producers (DESIGN §3.4).
//
// TxQueue: a bounded FIFO of complete datagrams in production order, drained
// by Stack::pop_transmit. Its ring is preallocated at construction
// (StackConfig::tx_queue_packets). Each entry may name the TCP connection
// (slot) that produced it, so queued_for(slot) can tell whether a packet of a
// connection still waits in the stack (the app-limited test of §5.4). When
// the connection's slot is freed, disown(slot) detaches its queued packets,
// so a later connection in the same slot does not count them.
//
// BlockedFifo: producers (TCP connections, by slot) that stopped because the
// queue or the packet pool was full, each at most once, in the order in which
// they blocked. Stack::advance resumes them in that order. Every push takes a
// sequence number, so a caller can resume only the slots that were queued
// when it started (pushes() and pop_before()).
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "utcp/packet.hpp"

namespace utcp {

class TxQueue {
public:
  explicit TxQueue(std::uint32_t capacity);

  [[nodiscard]] std::uint32_t capacity() const noexcept {
    return static_cast<std::uint32_t>(ring_.size());
  }
  [[nodiscard]] std::uint32_t size() const noexcept { return count_; }
  [[nodiscard]] bool empty() const noexcept { return count_ == 0; }
  [[nodiscard]] bool full() const noexcept { return count_ == ring_.size(); }

  // Appends a datagram. Precondition (checked): !full().
  void push(TxPacket&& p, std::optional<std::uint32_t> owner_slot);
  // Removes the oldest datagram; nullopt if empty.
  std::optional<TxPacket> pop() noexcept;

  // Queued datagrams pushed with this owner slot (and not disowned since).
  [[nodiscard]] std::uint32_t queued_for(std::uint32_t slot) const noexcept;
  // The connection in `slot` was freed: its queued datagrams stay queued but
  // belong to no owner, and queued_for(slot) is 0. O(size()) when it has any.
  void disown(std::uint32_t slot) noexcept;

  // Counts agree with the entries; aborts on failure.
  void check_invariants() const;

private:
  static constexpr std::uint32_t no_owner = 0xffff'ffff;

  struct Slot {
    TxPacket p;
    std::uint32_t owner = no_owner;
  };

  std::vector<Slot> ring_;
  std::uint32_t head_ = 0, count_ = 0;
  std::vector<std::uint32_t> per_owner_;  // indexed by slot; grows on first use of a slot
};

class BlockedFifo {
public:
  // Appends `slot` unless it is already queued.
  void push(std::uint32_t slot);
  // Removes the oldest slot; nullopt if empty.
  std::optional<std::uint32_t> pop() noexcept;
  // Pushes that appended a slot so far. A value taken before some calls is a
  // mark for pop_before: slots appended after it have numbers >= the mark.
  [[nodiscard]] std::uint64_t pushes() const noexcept { return pushes_; }
  // Removes and returns the oldest slot if it was appended before `mark`;
  // nullopt if empty or if the oldest was appended at or after `mark` (then so
  // were all others: the FIFO keeps push order).
  std::optional<std::uint32_t> pop_before(std::uint64_t mark) noexcept;
  // Removes `slot` wherever it is, keeping the order of the others; false if
  // it is not queued. O(size()).
  bool erase(std::uint32_t slot) noexcept;

  [[nodiscard]] bool contains(std::uint32_t slot) const noexcept {
    return slot < queued_.size() && queued_[slot] != 0;
  }
  [[nodiscard]] std::uint32_t size() const noexcept { return count_; }
  [[nodiscard]] bool empty() const noexcept { return count_ == 0; }

  // Membership flags agree with the ring and push numbers increase from the
  // oldest entry; aborts on failure.
  void check_invariants() const;

private:
  struct Entry {
    std::uint32_t slot = 0;
    std::uint64_t seq = 0;  // value of pushes_ when it was appended
  };

  std::vector<Entry> ring_;  // size 0 or a power of two
  std::uint32_t head_ = 0, count_ = 0;
  std::uint64_t pushes_ = 0;
  std::vector<std::uint8_t> queued_;  // indexed by slot
};

}  // namespace utcp
