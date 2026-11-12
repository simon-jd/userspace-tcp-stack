// Socket events (DESIGN §3.5): per-socket pending bits and a FIFO of the
// sockets that have any.
//
// Events are edge-triggered and coalesced: raise() ORs bits into the socket's
// pending set; a socket with pending bits sits in the FIFO exactly once, at the
// position where it first became pending; poll() returns the oldest socket
// with all of its bits and clears them. The order depends only on inputs.
// TCP and UDP sockets are kept apart (a Handle's slot indexes its protocol's
// slot vector). drop() forgets a socket's pending bits when its handle becomes
// invalid; its FIFO entry is skipped later (each entry carries the sequence
// number of the raise that queued it).
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "utcp/stack.hpp"
#include "utcp/types.hpp"

namespace utcp {

class EventQueue {
public:
  EventQueue();

  // ORs `ev` into the pending bits of `h` and queues `h` if it had none. Bits
  // still pending for an older handle of the same slot (not dropped) are
  // replaced. ev == 0 does nothing.
  void raise(Handle h, std::uint16_t ev);
  // Forgets the pending bits of `h` (no-op if it has none).
  void drop(Handle h) noexcept;
  // The oldest socket with pending bits, and the bits; nullopt if none.
  std::optional<SocketEvent> poll() noexcept;

  // Pending bits of `h` (0 for none or for another generation of the slot).
  [[nodiscard]] std::uint16_t pending(Handle h) const noexcept;
  // Sockets with pending bits.
  [[nodiscard]] std::uint32_t queued() const noexcept { return queued_; }

  // The FIFO holds exactly one valid entry per pending socket; aborts on
  // failure.
  void check_invariants() const;

private:
  struct State {
    std::uint32_t gen = 0;
    std::uint16_t bits = 0;
    std::uint64_t seq = 0;  // of the raise that queued the current entry
  };
  struct Entry {
    Handle h;
    std::uint64_t seq = 0;
  };

  [[nodiscard]] const State* find(Handle h) const noexcept;
  State& state(Handle h);
  [[nodiscard]] bool valid(const Entry& e) const noexcept;

  std::array<std::vector<State>, 2> states_;  // by Proto
  std::vector<Entry> ring_;                   // size a power of two
  std::uint32_t head_ = 0, count_ = 0;        // entries in the ring, stale ones included
  std::uint32_t queued_ = 0;                  // valid entries
  std::uint64_t next_seq_ = 1;
};

}  // namespace utcp
