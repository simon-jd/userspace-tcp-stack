// Two Stacks wired back to back (DESIGN §11, "two-stack loopback harness").
//
// The harness keeps one virtual clock. Every datagram a stack transmits is
// taken from its transmit queue (pop_transmit), copied, logged and passed to a
// hook that may rewrite it in place and decides whether it is delivered,
// dropped or held. Delivered datagrams arrive at the other stack after the
// one-way delay of their direction (default 0: at once); held datagrams wait
// until the test releases them, which reorders them behind later ones.
// run_until() moves the clock from event to event (a stack's next_deadline()
// or a delivery), calling advance() on due stacks, so timers fire as they
// would in a host that follows the host contract (§3.4). Socket events are
// left in the stacks for the test to poll.
//
// Used by the IP-layer tests (UDP, ICMP) and the TCP tests of m1-tcp-*.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

#include "support/packet_builder.hpp"
#include "utcp/config.hpp"
#include "utcp/stack.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp::test {

enum class Side : std::uint8_t { a, b };

[[nodiscard]] constexpr Side other(Side s) noexcept { return s == Side::a ? Side::b : Side::a; }

// What happens to a datagram in flight.
enum class Verdict : std::uint8_t { deliver, drop, hold };

// One datagram taken from a stack's transmit queue.
struct Sent {
  Time t;          // when the harness took it
  Side from = Side::a;
  Bytes bytes;     // as the stack sent it, before the hook
  Verdict verdict = Verdict::deliver;
};

class TcpHarness {
public:
  // Called for each datagram taken from `from`. It may rewrite `datagram` in
  // place (fix_checksums() after editing) and returns its fate.
  using Hook = std::function<Verdict(Side from, Bytes& datagram)>;

  // Stack a is 10.0.0.1 (seed 1), b is 10.0.0.2 (seed 2), both with
  // assert_time_monotonic on.
  [[nodiscard]] static StackConfig default_config(Side s);
  static constexpr Time default_start{1'000'000'000};  // 1 s

  TcpHarness();
  TcpHarness(const StackConfig& a, const StackConfig& b, Time start = default_start);
  TcpHarness(const TcpHarness&) = delete;
  TcpHarness& operator=(const TcpHarness&) = delete;

  Stack& a() noexcept { return a_; }
  Stack& b() noexcept { return b_; }
  Stack& stack(Side s) noexcept { return s == Side::a ? a_ : b_; }
  [[nodiscard]] Ipv4Addr addr(Side s) const noexcept {
    return (s == Side::a ? a_ : b_).config().local_addr;
  }
  [[nodiscard]] Time now() const noexcept { return now_; }

  // One-way delay of datagrams sent by `from`.
  void set_delay(Side from, Duration d) noexcept { delay_[index(from)] = d; }
  // nullptr (the default) delivers everything.
  void set_hook(Hook hook) { hook_ = std::move(hook); }

  // At the current time: drains both transmit queues through the hook and
  // delivers every datagram due, until nothing moves. Returns the number of
  // datagrams delivered.
  std::size_t settle();
  // Moves the clock to each next event up to `end` (advancing due stacks and
  // settling at each), then advances both stacks to `end`.
  void run_until(Time end);
  void run_for(Duration d) { run_until(now_ + d); }

  // Held datagrams, oldest first.
  [[nodiscard]] std::size_t held_count() const noexcept { return held_.size(); }
  [[nodiscard]] const Bytes& held(std::size_t i) const { return held_[i].bytes; }
  // Sends held datagram `i` on now (it arrives after its direction's delay)
  // and removes it from the held list. Call settle() or run_until() to
  // deliver it.
  void release_held(std::size_t i);
  void release_all_held();
  void drop_held() noexcept { held_.clear(); }

  [[nodiscard]] const std::vector<Sent>& log() const noexcept { return log_; }
  void clear_log() noexcept { log_.clear(); }
  [[nodiscard]] std::size_t delivered() const noexcept { return delivered_; }
  [[nodiscard]] std::size_t dropped() const noexcept { return dropped_; }

private:
  struct InFlight {
    Time at;
    std::uint64_t seq = 0;
    Side to = Side::a;
    Bytes bytes;
  };
  struct Held {
    Side from = Side::a;
    Bytes bytes;
  };

  static constexpr std::size_t index(Side s) noexcept { return s == Side::a ? 0 : 1; }
  void send(Side from, Bytes bytes);
  void sync_clock() noexcept;
  [[nodiscard]] Time next_event() const;

  Stack a_, b_;
  Time now_;
  std::array<Duration, 2> delay_{};
  Hook hook_;
  std::vector<InFlight> flight_;  // sorted by (at, seq)
  std::vector<Held> held_;
  std::vector<Sent> log_;
  std::uint64_t next_seq_ = 0;
  std::size_t delivered_ = 0, dropped_ = 0;
};

}  // namespace utcp::test
