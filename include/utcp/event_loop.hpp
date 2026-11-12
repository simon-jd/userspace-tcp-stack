// The backend's event loop (DESIGN §8.2): epoll_pwait2 with nanosecond
// timeouts on CLOCK_MONOTONIC, a signalfd for stop signals and 1 us timer
// slack. Not part of utcp_core (it makes system calls); lives in utcp_backend.
//
// One iteration (run_once):
// 1. deadline = the deadline source's value (Time::never() without one);
// 2. wait with epoll_pwait2: timeout 0 if the deadline has passed, no timeout
//    (blocking) for Time::never(), else deadline - mono_now();
// 3. call the callbacks of ready fds in the order epoll reports them; a
//    readable signalfd stops the loop (stop_signal() tells which signal);
// 4. if mono_now() >= deadline, record the lateness (now - deadline) and call
//    the deadline handler with that time.
// UtcpTransport builds the stack iteration of §8.2 on this (advance, read up
// to 64 datagrams, deliver events, drain pop_transmit).
#pragma once

#include <signal.h>

#include <array>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "utcp/time.hpp"

namespace utcp {

// clock_gettime(CLOCK_MONOTONIC) as a Time.
[[nodiscard]] Time mono_now() noexcept;

struct EventLoopOptions {
  // Blocked in the constructing thread and read from a signalfd; any of them
  // ends run(). Empty: no signalfd.
  std::vector<int> stop_signals{SIGINT, SIGTERM};
  std::uint64_t timer_slack_ns = 1000;  // prctl(PR_SET_TIMERSLACK); 0 leaves it unchanged
};

// Wake-up lateness (§8.3) in log2 buckets: bucket 0 counts 0 ns, bucket i
// (1..63) counts [2^(i-1), 2^i) ns. utcp-bulk reports its percentiles.
struct LatenessHistogram {
  static constexpr std::size_t bucket_count = 64;
  std::array<std::uint64_t, bucket_count> buckets{};
  std::uint64_t count = 0;
  Duration max{};  // largest recorded value

  // A negative value (woke before the deadline) counts as 0.
  void record(Duration lateness) noexcept;
  // An upper bound of the q-quantile, q in (0, 1]: the inclusive upper edge
  // of the bucket that holds the sample of rank ceil(q * count) (0 for bucket
  // 0, 2^i - 1 ns for bucket i), at most max. 0 when empty.
  [[nodiscard]] Duration percentile(double q) const noexcept;
};

struct LoopStats {
  std::uint64_t iterations = 0;        // run_once calls
  std::uint64_t io_wakeups = 0;        // waits that returned ready fds
  std::uint64_t deadline_calls = 0;    // deadline handler calls
  std::uint64_t zero_timeouts = 0;     // waits whose deadline had already passed
  std::uint64_t blocking_waits = 0;    // waits without a deadline
  std::int64_t last_timeout_ns = -1;   // timeout of the last wait; -1 = none (blocking)
  // now - deadline at each deadline handler call (§8.3). m1-backend adds
  // --spin-us and the lateness measurement runs.
  LatenessHistogram lateness;
};

class EventLoop {
public:
  using IoCallback = std::function<void(std::uint32_t epoll_events)>;
  using DeadlineSource = std::function<Time()>;
  using DeadlineHandler = std::function<void(Time now)>;

  // epoll_create1, the signalfd and the timer slack. Aborts with a message if
  // a system call fails. The stop signals are blocked in the constructing
  // thread (create the loop before starting other threads, so they inherit
  // the mask); the destructor restores the previous mask.
  EventLoop();
  explicit EventLoop(const EventLoopOptions& options);
  ~EventLoop();
  EventLoop(const EventLoop&) = delete;
  EventLoop& operator=(const EventLoop&) = delete;

  // Calls `cb` with the ready epoll events (EPOLLIN, EPOLLOUT, ...) of `fd`
  // (level-triggered). The loop does not own `fd`; watching an fd twice
  // aborts. A callback may watch, modify or unwatch fds, its own included; an
  // fd unwatched during an iteration gets no further callbacks in it, also
  // when its number is reused and watched again in the same iteration (the
  // new registration only sees events of later waits).
  void watch(int fd, std::uint32_t events, IoCallback cb);
  void modify(int fd, std::uint32_t events);
  void unwatch(int fd);

  // Queried at the start of every iteration (usually min(stack.next_deadline(),
  // app timers)).
  void set_deadline_source(DeadlineSource f);
  void set_deadline_handler(DeadlineHandler f);

  void run_once();
  // Iterates until stop() or a stop signal; returns at once if already stopped.
  void run();
  void stop() noexcept { stopped_ = true; }
  [[nodiscard]] bool stopped() const noexcept { return stopped_; }
  // The signal that stopped the loop, 0 if none.
  [[nodiscard]] int stop_signal() const noexcept { return stop_signal_; }

  [[nodiscard]] const LoopStats& stats() const noexcept { return stats_; }

private:
  // Implementation state; event_loop.cpp may change it.
  int epfd_ = -1;
  int sigfd_ = -1;
  sigset_t saved_mask_{};    // signal mask before the constructor blocked the stop signals
  bool restore_mask_ = false;
  // Indexed by fd. Shared, so a callback may unwatch its own fd while it runs.
  // Each watch() takes a new generation, stored with the fd in the epoll
  // event data (generation << 32 | fd); an event whose generation is not the
  // fd's current one belongs to an earlier registration and is skipped.
  struct Watch {
    std::shared_ptr<IoCallback> cb;
    std::uint32_t gen = 0;
  };
  std::vector<Watch> watches_;
  std::uint32_t next_gen_ = 1;  // 0 is the signalfd's
  DeadlineSource deadline_source_;
  DeadlineHandler deadline_handler_;
  bool stopped_ = false;
  int stop_signal_ = 0;
  LoopStats stats_;
};

}  // namespace utcp
