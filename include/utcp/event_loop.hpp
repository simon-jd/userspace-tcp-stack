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
// 4. if mono_now() >= deadline, call the deadline handler with that time.
// UtcpTransport builds the stack iteration of §8.2 on this (advance, read up
// to 64 datagrams, deliver events, drain pop_transmit).
#pragma once

#include <signal.h>

#include <csignal>
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

struct LoopStats {
  std::uint64_t iterations = 0;        // run_once calls
  std::uint64_t io_wakeups = 0;        // waits that returned ready fds
  std::uint64_t deadline_calls = 0;    // deadline handler calls
  std::uint64_t zero_timeouts = 0;     // waits whose deadline had already passed
  std::uint64_t blocking_waits = 0;    // waits without a deadline
  std::int64_t last_timeout_ns = -1;   // timeout of the last wait; -1 = none (blocking)
  // m1-backend adds the wake-up lateness histogram (§8.3).
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
  // fd unwatched during an iteration gets no further callbacks in it.
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
  std::vector<std::shared_ptr<IoCallback>> callbacks_;
  DeadlineSource deadline_source_;
  DeadlineHandler deadline_handler_;
  bool stopped_ = false;
  int stop_signal_ = 0;
  LoopStats stats_;
};

}  // namespace utcp
