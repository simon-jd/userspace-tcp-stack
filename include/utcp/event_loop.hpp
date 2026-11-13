// The backend's event loop (DESIGN §8.2): epoll_pwait2 with nanosecond
// timeouts on CLOCK_MONOTONIC, a signalfd for stop signals and 1 us timer
// slack. Not part of utcp_core (it makes system calls); lives in utcp_backend.
//
// One iteration (run_once):
// 1. deadline = the deadline source's value (Time::never() without one);
//    pending = the pending source's value (false without one);
// 2. wait with epoll_pwait2: timeout 0 if the deadline has passed or pending
//    is set, no timeout (blocking) for Time::never(), else deadline -
//    mono_now();
// 3. woke = mono_now() when the wait returns (§8.3: lateness is measured at
//    the wake-up);
// 4. call the callbacks of ready fds in the order epoll reports them; a
//    readable signalfd stops the loop (stop_signal() tells which signal);
// 5. now = mono_now(); if woke >= deadline, record the lateness (woke -
//    deadline) and call the deadline handler with now; if only now >=
//    deadline (it passed while the callbacks ran), call the handler without a
//    lateness sample (deadline_calls_after_wake); otherwise, if pending was
//    set, call the deadline handler without a lateness sample.
// With EventLoopOptions::spin_us = N > 0 (--spin-us, §8.3), step 2 sleeps only
// until N us before the deadline and then busy-polls (epoll_pwait2 with a
// zero timeout) until the deadline or the first ready fd. A wait that starts
// inside the last N us spins from its start; an earlier wake-up without ready
// fds (EINTR) ends the iteration without spinning.
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
  // --spin-us (§8.3): busy-poll the last spin_us microseconds before a
  // deadline instead of sleeping through them. 0 (the default): never spin.
  std::uint32_t spin_us = 0;
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
  std::uint64_t deadline_calls = 0;    // deadline handler calls for a deadline passed at the wake-up
  // Deadline handler calls for a deadline that passed only after the wake-up
  // (while the fd callbacks ran): no lateness sample.
  std::uint64_t deadline_calls_after_wake = 0;
  std::uint64_t pending_calls = 0;     // deadline handler calls for pending work only
  std::uint64_t zero_timeouts = 0;     // waits whose deadline had already passed
  std::uint64_t pending_polls = 0;     // zero-timeout waits for pending work (deadline not passed)
  std::uint64_t blocking_waits = 0;    // waits without a deadline
  // Timeout of the last iteration's first wait; -1 = none (blocking). With
  // spin_us, the sleep before the spin (deadline - spin_us - now, or 0).
  std::int64_t last_timeout_ns = -1;
  // woke - deadline at each deadline_calls call (§8.3: at the wake-up, before
  // the fd callbacks); pending work is not a deadline and adds no sample.
  LatenessHistogram lateness;
  // --spin-us (§8.3). spin_time is the wall time spent busy-polling, which is
  // also its CPU cost (less if the thread was preempted while spinning).
  std::uint64_t spin_waits = 0;  // iterations that busy-polled
  std::uint64_t spin_polls = 0;  // zero-timeout epoll_pwait2 calls while busy-polling
  Duration spin_time{};          // total time spent busy-polling
  Duration spin_lead_max{};      // largest deadline - (start of a busy-poll); <= spin_us
};

class EventLoop {
public:
  using IoCallback = std::function<void(std::uint32_t epoll_events)>;
  using DeadlineSource = std::function<Time()>;
  using DeadlineHandler = std::function<void(Time now)>;
  using PendingSource = std::function<bool()>;

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
  // Queried at the start of every iteration: true when work is due now that
  // is not a timer (UtcpTransport: blocked connections can resume, which
  // Stack::next_deadline() reports as now(), §3.4). Such an iteration does
  // not sleep (zero timeout, no --spin-us) and then calls the deadline
  // handler, but records no lateness sample: nothing was waited for, and
  // now - stack.now() would only measure the processing since the last
  // stack call.
  void set_pending_source(PendingSource f);

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
  Duration spin_{};  // EventLoopOptions::spin_us
  DeadlineSource deadline_source_;
  DeadlineHandler deadline_handler_;
  PendingSource pending_source_;
  bool stopped_ = false;
  int stop_signal_ = 0;
  LoopStats stats_;
};

}  // namespace utcp
