// The backend's event loop (DESIGN §8.2). See include/utcp/event_loop.hpp.
#include "utcp/event_loop.hpp"

#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace utcp {
namespace {

constexpr int max_events = 64;
constexpr std::int64_t ns_per_s = 1'000'000'000;

[[noreturn]] void die(const char* what) {
  std::fprintf(stderr, "EventLoop: %s: %s\n", what, std::strerror(errno));
  std::abort();
}

}  // namespace

Time mono_now() noexcept {
  timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return Time{static_cast<std::int64_t>(ts.tv_sec) * ns_per_s + ts.tv_nsec};
}

EventLoop::EventLoop() : EventLoop(EventLoopOptions{}) {}

EventLoop::EventLoop(const EventLoopOptions& options) {
  epfd_ = epoll_create1(EPOLL_CLOEXEC);
  if (epfd_ < 0) {
    die("epoll_create1");
  }
  // §8.3: 1 us slack keeps epoll_pwait2 wake-ups close to the deadline.
  if (options.timer_slack_ns != 0 &&
      prctl(PR_SET_TIMERSLACK, static_cast<unsigned long>(options.timer_slack_ns), 0UL, 0UL,
            0UL) != 0) {
    die("prctl(PR_SET_TIMERSLACK)");
  }
  if (!options.stop_signals.empty()) {
    sigset_t set;
    sigemptyset(&set);
    for (const int sig : options.stop_signals) {
      sigaddset(&set, sig);
    }
    // Blocked, so the signals stay pending until the signalfd is read.
    const int rc = pthread_sigmask(SIG_BLOCK, &set, &saved_mask_);
    if (rc != 0) {
      errno = rc;
      die("pthread_sigmask");
    }
    restore_mask_ = true;
    sigfd_ = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sigfd_ < 0) {
      die("signalfd");
    }
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = sigfd_;
    if (epoll_ctl(epfd_, EPOLL_CTL_ADD, sigfd_, &ev) != 0) {
      die("epoll_ctl(signalfd)");
    }
  }
}

EventLoop::~EventLoop() {
  if (sigfd_ >= 0) {
    close(sigfd_);
  }
  if (epfd_ >= 0) {
    close(epfd_);
  }
  if (restore_mask_) {
    pthread_sigmask(SIG_SETMASK, &saved_mask_, nullptr);
  }
}

void EventLoop::watch(int fd, std::uint32_t events, IoCallback cb) {
  if (fd < 0 || fd == sigfd_) {
    errno = EBADF;
    die("watch");
  }
  epoll_event ev{};
  ev.events = events;
  ev.data.fd = fd;
  if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) != 0) {
    die("epoll_ctl(ADD)");
  }
  const auto i = static_cast<std::size_t>(fd);
  if (callbacks_.size() <= i) {
    callbacks_.resize(i + 1);
  }
  callbacks_[i] = std::make_shared<IoCallback>(std::move(cb));
}

void EventLoop::modify(int fd, std::uint32_t events) {
  epoll_event ev{};
  ev.events = events;
  ev.data.fd = fd;
  if (epoll_ctl(epfd_, EPOLL_CTL_MOD, fd, &ev) != 0) {
    die("epoll_ctl(MOD)");
  }
}

void EventLoop::unwatch(int fd) {
  if (epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr) != 0) {
    die("epoll_ctl(DEL)");
  }
  const auto i = static_cast<std::size_t>(fd);
  if (i < callbacks_.size()) {
    callbacks_[i].reset();
  }
}

void EventLoop::set_deadline_source(DeadlineSource f) { deadline_source_ = std::move(f); }

void EventLoop::set_deadline_handler(DeadlineHandler f) { deadline_handler_ = std::move(f); }

void EventLoop::run_once() {
  ++stats_.iterations;
  const Time deadline = deadline_source_ ? deadline_source_() : Time::never();

  // §8.2: timeout = deadline - now as a timespec, zero if past, NULL if never.
  timespec ts{};
  timespec* timeout = nullptr;
  if (deadline.is_never()) {
    ++stats_.blocking_waits;
    stats_.last_timeout_ns = -1;
  } else {
    const std::int64_t left = (deadline - mono_now()).count();
    if (left <= 0) {
      ++stats_.zero_timeouts;
      stats_.last_timeout_ns = 0;
    } else {
      ts.tv_sec = static_cast<time_t>(left / ns_per_s);
      ts.tv_nsec = static_cast<long>(left % ns_per_s);
      stats_.last_timeout_ns = left;
    }
    timeout = &ts;
  }

  epoll_event events[max_events];
  int n = epoll_pwait2(epfd_, events, max_events, timeout, nullptr);
  if (n < 0) {
    if (errno != EINTR) {
      die("epoll_pwait2");
    }
    n = 0;
  }
  if (n > 0) {
    ++stats_.io_wakeups;
  }
  for (int k = 0; k < n; ++k) {
    const int fd = events[k].data.fd;
    if (fd == sigfd_) {
      signalfd_siginfo si{};
      while (read(sigfd_, &si, sizeof si) == static_cast<ssize_t>(sizeof si)) {
        stop_signal_ = static_cast<int>(si.ssi_signo);
        stopped_ = true;
      }
      continue;
    }
    const auto i = static_cast<std::size_t>(fd);
    if (i < callbacks_.size() && callbacks_[i]) {
      const std::shared_ptr<IoCallback> cb = callbacks_[i];  // survives an unwatch inside the call
      (*cb)(events[k].events);
    }
  }

  if (!deadline.is_never() && deadline_handler_) {
    const Time now = mono_now();
    if (now >= deadline) {
      ++stats_.deadline_calls;
      deadline_handler_(now);
    }
  }
}

void EventLoop::run() {
  while (!stopped_) {
    run_once();
  }
}

}  // namespace utcp
