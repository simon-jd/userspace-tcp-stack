#include "utcp/event_loop.hpp"

#include <gtest/gtest.h>

#include <signal.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::EventLoop;
using utcp::EventLoopOptions;
using utcp::mono_now;
using utcp::Time;

struct Pipe {
  int r = -1, w = -1;
  Pipe() {
    int fds[2];
    EXPECT_EQ(pipe(fds), 0);
    r = fds[0];
    w = fds[1];
  }
  ~Pipe() {
    close(r);
    close(w);
  }
  void put(char c = 'x') const { EXPECT_EQ(write(w, &c, 1), 1); }
  char take() const {
    char c = 0;
    EXPECT_EQ(read(r, &c, 1), 1);
    return c;
  }
};

EventLoopOptions no_signals() {
  EventLoopOptions o;
  o.stop_signals.clear();
  return o;
}

bool blocked(int sig) {
  sigset_t cur;
  pthread_sigmask(SIG_BLOCK, nullptr, &cur);
  return sigismember(&cur, sig) == 1;
}

TEST(EventLoop, MonoNowIsMonotonic) {
  Time prev = mono_now();
  for (int i = 0; i < 1000; ++i) {
    const Time t = mono_now();
    EXPECT_GE(t, prev);
    prev = t;
  }
  EXPECT_GT(prev.ns, 0);
}

TEST(EventLoop, PipeCallbackGetsTheEvents) {
  EventLoop loop(no_signals());
  Pipe p;
  std::vector<std::uint32_t> got;
  loop.watch(p.r, EPOLLIN, [&](std::uint32_t ev) {
    got.push_back(ev);
    p.take();
  });
  p.put();
  loop.run_once();  // no deadline source: a blocking wait that the pipe ends
  ASSERT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0], static_cast<std::uint32_t>(EPOLLIN));
  EXPECT_EQ(loop.stats().iterations, 1u);
  EXPECT_EQ(loop.stats().io_wakeups, 1u);
  EXPECT_EQ(loop.stats().blocking_waits, 1u);
  EXPECT_EQ(loop.stats().last_timeout_ns, -1);
  EXPECT_EQ(loop.stats().deadline_calls, 0u);
}

TEST(EventLoop, CallbacksAndDeadlinesFireInOrder) {
  EventLoop loop(no_signals());
  Pipe p;
  std::vector<std::string> log;
  loop.watch(p.r, EPOLLIN, [&](std::uint32_t) {
    p.take();
    log.push_back("pipe");
  });
  const Time start = mono_now();
  // Deadlines 2, 4, 4 (equal) and 6 ms ahead, each with a name.
  std::deque<std::pair<Time, std::string>> due{{start + 2ms, "d2"},
                                               {start + 4ms, "d4a"},
                                               {start + 4ms, "d4b"},
                                               {start + 6ms, "d6"}};
  std::vector<Duration> late;
  loop.set_deadline_source([&] { return due.empty() ? Time::never() : due.front().first; });
  loop.set_deadline_handler([&](Time now) {
    while (!due.empty() && due.front().first <= now) {
      late.push_back(now - due.front().first);
      log.push_back(due.front().second);
      due.pop_front();
    }
    if (due.empty()) {
      loop.stop();
    }
  });
  p.put();  // ready before the first wait, so it comes first
  loop.run();
  EXPECT_TRUE(loop.stopped());
  EXPECT_EQ(loop.stop_signal(), 0);
  // The equal deadlines may be handled in one call; the order holds either way.
  EXPECT_EQ(log, (std::vector<std::string>{"pipe", "d2", "d4a", "d4b", "d6"}));
  for (const Duration d : late) {
    EXPECT_GE(d.count(), 0);  // never called before its deadline
  }
  EXPECT_GE(mono_now() - start, 6ms);
  EXPECT_GE(loop.stats().deadline_calls, 3u);
}

TEST(EventLoop, FutureDeadlineGivesItsTimeout) {
  EventLoop loop(no_signals());
  const Time deadline = mono_now() + 5ms;
  Time fired;
  loop.set_deadline_source([&] { return deadline; });
  loop.set_deadline_handler([&](Time now) { fired = now; });
  loop.run_once();
  EXPECT_GT(loop.stats().last_timeout_ns, 0);
  EXPECT_LE(loop.stats().last_timeout_ns, 5'000'000);
  EXPECT_EQ(loop.stats().zero_timeouts, 0u);
  EXPECT_EQ(loop.stats().deadline_calls, 1u);
  EXPECT_GE(fired, deadline);
}

TEST(EventLoop, PastDeadlineGivesZeroTimeout) {
  EventLoop loop(no_signals());
  const Time past = mono_now() - 1ms;
  int calls = 0;
  loop.set_deadline_source([&] { return past; });
  loop.set_deadline_handler([&](Time now) {
    EXPECT_GE(now, past);
    ++calls;
  });
  const Time before = mono_now();
  loop.run_once();
  EXPECT_LT(mono_now() - before, 100ms);  // did not wait
  EXPECT_EQ(loop.stats().last_timeout_ns, 0);
  EXPECT_EQ(loop.stats().zero_timeouts, 1u);
  EXPECT_EQ(calls, 1);
  // A deadline equal to "now" counts as past as well.
  loop.set_deadline_source([] { return mono_now(); });
  loop.run_once();
  EXPECT_EQ(loop.stats().last_timeout_ns, 0);
  EXPECT_EQ(calls, 2);
}

TEST(EventLoop, NeverMeansBlockingWait) {
  EventLoop loop(no_signals());
  Pipe p;
  int calls = 0;
  bool woke = false;
  loop.set_deadline_source([] { return Time::never(); });
  loop.set_deadline_handler([&](Time) { ++calls; });
  loop.watch(p.r, EPOLLIN, [&](std::uint32_t) {
    p.take();
    woke = true;
  });
  const Time before = mono_now();
  std::thread writer([&] {
    std::this_thread::sleep_for(50ms);
    p.put();
  });
  loop.run_once();
  writer.join();
  EXPECT_TRUE(woke);
  EXPECT_GE(mono_now() - before, 45ms);  // blocked until the write
  EXPECT_EQ(loop.stats().blocking_waits, 1u);
  EXPECT_EQ(loop.stats().last_timeout_ns, -1);
  EXPECT_EQ(calls, 0);  // never is not a deadline
}

TEST(EventLoop, SignalEndsRun) {
  EventLoopOptions o;
  o.stop_signals = {SIGUSR1, SIGUSR2};
  ASSERT_FALSE(blocked(SIGUSR1));
  {
    EventLoop loop(o);
    EXPECT_TRUE(blocked(SIGUSR1));
    EXPECT_TRUE(blocked(SIGUSR2));
    // Created after the loop, so the thread inherits the blocked mask; the
    // process-directed signal stays pending until the signalfd reads it.
    std::thread sender([] {
      std::this_thread::sleep_for(20ms);
      kill(getpid(), SIGUSR2);
    });
    loop.run();  // no deadline: blocks until the signal
    sender.join();
    EXPECT_TRUE(loop.stopped());
    EXPECT_EQ(loop.stop_signal(), SIGUSR2);
    loop.run();  // already stopped: returns at once
  }
  EXPECT_FALSE(blocked(SIGUSR1));  // the destructor restored the mask
  EXPECT_FALSE(blocked(SIGUSR2));
}

TEST(EventLoop, DefaultsBlockIntAndTermAndSetTheSlack) {
  ASSERT_FALSE(blocked(SIGTERM));
  {
    EventLoop loop;
    EXPECT_TRUE(blocked(SIGINT));
    EXPECT_TRUE(blocked(SIGTERM));
    EXPECT_EQ(prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0), 1000);
  }
  EXPECT_FALSE(blocked(SIGTERM));
}

TEST(EventLoop, CallbackMayUnwatchAndStop) {
  EventLoop loop(no_signals());
  Pipe a, b;
  int a_calls = 0, b_calls = 0;
  loop.watch(a.r, EPOLLIN, [&](std::uint32_t) {
    ++a_calls;
    loop.unwatch(a.r);  // its own fd, while running
    loop.unwatch(b.r);  // and another one that is ready too
    loop.stop();
  });
  loop.watch(b.r, EPOLLIN, [&](std::uint32_t) { ++b_calls; });
  a.put();
  b.put();
  loop.run();
  // Depending on epoll's order, b ran first or not at all.
  EXPECT_EQ(a_calls, 1);
  EXPECT_LE(b_calls, 1);
  EXPECT_TRUE(loop.stopped());
}

TEST(EventLoop, ModifyChangesTheEvents) {
  EventLoop loop(no_signals());
  Pipe p;
  std::vector<std::uint32_t> got;
  loop.watch(p.w, 0, [&](std::uint32_t ev) { got.push_back(ev); });
  loop.set_deadline_source([] { return mono_now() + 1ms; });
  loop.run_once();  // not interested in anything yet: times out
  EXPECT_TRUE(got.empty());
  loop.modify(p.w, EPOLLOUT);
  loop.run_once();  // an empty pipe is writable
  ASSERT_EQ(got.size(), 1u);
  EXPECT_NE(got[0] & EPOLLOUT, 0u);
}

}  // namespace
