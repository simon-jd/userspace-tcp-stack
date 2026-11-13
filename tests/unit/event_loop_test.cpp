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

// One run of CallbacksAndDeadlinesFireInOrder; returns the number of deadline
// handler calls.
std::uint64_t run_callbacks_and_deadlines() {
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
  std::uint64_t calls = 0;
  std::uint64_t empty_calls = 0;
  loop.set_deadline_source([&] { return due.empty() ? Time::never() : due.front().first; });
  loop.set_deadline_handler([&](Time now) {
    ++calls;
    if (due.empty() || due.front().first > now) {
      ++empty_calls;
    } else {
      // The wait before this call aimed at the earliest pending deadline, not
      // a later one: it started at or after `start`, so its timeout is at
      // most that deadline - start.
      EXPECT_LE(loop.stats().last_timeout_ns, (due.front().first - start).count());
    }
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
  // Every handler call is a counted deadline call that handles at least one
  // due deadline.
  EXPECT_EQ(empty_calls, 0u);
  EXPECT_EQ(loop.stats().deadline_calls + loop.stats().deadline_calls_after_wake, calls);
  EXPECT_EQ(loop.stats().pending_calls, 0u);
  return calls;
}

TEST(EventLoop, CallbacksAndDeadlinesFireInOrder) {
  // The three deadline times take three handler calls when the loop wakes
  // less than 2 ms late; one wake-up 2 ms or more late (a busy host) handles
  // d2 and d4 together. So the run is repeated until one gets three calls,
  // at most 5 times; a loop that sleeps past the earliest deadline never
  // gets there.
  std::vector<std::uint64_t> calls;
  for (int attempt = 0; attempt < 5; ++attempt) {
    calls.push_back(run_callbacks_and_deadlines());
    if (::testing::Test::HasFailure() || calls.back() >= 3) {
      break;
    }
  }
  EXPECT_GE(calls.back(), 3u) << "deadline handler calls per run: " << ::testing::PrintToString(calls);
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

// A callback unwatches and closes another ready fd, and a new fd that gets
// the same number is watched in the same iteration. The old fd's event, still
// in this iteration's batch, must not reach the new fd's callback.
TEST(EventLoop, ReusedFdNumberGetsNoStaleEvent) {
  EventLoop loop(no_signals());
  int fds_a[2], fds_b[2];
  ASSERT_EQ(pipe(fds_a), 0);
  ASSERT_EQ(pipe(fds_b), 0);
  int read_end[2] = {fds_a[0], fds_b[0]};
  const int write_end[2] = {fds_a[1], fds_b[1]};
  int first = -1;  // which callback ran first
  int new_calls = 0;
  int new_r = -1, new_w = -1;
  auto make_cb = [&](int me) {
    return [&, me](std::uint32_t) {
      if (first >= 0) {
        ADD_FAILURE() << "the unwatched fd got a callback";
        return;
      }
      char ch = 0;
      ASSERT_EQ(read(read_end[me], &ch, 1), 1);
      first = me;
      const int other = read_end[1 - me];
      loop.unwatch(other);
      ASSERT_EQ(close(other), 0);
      // A new, empty pipe whose read end has the number just closed.
      int fresh[2];
      ASSERT_EQ(pipe(fresh), 0);
      if (fresh[0] != other) {
        ASSERT_EQ(dup2(fresh[0], other), other);
        ASSERT_EQ(close(fresh[0]), 0);
      }
      new_r = other;
      new_w = fresh[1];
      read_end[1 - me] = -1;
      loop.watch(new_r, EPOLLIN, [&](std::uint32_t) { ++new_calls; });
    };
  };
  loop.watch(read_end[0], EPOLLIN, make_cb(0));
  loop.watch(read_end[1], EPOLLIN, make_cb(1));
  const char c = 'x';
  ASSERT_EQ(write(write_end[0], &c, 1), 1);
  ASSERT_EQ(write(write_end[1], &c, 1), 1);
  loop.set_deadline_source([] { return mono_now() + 1ms; });
  loop.run_once();  // both pipes are ready in the same wait
  ASSERT_GE(first, 0);
  EXPECT_EQ(new_calls, 0);  // the new pipe is empty: no event for it yet
  // The new registration works: data on the new pipe reaches its callback.
  ASSERT_EQ(write(new_w, &c, 1), 1);
  loop.run_once();
  EXPECT_EQ(new_calls, 1);
  loop.unwatch(new_r);
  loop.unwatch(read_end[first]);
  close(new_r);
  close(new_w);
  close(read_end[first]);
  close(write_end[0]);
  close(write_end[1]);
}

TEST(EventLoop, LatenessHistogramBucketsAndPercentiles) {
  utcp::LatenessHistogram h;
  EXPECT_EQ(h.percentile(0.5), Duration{0});
  h.record(Duration{-5});  // early: bucket 0
  h.record(Duration{0});
  h.record(Duration{1});     // [1, 2): bucket 1
  h.record(Duration{1023});  // [512, 1024): bucket 10
  h.record(Duration{1024});  // [1024, 2048): bucket 11
  EXPECT_EQ(h.count, 5u);
  EXPECT_EQ(h.buckets[0], 2u);
  EXPECT_EQ(h.buckets[1], 1u);
  EXPECT_EQ(h.buckets[10], 1u);
  EXPECT_EQ(h.buckets[11], 1u);
  EXPECT_EQ(h.max, Duration{1024});
  EXPECT_EQ(h.percentile(0.4), Duration{0});     // rank 2: bucket 0
  EXPECT_EQ(h.percentile(0.6), Duration{1});     // rank 3: bucket 1, upper edge 1
  EXPECT_EQ(h.percentile(0.8), Duration{1023});  // rank 4: bucket 10
  EXPECT_EQ(h.percentile(1.0), Duration{1024});  // bucket 11's edge 2047, capped at max
}

TEST(EventLoop, DeadlineCallsRecordTheirLateness) {
  EventLoop loop(no_signals());
  const Time past = mono_now() - 3ms;
  loop.set_deadline_source([&] { return past; });
  loop.set_deadline_handler([](Time) {});
  loop.run_once();
  loop.run_once();
  const auto& h = loop.stats().lateness;
  EXPECT_EQ(h.count, 2u);
  EXPECT_GE(h.max, 3ms);
  EXPECT_GE(h.percentile(0.5), Duration{2'097'151});  // >= 3 ms lies in [2^21, 2^22) ns or above
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
