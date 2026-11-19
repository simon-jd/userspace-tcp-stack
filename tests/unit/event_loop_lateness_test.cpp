// Wake-up lateness histogram and --spin-us (DESIGN §8.3; m1-backend test 1).
#include <gtest/gtest.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstdint>
#include <limits>
#include <random>
#include <thread>
#include <vector>

#include "utcp/event_loop.hpp"

namespace {
using namespace std::chrono_literals;

struct ScheduledWake {
  explicit ScheduledWake(utcp::Duration first) : sleep_elapsed(first) {}
  utcp::Time now{1'000'000'000};
  utcp::Duration sleep_elapsed;
  std::vector<utcp::Duration> waits;
};
thread_local ScheduledWake* schedule = nullptr;
}  // namespace

// Scope the substituted clock to one test thread. Even a controlled wait
// polls the real epoll fd for readiness; only the time spent blocked is scripted.
extern "C" int __real_clock_gettime(clockid_t, timespec*);
extern "C" int __wrap_clock_gettime(clockid_t clock, timespec* out) {
  if (!schedule || clock != CLOCK_MONOTONIC) return __real_clock_gettime(clock, out);
  out->tv_sec = schedule->now.ns / 1'000'000'000;
  out->tv_nsec = schedule->now.ns % 1'000'000'000;
  return 0;
}
extern "C" int __real_epoll_pwait2(int, epoll_event*, int, const timespec*, const sigset_t*);
extern "C" int __wrap_epoll_pwait2(int fd, epoll_event* events, int count, const timespec* timeout,
                                   const sigset_t* mask) {
  if (!schedule || !timeout) return __real_epoll_pwait2(fd, events, count, timeout, mask);
  const utcp::Duration requested{timeout->tv_sec * 1'000'000'000 + timeout->tv_nsec};
  schedule->waits.push_back(requested);
  schedule->now += requested == utcp::Duration::zero() ? 1ms : schedule->sleep_elapsed;
  const timespec zero{};
  return __real_epoll_pwait2(fd, events, count, &zero, mask);
}

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::EventLoop;
using utcp::EventLoopOptions;
using utcp::LatenessHistogram;
using utcp::mono_now;
using utcp::Time;

// Inclusive upper edge of the bucket that holds v >= 0 (the histogram's
// documented rule, written out independently).
std::int64_t upper_edge(std::int64_t v) {
  if (v <= 0) {
    return 0;
  }
  const int i = std::bit_width(static_cast<std::uint64_t>(v));  // v in [2^(i-1), 2^i)
  return i == 63 ? std::numeric_limits<std::int64_t>::max()
                 : static_cast<std::int64_t>((std::uint64_t{1} << i) - 1);
}

// The q-quantile bound for q = k / 1000 from a sorted reference: the sample
// of rank ceil(k * n / 1000) (at least 1), its bucket's upper edge, at most
// the maximum.
std::int64_t expected_percentile(const std::vector<std::int64_t>& sorted, std::uint64_t k) {
  const std::uint64_t n = sorted.size();
  const std::uint64_t rank = std::clamp<std::uint64_t>((k * n + 999) / 1000, 1, n);
  return std::min(upper_edge(sorted[rank - 1]), sorted.back());
}

EventLoopOptions spin_options(std::uint32_t spin_us) {
  EventLoopOptions o;
  o.stop_signals.clear();
  o.spin_us = spin_us;
  return o;
}

Duration thread_cpu_time() {
  timespec ts{};
  clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
  return Duration{static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec};
}

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
};

TEST(EventLoopLateness, BucketBoundaries) {
  // Bucket 0: zero and early wake-ups.
  {
    LatenessHistogram h;
    h.record(Duration{0});
    h.record(Duration{-1});
    h.record(Duration{std::numeric_limits<std::int64_t>::min()});
    EXPECT_EQ(h.buckets[0], 3u);
    EXPECT_EQ(h.count, 3u);
    EXPECT_EQ(h.max, Duration{0});
    EXPECT_EQ(h.percentile(1.0), Duration{0});
  }
  // Bucket i holds [2^(i-1), 2^i): both edges land in it, 2^i in the next.
  for (std::size_t i = 1; i < LatenessHistogram::bucket_count; ++i) {
    SCOPED_TRACE(i);
    const auto lo = static_cast<std::int64_t>(std::uint64_t{1} << (i - 1));
    const std::int64_t hi = i == 63 ? std::numeric_limits<std::int64_t>::max()
                                    : static_cast<std::int64_t>((std::uint64_t{1} << i) - 1);
    LatenessHistogram h;
    h.record(Duration{lo});
    h.record(Duration{hi});
    EXPECT_EQ(h.buckets[i], 2u);
    EXPECT_EQ(h.count, 2u);
    EXPECT_EQ(h.max, Duration{hi});
    EXPECT_EQ(h.percentile(0.5), Duration{hi});  // rank 1 = lo, edge hi
    if (i + 1 < LatenessHistogram::bucket_count) {
      h.record(Duration{hi + 1});
      EXPECT_EQ(h.buckets[i + 1], 1u);
      EXPECT_EQ(h.buckets[i], 2u);
    }
    std::uint64_t total = 0;
    for (const std::uint64_t b : h.buckets) {
      total += b;
    }
    EXPECT_EQ(total, h.count);
  }
}

TEST(EventLoopLateness, PercentilesMatchSortedReference) {
  std::mt19937_64 gen(20261112);
  for (const std::size_t n : {1u, 2u, 3u, 10u, 100u, 999u, 1000u, 10007u}) {
    SCOPED_TRACE(n);
    std::vector<std::int64_t> samples;
    LatenessHistogram h;
    for (std::size_t j = 0; j < n; ++j) {
      // Log-uniform over 1 ns .. 2^40 ns, plus zeros and repeated values.
      std::int64_t v = 0;
      switch (gen() % 8) {
        case 0: v = 0; break;
        case 1: v = 1000; break;
        default: {
          const unsigned e = static_cast<unsigned>(gen() % 41);
          v = static_cast<std::int64_t>((std::uint64_t{1} << e) | (gen() & ((std::uint64_t{1} << e) - 1)));
        }
      }
      samples.push_back(v);
      h.record(Duration{v});
    }
    std::sort(samples.begin(), samples.end());
    ASSERT_EQ(h.count, n);
    ASSERT_EQ(h.max, Duration{samples.back()});
    for (std::uint64_t k = 0; k <= 1000; ++k) {
      const std::int64_t want = expected_percentile(samples, k);
      const Duration got = h.percentile(static_cast<double>(k) / 1000.0);
      ASSERT_EQ(got, Duration{want}) << "q = " << k << "/1000";
      // An upper bound within a factor of 2 of the reference sample.
      const std::uint64_t rank = std::clamp<std::uint64_t>((k * n + 999) / 1000, 1, n);
      const std::int64_t ref = samples[rank - 1];
      EXPECT_GE(got.count(), ref);
      EXPECT_LE(got.count(), ref == 0 ? 0 : 2 * ref - 1);
    }
    // The quantiles reported by utcp-bulk.
    for (const double q : {0.5, 0.9, 0.99, 0.999}) {
      const auto k = static_cast<std::uint64_t>(q * 1000 + 0.5);
      EXPECT_EQ(h.percentile(q), Duration{expected_percentile(samples, k)}) << q;
    }
  }
}

// 0.07 * 100 is 7.000000000000001 in binary floating point; the rank is 7.
TEST(EventLoopLateness, RankIsNotRoundedUpPastAnExactProduct) {
  LatenessHistogram h;
  for (int v = 1; v <= 100; ++v) {
    h.record(Duration{v});
  }
  EXPECT_EQ(h.percentile(0.07), Duration{7});   // rank 7 = 7 ns, bucket [4, 8)
  EXPECT_EQ(h.percentile(0.08), Duration{15});  // rank 8 = 8 ns, bucket [8, 16)
  EXPECT_EQ(h.percentile(0.29), Duration{31});  // rank 29, bucket [16, 32)
  EXPECT_EQ(h.percentile(0.57), Duration{63});  // 0.57 * 100 = 56.99999999999999: rank 57
  EXPECT_EQ(h.percentile(1.0), Duration{100});  // bucket [64, 128), capped at max
}

TEST(EventLoopLateness, NoSpinByDefault) {
  EventLoop loop(spin_options(0));
  const Time deadline = mono_now() + 3ms;
  int calls = 0;
  loop.set_deadline_source([&] { return deadline; });
  loop.set_deadline_handler([&](Time) { ++calls; });
  loop.run_once();
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(loop.stats().spin_waits, 0u);
  EXPECT_EQ(loop.stats().spin_polls, 0u);
  EXPECT_EQ(loop.stats().spin_time, Duration{0});
  EXPECT_GT(loop.stats().last_timeout_ns, 0);
}

// Drive the actual run_once wait, readiness, spin and dispatch paths. A
// 37 ms sleep can end on time, after the deadline or early (e.g. EINTR).
TEST(EventLoopLateness, SpinsOnlyInTheLastMicroseconds) {
  for (const Duration elapsed : {37ms, 43ms, 34ms}) {
    SCOPED_TRACE(elapsed.count());
    ScheduledWake clock(elapsed);
    EventLoop loop(spin_options(3000));
    const Time deadline = clock.now + 40ms;
    int calls = 0;
    loop.set_deadline_source([&] { return deadline; });
    loop.set_deadline_handler([&](Time now) {
      ++calls;
      EXPECT_EQ(now, clock.now);
      EXPECT_GE(now, deadline);
    });
    schedule = &clock;
    loop.run_once();
    schedule = nullptr;
    const auto& st = loop.stats();
    const bool timely = elapsed == 37ms;
    const bool early = elapsed < 37ms;
    const std::vector<Duration> expected = timely ? std::vector<Duration>{37ms, 0ms, 0ms, 0ms}
                                                  : std::vector<Duration>{37ms};
    EXPECT_EQ(clock.waits, expected);
    EXPECT_EQ(st.last_timeout_ns, Duration{37ms}.count());
    EXPECT_EQ(st.spin_polls, timely ? 3u : 0u);
    EXPECT_EQ(st.spin_waits, timely ? 1u : 0u);
    EXPECT_EQ(st.spin_lead_max, timely ? 3ms : 0ms);
    EXPECT_EQ(st.spin_time, timely ? 3ms : 0ms);
    EXPECT_EQ(st.lateness.count, early ? 0u : 1u);
    EXPECT_EQ(st.lateness.max, elapsed > 40ms ? elapsed - 40ms : 0ms);
    EXPECT_EQ(calls, early ? 0 : 1);
  }
}

// Exercise the real blocking syscall, clock and CPU cost under host scheduling.
TEST(EventLoopLateness, RealWaitSleepsBeforeTheSpinWindow) {
  constexpr std::uint32_t spin_us = 3000;
  EventLoop loop(spin_options(spin_us));
  const Time before = mono_now();
  const Time deadline = before + 40ms;
  Time fired;
  int calls = 0;
  loop.set_deadline_source([&] { return deadline; });
  loop.set_deadline_handler([&](Time now) {
    fired = now;
    ++calls;
  });
  const Duration cpu0 = thread_cpu_time();
  loop.run_once();
  const Duration cpu = thread_cpu_time() - cpu0;
  const auto& st = loop.stats();
  ASSERT_EQ(calls, 1);
  EXPECT_GE(fired, deadline);
  EXPECT_EQ(st.lateness.count, 1u);
  // The sleep before the spin.
  EXPECT_GE(st.last_timeout_ns, 0);
  EXPECT_LE(st.last_timeout_ns, Duration{40ms - std::chrono::microseconds{spin_us}}.count());
  EXPECT_LE(st.spin_waits, 1u);
  EXPECT_EQ(st.spin_waits == 1, st.spin_polls > 0);
  EXPECT_EQ(st.spin_waits == 1, st.spin_lead_max > Duration{0});
  EXPECT_LE(st.spin_lead_max, std::chrono::microseconds{spin_us});
  EXPECT_GE(st.spin_time, st.spin_lead_max);  // spun from its start up to the deadline
  EXPECT_LT(cpu, 20ms) << "spun for most of the wait";
}

// A deadline already inside the window: no sleep, the spin starts at once.
TEST(EventLoopLateness, DeadlineInsideTheWindowSpinsAtOnce) {
  EventLoop loop(spin_options(20'000));
  const Time deadline = mono_now() + 5ms;
  int calls = 0;
  loop.set_deadline_source([&] { return deadline; });
  loop.set_deadline_handler([&](Time now) {
    EXPECT_GE(now, deadline);
    ++calls;
  });
  loop.run_once();
  const auto& st = loop.stats();
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(st.last_timeout_ns, 0);
  EXPECT_EQ(st.spin_waits, 1u);
  EXPECT_GT(st.spin_polls, 1u);
  EXPECT_LE(st.spin_lead_max, 5ms);
  EXPECT_GE(st.spin_time, st.spin_lead_max);
}

// A ready fd ends the spin before the deadline; the deadline handler does
// not run (the deadline has not passed).
TEST(EventLoopLateness, ReadyFdEndsTheSpin) {
  EventLoop loop(spin_options(200'000));
  Pipe p;
  int io = 0, calls = 0;
  loop.watch(p.r, EPOLLIN, [&](std::uint32_t) {
    char c = 0;
    EXPECT_EQ(read(p.r, &c, 1), 1);
    ++io;
  });
  const Time deadline = mono_now() + 150ms;
  loop.set_deadline_source([&] { return deadline; });
  loop.set_deadline_handler([&](Time) { ++calls; });
  std::thread writer([&] {
    std::this_thread::sleep_for(10ms);
    const char c = 'x';
    EXPECT_EQ(write(p.w, &c, 1), 1);
  });
  loop.run_once();
  writer.join();
  const auto& st = loop.stats();
  EXPECT_EQ(io, 1);
  if (mono_now() < deadline) {  // unless this thread was descheduled for 140 ms
    EXPECT_EQ(calls, 0);
  }
  EXPECT_EQ(st.io_wakeups, 1u);
  EXPECT_EQ(st.spin_waits, 1u);
  EXPECT_LT(st.spin_time, 150ms);
}

// No deadline: a blocking wait, never a spin.
TEST(EventLoopLateness, NoDeadlineNoSpin) {
  EventLoop loop(spin_options(1000));
  Pipe p;
  int io = 0;
  loop.watch(p.r, EPOLLIN, [&](std::uint32_t) {
    char c = 0;
    EXPECT_EQ(read(p.r, &c, 1), 1);
    ++io;
  });
  const char c = 'x';
  ASSERT_EQ(write(p.w, &c, 1), 1);
  loop.run_once();
  EXPECT_EQ(io, 1);
  EXPECT_EQ(loop.stats().blocking_waits, 1u);
  EXPECT_EQ(loop.stats().spin_waits, 0u);
  EXPECT_EQ(loop.stats().spin_polls, 0u);
}

// A past deadline: a zero-timeout wait, the handler runs, no spin.
TEST(EventLoopLateness, PastDeadlineDoesNotSpin) {
  EventLoop loop(spin_options(1000));
  const Time past = mono_now() - 1ms;
  int calls = 0;
  loop.set_deadline_source([&] { return past; });
  loop.set_deadline_handler([&](Time) { ++calls; });
  loop.run_once();
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(loop.stats().zero_timeouts, 1u);
  EXPECT_EQ(loop.stats().spin_waits, 0u);
  EXPECT_GE(loop.stats().lateness.max, 1ms);
}

// Pending work (UtcpTransport: blocked connections can resume, which
// Stack::next_deadline() reports as the stack's now()): a zero-timeout wait
// and a deadline handler call, but no lateness sample, as nothing was waited
// for. Without pending work the same loop waits for its deadline again.
TEST(EventLoopLateness, PendingWorkAddsNoLatenessSample) {
  EventLoop loop(spin_options(0));
  Time deadline = mono_now() + 2s;
  bool pending = true;
  int calls = 0;
  loop.set_deadline_source([&] { return deadline; });
  loop.set_pending_source([&] { return pending; });
  loop.set_deadline_handler([&](Time) { ++calls; });
  const Time t0 = mono_now();
  loop.run_once();
  EXPECT_LT(mono_now() - t0, 1s) << "waited for the deadline";
  EXPECT_EQ(calls, 1);
  const auto& st = loop.stats();
  EXPECT_EQ(st.pending_polls, 1u);
  EXPECT_EQ(st.pending_calls, 1u);
  EXPECT_EQ(st.last_timeout_ns, 0);
  EXPECT_EQ(st.deadline_calls, 0u);
  EXPECT_EQ(st.zero_timeouts, 0u);
  EXPECT_EQ(st.lateness.count, 0u);

  pending = false;
  deadline = mono_now() + 3ms;
  loop.run_once();
  EXPECT_EQ(calls, 2);
  EXPECT_GT(st.last_timeout_ns, 0);
  EXPECT_EQ(st.pending_polls, 1u);
  EXPECT_EQ(st.pending_calls, 1u);
  EXPECT_EQ(st.deadline_calls, 1u);
  EXPECT_EQ(st.lateness.count, 1u);
}

// Pending work and a deadline that has passed: one handler call, and the
// deadline's lateness is recorded.
TEST(EventLoopLateness, PendingWorkAndAPastDeadline) {
  EventLoop loop(spin_options(0));
  const Time past = mono_now() - 1ms;
  int calls = 0;
  loop.set_deadline_source([&] { return past; });
  loop.set_pending_source([] { return true; });
  loop.set_deadline_handler([&](Time) { ++calls; });
  loop.run_once();
  const auto& st = loop.stats();
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(st.zero_timeouts, 1u);
  EXPECT_EQ(st.deadline_calls, 1u);
  EXPECT_EQ(st.pending_polls, 0u);
  EXPECT_EQ(st.pending_calls, 0u);
  EXPECT_EQ(st.lateness.count, 1u);
  EXPECT_GE(st.lateness.max, 1ms);
}

// Pending work does not spin, even with the deadline inside the window.
TEST(EventLoopLateness, PendingWorkDoesNotSpin) {
  EventLoop loop(spin_options(20'000));
  const Time deadline = mono_now() + 5ms;
  int calls = 0;
  loop.set_deadline_source([&] { return deadline; });
  loop.set_pending_source([] { return true; });
  loop.set_deadline_handler([&](Time) { ++calls; });
  loop.run_once();
  const auto& st = loop.stats();
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(st.spin_waits, 0u);
  EXPECT_EQ(st.spin_polls, 0u);
  EXPECT_EQ(st.pending_polls, 1u);
  // The deadline has passed by the handler call only if this thread was
  // descheduled for 5 ms.
  EXPECT_EQ(st.pending_calls + st.deadline_calls + st.deadline_calls_after_wake, 1u);
}

// Lateness is taken at the wake-up (§8.3), not after the fd callbacks: a
// ready fd wakes the loop 5 ms before its deadline and its callback runs for
// 8 ms. The deadline has passed by the end of the iteration, so the handler
// runs (with the later time), but the loop was not late: no sample.
TEST(EventLoopLateness, DeadlinePassedInACallbackAddsNoSample) {
  EventLoop loop(spin_options(0));
  Pipe p;
  const char c = 'x';
  ASSERT_EQ(write(p.w, &c, 1), 1);
  const Time deadline = mono_now() + 5ms;
  int io = 0, calls = 0;
  Time fired;
  loop.watch(p.r, EPOLLIN, [&](std::uint32_t) {
    char b = 0;
    EXPECT_EQ(read(p.r, &b, 1), 1);
    ++io;
    std::this_thread::sleep_for(8ms);
  });
  loop.set_deadline_source([&] { return deadline; });
  loop.set_deadline_handler([&](Time now) {
    fired = now;
    ++calls;
  });
  loop.run_once();
  const auto& st = loop.stats();
  ASSERT_EQ(io, 1);
  EXPECT_EQ(calls, 1);
  EXPECT_GE(fired, deadline);
  EXPECT_EQ(st.io_wakeups, 1u);
  EXPECT_EQ(st.deadline_calls_after_wake, 1u);
  EXPECT_EQ(st.deadline_calls, 0u);
  EXPECT_EQ(st.lateness.count, 0u) << "max " << st.lateness.max.count() << " ns";
}

// A deadline that had passed at the wake-up: the sample is woke - deadline,
// without the time the fd callback took afterwards.
TEST(EventLoopLateness, LatenessExcludesCallbackTime) {
  EventLoop loop(spin_options(0));
  Pipe p;
  const char c = 'x';
  ASSERT_EQ(write(p.w, &c, 1), 1);
  const Time deadline = mono_now() - 1ms;
  Time callback_start;
  int calls = 0;
  loop.watch(p.r, EPOLLIN, [&](std::uint32_t) {
    callback_start = mono_now();
    char b = 0;
    EXPECT_EQ(read(p.r, &b, 1), 1);
    std::this_thread::sleep_for(20ms);
  });
  loop.set_deadline_source([&] { return deadline; });
  loop.set_deadline_handler([&](Time) { ++calls; });
  loop.run_once();
  const auto& st = loop.stats();
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(st.deadline_calls, 1u);
  EXPECT_EQ(st.deadline_calls_after_wake, 0u);
  ASSERT_EQ(st.lateness.count, 1u);
  EXPECT_GE(st.lateness.max, 1ms);
  EXPECT_LE(st.lateness.max, callback_start - deadline);  // taken before the callback ran
}

}  // namespace
