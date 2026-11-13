// backend_lateness: wake-up lateness of the EventLoop (DESIGN §8.3; m1-backend
// test 2). Runs --count waits, each on a deadline --period-us after the
// previous wake-up, with nothing else to do, and reports how late the loop
// woke (now - deadline at the deadline handler):
//   - exact nearest-rank percentiles from all samples (min, p50, p90, p99,
//     p99.9, max, mean);
//   - the loop's log2 histogram bounds (what utcp-bulk reports);
//   - the process CPU time (getrusage) against the wall time, and with
//     --spin-us the time spent busy-polling.
// One JSON object on stdout, then the non-empty histogram buckets.
#include <sys/resource.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <print>
#include <string>
#include <vector>

#include "common/cli.hpp"
#include "utcp/event_loop.hpp"

namespace {

using utcp::Duration;
using utcp::Time;

std::int64_t cpu_ns() {
  rusage ru{};
  getrusage(RUSAGE_SELF, &ru);
  const auto tv = [](const timeval& t) {
    return static_cast<std::int64_t>(t.tv_sec) * 1'000'000'000 + std::int64_t{t.tv_usec} * 1000;
  };
  return tv(ru.ru_utime) + tv(ru.ru_stime);
}

// Nearest-rank percentile of sorted samples, q = k / 1000.
std::int64_t rank_pct(const std::vector<std::int64_t>& s, std::uint64_t k) {
  const std::uint64_t n = s.size();
  const std::uint64_t rank = std::clamp<std::uint64_t>((k * n + 999) / 1000, 1, n);
  return s[rank - 1];
}

}  // namespace

int main(int argc, char** argv) {
  utcp::app::CliParser cli("backend_lateness",
                           "Measures the EventLoop's wake-up lateness on fixed-length waits.");
  cli.option("count", "N", "number of waits", "10000")
      .option("period-us", "US", "length of each wait", "1000")
      .option("spin-us", "US", "busy-poll the last US microseconds of each wait (0: off)", "0")
      .option("label", "TEXT", "copied into the JSON output", "");
  const auto args = cli.parse(argc, argv);
  if (!args || args->help()) {
    std::println(stderr, "{}{}", args ? "" : args.error() + "\n", cli.usage());
    return args ? 0 : 2;
  }
  const auto count = utcp::app::parse_u64(*args->get("count"));
  const auto period_us = utcp::app::parse_u64(*args->get("period-us"));
  const auto spin_us = utcp::app::parse_u64(*args->get("spin-us"));
  if (!count || !period_us || !spin_us || *count == 0 || *period_us == 0 ||
      *spin_us > 1'000'000) {
    std::println(stderr, "backend_lateness: bad --count, --period-us or --spin-us");
    return 2;
  }

  utcp::EventLoopOptions opts;
  opts.spin_us = static_cast<std::uint32_t>(*spin_us);
  utcp::EventLoop loop(opts);
  const Duration period = std::chrono::microseconds{*period_us};
  std::vector<std::int64_t> samples;
  samples.reserve(*count);

  Time deadline = utcp::mono_now() + period;
  loop.set_deadline_source([&] { return deadline; });
  loop.set_deadline_handler([&](Time now) {
    samples.push_back((now - deadline).count());
    if (samples.size() >= *count) {
      loop.stop();
    }
    deadline = utcp::mono_now() + period;  // the next wait starts now
  });

  const std::int64_t cpu0 = cpu_ns();
  const Time t0 = utcp::mono_now();
  loop.run();
  const Duration wall = utcp::mono_now() - t0;
  const std::int64_t cpu = cpu_ns() - cpu0;
  if (loop.stop_signal() != 0) {
    std::println(stderr, "backend_lateness: stopped by signal {} after {} waits",
                 loop.stop_signal(), samples.size());
    return 1;
  }

  std::vector<std::int64_t> s = samples;
  std::sort(s.begin(), s.end());
  std::int64_t sum = 0;
  for (const std::int64_t v : s) {
    sum += v;
  }
  const auto& st = loop.stats();
  const auto& h = st.lateness;
  const auto hp = [&h](double q) { return h.percentile(q).count(); };
  std::println(
      "{{\"label\":\"{}\",\"waits\":{},\"period_us\":{},\"spin_us\":{},"
      "\"lateness_ns\":{{\"min\":{},\"p50\":{},\"p90\":{},\"p99\":{},\"p999\":{},\"max\":{},"
      "\"mean\":{}}},"
      "\"hist_upper_ns\":{{\"p50\":{},\"p90\":{},\"p99\":{},\"p999\":{},\"max\":{}}},"
      "\"wall_ns\":{},\"cpu_ns\":{},\"cpu_share_permille\":{},"
      "\"iterations\":{},\"deadline_calls\":{},\"zero_timeouts\":{},"
      "\"spin_waits\":{},\"spin_polls\":{},\"spin_ns\":{},\"spin_lead_max_ns\":{}}}",
      *args->get("label"), s.size(), *period_us, *spin_us, s.front(), rank_pct(s, 500),
      rank_pct(s, 900), rank_pct(s, 990), rank_pct(s, 999), s.back(),
      sum / static_cast<std::int64_t>(s.size()), hp(0.5), hp(0.9), hp(0.99), hp(0.999),
      h.max.count(), wall.count(), cpu, wall.count() > 0 ? cpu * 1000 / wall.count() : 0,
      st.iterations, st.deadline_calls, st.zero_timeouts, st.spin_waits, st.spin_polls,
      st.spin_time.count(), st.spin_lead_max.count());
  for (std::size_t i = 0; i < h.buckets.size(); ++i) {
    if (h.buckets[i] != 0) {
      const std::uint64_t lo = i == 0 ? 0 : std::uint64_t{1} << (i - 1);
      const std::uint64_t hi = i == 0 ? 0 : (std::uint64_t{1} << i) - 1;
      std::println("bucket {:2} [{}, {}] ns: {}", i, lo, hi, h.buckets[i]);
    }
  }
  return 0;
}
