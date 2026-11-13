// utcp-sim: runs simulator scenarios (DESIGN §7.2, §7.4).
//
//   utcp-sim --seed N | --seed-range A:B | --scenario FILE | --corpus DIR
//            [--nodes stack|synthetic] [--jsonl FILE] [--pcap DIR] [--trace FILE]
//            [--dump-scenario] [--plant-fail LIST] [--plant-abort LIST]
//            [--plant-hang LIST] [--plant-segv LIST] [--plant-after N]
//            [--test-fault NAME]
//
// One JSON line per run (seed, verdict, digest, ...), flushed after each run.
// A handler for SIGABRT, SIGSEGV, SIGBUS, SIGFPE and SIGILL prints the
// running seed's rolling digest and event count to stderr, so crashing seeds
// can be compared too (DESIGN §7.2):
//   utcp-sim: crash {"seed":S,"signal":N,"events":E,"digest":"D"}
// then the signal kills the process as before. In ASan builds only SIGABRT
// is caught, so ASan still reports the other signals itself. Exit status: 0
// if every run passed, 1 if any failed, 2 for usage errors.
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

#include "common/cli.hpp"
#include "common/jsonl.hpp"
#include "utcp/sim/results.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/sim/world.hpp"

namespace {

using namespace utcp;
using namespace utcp::sim;

std::atomic<const World*> g_world{nullptr};
std::atomic<std::uint64_t> g_seed{0};

// Async-signal-safe decimal formatting.
std::size_t put_u64(char* out, std::uint64_t v) {
  char tmp[20];
  std::size_t n = 0;
  do {
    tmp[n++] = static_cast<char>('0' + v % 10);
    v /= 10;
  } while (v != 0);
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = tmp[n - 1 - i];
  }
  return n;
}

std::size_t put_str(char* out, std::string_view s) {
  for (std::size_t i = 0; i < s.size(); ++i) {
    out[i] = s[i];
  }
  return s.size();
}

// Async-signal-safe: atomics, arithmetic and write(2) only. SA_RESETHAND
// has restored the default action, so the re-raised signal ends the process.
extern "C" void on_fatal_signal(int sig) {
  char line[192];
  std::size_t n = 0;
  n += put_str(line + n, "utcp-sim: crash {\"seed\":");
  n += put_u64(line + n, g_seed.load());
  n += put_str(line + n, ",\"signal\":");
  n += put_u64(line + n, static_cast<std::uint64_t>(sig));
  const World* w = g_world.load();
  if (w != nullptr) {
    n += put_str(line + n, ",\"events\":");
    n += put_u64(line + n, w->events());
    n += put_str(line + n, ",\"digest\":\"");
    const auto h = RunDigest::hex(w->digest_now());
    n += put_str(line + n, std::string_view(h.data(), h.size()));
    n += put_str(line + n, "\"");
  }
  n += put_str(line + n, "}\n");
  [[maybe_unused]] const auto r = ::write(2, line, n);
  std::raise(sig);
}

#if defined(__SANITIZE_ADDRESS__)
constexpr bool asan_build = true;
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
constexpr bool asan_build = true;
#else
constexpr bool asan_build = false;
#endif
#else
constexpr bool asan_build = false;
#endif

// The handler runs on its own stack, so a stack overflow is reported too.
void install_crash_handlers() {
  static std::array<char, 64 * 1024> alt_stack{};
  stack_t ss{};
  ss.ss_sp = alt_stack.data();
  ss.ss_size = alt_stack.size();
  ::sigaltstack(&ss, nullptr);
  struct sigaction sa {};
  sa.sa_handler = on_fatal_signal;
  ::sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_ONSTACK | SA_RESETHAND;
  ::sigaction(SIGABRT, &sa, nullptr);
  if (!asan_build) {
    for (const int sig : {SIGSEGV, SIGBUS, SIGFPE, SIGILL}) {
      ::sigaction(sig, &sa, nullptr);
    }
  }
}

std::expected<std::set<std::uint64_t>, std::string> parse_list(const std::optional<std::string>& s) {
  std::set<std::uint64_t> out;
  if (!s) {
    return out;
  }
  std::string_view rest = *s;
  while (!rest.empty()) {
    const auto comma = rest.find(',');
    const auto word = rest.substr(0, comma);
    auto v = app::parse_u64(word);
    if (!v) {
      return std::unexpected(v.error());
    }
    out.insert(*v);
    if (comma == std::string_view::npos) {
      break;
    }
    rest.remove_prefix(comma + 1);
  }
  return out;
}

struct Options {
  NodeKind nodes = NodeKind::stack;
  std::set<std::uint64_t> plant_fail, plant_abort, plant_hang, plant_segv;
  std::optional<std::uint64_t> plant_after;
  std::optional<TestFault> test_fault;
  std::string pcap_dir;
  std::string trace_path;
  std::uint64_t snaplen = 65535;
  std::optional<std::uint64_t> max_events;
};

void apply(const Options& o, Scenario& s) {
  if (o.plant_fail.contains(s.seed)) {
    s.plant = Plant::fail;
  } else if (o.plant_abort.contains(s.seed)) {
    s.plant = Plant::abort;
  } else if (o.plant_hang.contains(s.seed)) {
    s.plant = Plant::hang;
  } else if (o.plant_segv.contains(s.seed)) {
    s.plant = Plant::segv;
  }
  if (o.plant_after) {
    s.plant_after_events = *o.plant_after;
  }
  if (o.test_fault) {
    for (NodeSpec& n : s.node) {
      n.test_fault = *o.test_fault;
    }
  }
}

// Runs one scenario; false if it failed.
bool run_one(const Scenario& s, const Options& o, app::JsonlWriter& out) {
  WorldOptions wo;
  if (o.max_events) {
    wo.max_events = *o.max_events;
  }
  wo.snaplen = static_cast<std::uint32_t>(o.snaplen);
  if (!o.pcap_dir.empty()) {
    const std::string dir = o.pcap_dir + "/seed-" + std::to_string(s.seed);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
      std::fprintf(stderr, "utcp-sim: %s: %s\n", dir.c_str(), ec.message().c_str());
    }
    write_scenario_file(dir + "/scenario.txt", s);
    wo.pcap_dir = dir;
  }
  std::optional<app::JsonlWriter> trace;
  if (!o.trace_path.empty()) {
    auto t = app::JsonlWriter::open(o.trace_path);
    if (!t) {
      std::fprintf(stderr, "utcp-sim: %s\n", t.error().c_str());
    } else {
      trace.emplace(std::move(*t));
      wo.trace_out = [&trace](std::uint32_t node, const TraceEvent& e) {
        app::JsonLine j;
        j.add("node", node_name(node));
        app::add_fields(j, e);
        trace->write(j);
        trace->flush();  // complete up to the last event if the run aborts
      };
    }
  }
  g_seed.store(s.seed);
  const auto t0 = std::chrono::steady_clock::now();
  World w(s, std::move(wo));
  g_world.store(&w);
  const RunResult r = w.run();
  g_world.store(nullptr);
  const auto wall = std::chrono::steady_clock::now() - t0;
  out.write(result_line(r, static_cast<std::uint64_t>(
                               std::chrono::duration_cast<std::chrono::nanoseconds>(wall).count())));
  out.flush();
  if (trace) {
    trace->flush();
  }
  return r.verdict == Verdict::ok;
}

}  // namespace

int main(int argc, char** argv) {
  app::CliParser cli("utcp-sim", "Run seeded simulator scenarios and print one JSON line per run.");
  cli.option("seed", "N", "run the scenario of seed N")
      .option("seed-range", "A:B", "run seeds A..B-1")
      .option("scenario", "FILE", "run a key=value scenario file")
      .option("corpus", "DIR", "run every DIR/*.scenario")
      .option("nodes", "KIND", "stack or synthetic (generated scenarios)", "stack")
      .option("jsonl", "FILE", "result lines ('-' = stdout)", "-")
      .option("pcap", "DIR", "write DIR/seed-N/{scenario.txt,<node>.egress.pcap,<node>.ingress.pcap}")
      .option("snaplen", "N", "pcap snapshot length", "65535")
      .option("trace", "FILE", "every trace event as JSON lines (one run only)")
      .flag("dump-scenario", "print the scenario as key=value lines instead of running it")
      .option("plant-fail", "LIST", "seeds (comma-separated) whose run ends with verdict planted")
      .option("plant-abort", "LIST", "seeds that abort after --plant-after events")
      .option("plant-hang", "LIST", "seeds that hang after --plant-after events")
      .option("plant-segv", "LIST", "seeds that get SIGSEGV after --plant-after events")
      .option("plant-after", "N", "events before a planted abort or hang")
      .option("test-fault", "NAME", "set TcpConfig::test_fault on every node (none, unscaled_peer_window)")
      .option("max-events", "N", "livelock limit per run");
  auto args = cli.parse(argc, argv);
  if (!args) {
    std::fprintf(stderr, "utcp-sim: %s\n%s", args.error().c_str(), cli.usage().c_str());
    return 2;
  }
  if (args->help()) {
    std::fputs(cli.usage().c_str(), stdout);
    return 0;
  }
  const auto usage_error = [&](const std::string& msg) {
    std::fprintf(stderr, "utcp-sim: %s\n", msg.c_str());
    return 2;
  };

  Options o;
  if (const auto k = node_kind_from_string(*args->get("nodes"))) {
    o.nodes = *k;
  } else {
    return usage_error("--nodes: stack or synthetic");
  }
  for (auto [name, set] : {std::pair{"plant-fail", &o.plant_fail}, std::pair{"plant-abort", &o.plant_abort},
                           std::pair{"plant-hang", &o.plant_hang}, std::pair{"plant-segv", &o.plant_segv}}) {
    auto l = parse_list(args->get(name));
    if (!l) {
      return usage_error(std::string("--") + name + ": " + l.error());
    }
    *set = std::move(*l);
  }
  if (const auto v = args->get("plant-after")) {
    auto n = app::parse_u64(*v);
    if (!n) {
      return usage_error("--plant-after: " + n.error());
    }
    o.plant_after = *n;
  }
  if (const auto v = args->get("max-events")) {
    auto n = app::parse_u64(*v);
    if (!n) {
      return usage_error("--max-events: " + n.error());
    }
    o.max_events = *n;
  }
  if (const auto v = args->get("test-fault")) {
    if (*v == "none") {
      o.test_fault = TestFault::none;
    } else if (*v == "unscaled_peer_window") {
      o.test_fault = TestFault::unscaled_peer_window;
    } else {
      return usage_error("--test-fault: none or unscaled_peer_window");
    }
  }
  {
    auto n = app::parse_u64(*args->get("snaplen"));
    if (!n || *n == 0 || *n > 262144) {
      return usage_error("--snaplen: 1..262144");
    }
    o.snaplen = *n;
  }
  o.pcap_dir = args->get("pcap").value_or("");
  o.trace_path = args->get("trace").value_or("");

  // The scenarios to run.
  std::vector<Scenario> fixed;  // --scenario, --corpus
  std::uint64_t first = 0, last = 0;  // generated: [first, last)
  int modes = 0;
  if (const auto v = args->get("seed")) {
    auto n = app::parse_u64(*v);
    if (!n) {
      return usage_error("--seed: " + n.error());
    }
    first = *n;
    last = *n + 1;
    ++modes;
  }
  if (const auto v = args->get("seed-range")) {
    auto p = app::parse_pair(*v);
    if (!p) {
      return usage_error("--seed-range: " + p.error());
    }
    auto a = app::parse_u64(p->first);
    auto b = app::parse_u64(p->second);
    if (!a || !b || *b < *a) {
      return usage_error("--seed-range: A:B with A <= B");
    }
    first = *a;
    last = *b;
    ++modes;
  }
  if (const auto v = args->get("scenario")) {
    auto s = read_scenario_file(*v);
    if (!s) {
      return usage_error(s.error());
    }
    fixed.push_back(std::move(*s));
    ++modes;
  }
  if (const auto v = args->get("corpus")) {
    auto c = load_corpus(*v);
    if (!c) {
      return usage_error(c.error());
    }
    for (CorpusEntry& e : *c) {
      fixed.push_back(std::move(e.scenario));
    }
    ++modes;
  }
  if (modes != 1) {
    return usage_error("give exactly one of --seed, --seed-range, --scenario, --corpus");
  }
  const std::uint64_t runs = fixed.empty() ? last - first : fixed.size();
  if (!o.trace_path.empty() && runs > 1) {
    return usage_error("--trace needs a single run");
  }

  const auto scenario_at = [&](std::uint64_t i) {
    Scenario s = fixed.empty() ? generate_scenario(first + i, o.nodes) : fixed[i];
    apply(o, s);
    return s;
  };

  if (args->flag("dump-scenario")) {
    for (std::uint64_t i = 0; i < runs; ++i) {
      std::fputs(to_kv(scenario_at(i)).c_str(), stdout);
    }
    return 0;
  }

  auto out = app::JsonlWriter::open(*args->get("jsonl"));
  if (!out) {
    return usage_error(out.error());
  }
  install_crash_handlers();
  bool all_ok = true;
  for (std::uint64_t i = 0; i < runs; ++i) {
    all_ok = run_one(scenario_at(i), o, *out) && all_ok;
  }
  return all_ok ? 0 : 1;
}
