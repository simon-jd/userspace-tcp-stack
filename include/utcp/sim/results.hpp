// Run results as JSON Lines (DESIGN §7.4) and the corpus runner (§7.2):
// tests/sim/corpus holds the dumped scenario of every SIM-BUGS entry, and CI
// replays them all.
#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "common/jsonl.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/sim/world.hpp"

namespace utcp::sim {

// 16 lowercase hex digits.
[[nodiscard]] std::string digest_string(std::uint64_t digest);

// One RunResult line: seed, verdict, violations (count and the first
// message), start/end/duration of virtual time (ns), events, packets, bytes,
// digest, wall time (ms). "seed" precedes "digest" (ci/check-digests.sh).
[[nodiscard]] app::JsonLine result_line(const RunResult& r, std::uint64_t wall_ns);

// A corpus entry: a `*.scenario` file (key=value, see parse_kv).
struct CorpusEntry {
  std::string path;
  Scenario scenario;
};
// Every *.scenario file in `dir`, sorted by file name. An empty or missing
// directory gives no entries; a file that does not parse is an error.
[[nodiscard]] std::expected<std::vector<CorpusEntry>, std::string> load_corpus(const std::string& dir);

struct CorpusRun {
  std::string path;
  RunResult result;
};
[[nodiscard]] std::vector<CorpusRun> run_corpus(const std::vector<CorpusEntry>& entries);

// Writes `s` (to_kv) to `path`; false on error.
bool write_scenario_file(const std::string& path, const Scenario& s);
// Reads and parses a scenario file.
[[nodiscard]] std::expected<Scenario, std::string> read_scenario_file(const std::string& path);

}  // namespace utcp::sim
