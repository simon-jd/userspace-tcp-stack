#include "utcp/sim/results.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <system_error>

namespace utcp::sim {

std::string digest_string(std::uint64_t digest) {
  const auto h = RunDigest::hex(digest);
  return std::string(h.data(), h.size());
}

app::JsonLine result_line(const RunResult& r, std::uint64_t wall_ns) {
  app::JsonLine j;
  j.add("seed", r.seed);
  j.add("verdict", to_string(r.verdict));
  j.add("violations", static_cast<std::uint64_t>(r.violations.size()));
  if (!r.violations.empty()) {
    j.add("violation", r.violations.front().message);
    j.add("violation_t_ns", r.violations.front().t.ns);
  }
  j.add("start_ns", r.start.ns);
  j.add("end_ns", r.end.ns);
  j.add("duration_ns", (r.end - r.start).count());
  j.add("events", r.events);
  j.add("packets", r.packets);
  j.add("bytes", r.bytes);
  j.add("digest", digest_string(r.digest));
  j.add("wall_ms", wall_ns / 1'000'000);
  return j;
}

std::expected<std::vector<CorpusEntry>, std::string> load_corpus(const std::string& dir) {
  namespace fs = std::filesystem;
  std::vector<CorpusEntry> out;
  std::error_code ec;
  if (!fs::is_directory(dir, ec)) {
    return out;
  }
  std::vector<std::string> paths;
  for (const auto& e : fs::directory_iterator(dir, ec)) {
    if (e.is_regular_file() && e.path().extension() == ".scenario") {
      paths.push_back(e.path().string());
    }
  }
  if (ec) {
    return std::unexpected(dir + ": " + ec.message());
  }
  std::ranges::sort(paths);
  for (const std::string& p : paths) {
    auto s = read_scenario_file(p);
    if (!s) {
      return std::unexpected(s.error());
    }
    out.push_back(CorpusEntry{p, std::move(*s)});
  }
  return out;
}

std::vector<CorpusRun> run_corpus(const std::vector<CorpusEntry>& entries) {
  std::vector<CorpusRun> out;
  out.reserve(entries.size());
  for (const CorpusEntry& e : entries) {
    out.push_back(CorpusRun{e.path, run_scenario(e.scenario)});
  }
  return out;
}

bool write_scenario_file(const std::string& path, const Scenario& s) {
  std::FILE* f = std::fopen(path.c_str(), "w");
  if (f == nullptr) {
    return false;
  }
  const std::string text = to_kv(s);
  const bool ok = std::fwrite(text.data(), 1, text.size(), f) == text.size();
  return std::fclose(f) == 0 && ok;
}

std::expected<Scenario, std::string> read_scenario_file(const std::string& path) {
  std::FILE* f = std::fopen(path.c_str(), "r");
  if (f == nullptr) {
    return std::unexpected(path + ": " + std::strerror(errno));
  }
  std::string text;
  char buf[4096];
  for (;;) {
    const std::size_t n = std::fread(buf, 1, sizeof buf, f);
    text.append(buf, n);
    if (n < sizeof buf) {
      break;
    }
  }
  const bool err = std::ferror(f) != 0;
  std::fclose(f);
  if (err) {
    return std::unexpected(path + ": read error");
  }
  auto s = parse_kv(text);
  if (!s) {
    return std::unexpected(path + ": " + s.error());
  }
  return s;
}

}  // namespace utcp::sim
