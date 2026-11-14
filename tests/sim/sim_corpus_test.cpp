// The corpus runner (DESIGN §7.2, m1-sim acceptance test 9): every
// tests/sim/corpus/*.scenario (the dumped scenario of a SIM-BUGS entry)
// replays and passes, each as its own test (SimCorpusEntry); a dumped
// scenario replays to the same digest.
#include <gtest/gtest.h>

#include <unistd.h>

#include <cctype>
#include <filesystem>
#include <string>
#include <vector>

#include "utcp/sim/results.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/sim/world.hpp"

namespace utcp::sim {
namespace {

namespace fs = std::filesystem;

// The corpus file names (without directory), sorted, read once when the
// tests are registered so that each entry is its own test and ctest runs
// them in parallel (some take minutes under ASan).
std::vector<std::string> corpus_files() {
  std::vector<std::string> out;
  const auto entries = load_corpus(UTCP_SIM_CORPUS_DIR);
  if (entries) {
    for (const CorpusEntry& e : *entries) {
      out.push_back(fs::path(e.path).filename().string());
    }
  }
  return out;
}

// The corpus loads (every file parses) and has an entry per test below.
TEST(SimCorpus, EveryEntryLoads) {
  const auto entries = load_corpus(UTCP_SIM_CORPUS_DIR);
  ASSERT_TRUE(entries.has_value()) << entries.error();
  EXPECT_FALSE(entries->empty());
  EXPECT_EQ(entries->size(), corpus_files().size());
}

class SimCorpusEntry : public ::testing::TestWithParam<std::string> {};

TEST_P(SimCorpusEntry, Passes) {
  const std::string path = (fs::path(UTCP_SIM_CORPUS_DIR) / GetParam()).string();
  const auto s = read_scenario_file(path);
  ASSERT_TRUE(s.has_value()) << s.error();
  const RunResult r = run_scenario(*s);
  EXPECT_EQ(r.verdict, Verdict::ok)
      << path << ": " << (r.violations.empty() ? "" : r.violations[0].message);
}

INSTANTIATE_TEST_SUITE_P(Corpus, SimCorpusEntry, ::testing::ValuesIn(corpus_files()),
                         [](const ::testing::TestParamInfo<std::string>& i) {
                           std::string n = fs::path(i.param).stem().string();
                           for (char& c : n) {
                             if (!std::isalnum(static_cast<unsigned char>(c))) {
                               c = '_';
                             }
                           }
                           return n;
                         });

TEST(SimCorpus, DumpedScenarioReplays) {
  const fs::path dir = fs::temp_directory_path() / ("utcp-sim-corpus-" + std::to_string(::getpid()));
  fs::remove_all(dir);
  fs::create_directories(dir);
  Scenario s1 = generate_scenario(31, NodeKind::synthetic);
  Scenario s2 = generate_scenario(32, NodeKind::synthetic);
  s2.plant = Plant::fail;
  ASSERT_TRUE(write_scenario_file((dir / "b-0032.scenario").string(), s2));
  ASSERT_TRUE(write_scenario_file((dir / "a-0031.scenario").string(), s1));
  ASSERT_TRUE(write_scenario_file((dir / "ignored.txt").string(), s1));
  const auto entries = load_corpus(dir.string());
  ASSERT_TRUE(entries.has_value()) << entries.error();
  ASSERT_EQ(entries->size(), 2u);
  EXPECT_EQ((*entries)[0].scenario, s1);  // sorted by file name
  EXPECT_EQ((*entries)[1].scenario, s2);
  const auto runs = run_corpus(*entries);
  ASSERT_EQ(runs.size(), 2u);
  EXPECT_EQ(runs[0].result.verdict, Verdict::ok);
  EXPECT_EQ(runs[0].result.digest, run_scenario(s1).digest);
  EXPECT_EQ(runs[1].result.verdict, Verdict::planted);
  EXPECT_EQ(runs[1].result.digest, run_scenario(s2).digest);

  // A file that does not parse is an error, not a skipped entry.
  {
    std::FILE* f = std::fopen((dir / "c-bad.scenario").c_str(), "w");
    ASSERT_NE(f, nullptr);
    std::fputs("seed=1\nbogus=2\n", f);
    std::fclose(f);
  }
  EXPECT_FALSE(load_corpus(dir.string()).has_value());
  fs::remove_all(dir);
  // A missing directory is an empty corpus.
  const auto none = load_corpus((dir / "missing").string());
  ASSERT_TRUE(none.has_value());
  EXPECT_TRUE(none->empty());
}

TEST(SimCorpus, ResultLineCarriesSeedBeforeDigest) {
  const RunResult r = run_scenario(generate_scenario(33, NodeKind::synthetic));
  const std::string line = result_line(r, 1'500'000).str();
  const auto seed = line.find("\"seed\":33");
  const auto digest = line.find("\"digest\":\"" + digest_string(r.digest) + "\"");
  ASSERT_NE(seed, std::string::npos) << line;
  ASSERT_NE(digest, std::string::npos) << line;
  EXPECT_LT(seed, digest);
  EXPECT_NE(line.find("\"verdict\":\"ok\""), std::string::npos) << line;
  EXPECT_NE(line.find("\"wall_ms\":1"), std::string::npos) << line;
  EXPECT_EQ(digest_string(0x0123'4567'89ab'cdef), "0123456789abcdef");
}

}  // namespace
}  // namespace utcp::sim
