// pcap files of a simulator run (m1-sim acceptance test 8): nanosecond
// LINKTYPE_RAW files that tshark reads without Error-severity expert items.
// The tshark part runs where tshark is installed (the testbed image) and is
// skipped elsewhere.
#include <gtest/gtest.h>

#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#include "utcp/sim/scenario.hpp"
#include "utcp/sim/world.hpp"

namespace utcp::sim {
namespace {

namespace fs = std::filesystem;

class TempDir {
public:
  TempDir() {
    path_ = fs::temp_directory_path() / ("utcp-sim-pcap-" + std::to_string(::getpid()));
    fs::remove_all(path_);
    fs::create_directories(path_);
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  [[nodiscard]] const fs::path& path() const { return path_; }

private:
  fs::path path_;
};

std::vector<unsigned char> read_file(const fs::path& p) {
  std::ifstream f(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

std::uint32_t le32(const std::vector<unsigned char>& b, std::size_t at) {
  return std::uint32_t{b[at]} | (std::uint32_t{b[at + 1]} << 8) | (std::uint32_t{b[at + 2]} << 16) |
         (std::uint32_t{b[at + 3]} << 24);
}

// A synthetic run through a router with a smaller MTU (frag-needed in the
// capture), loss, duplication and reordering, but no bit flips or garbage.
Scenario clean_scenario() {
  for (std::uint64_t seed = 0;; ++seed) {
    Scenario s = generate_scenario(seed, NodeKind::synthetic);
    if (s.link.size() != 4 || s.conn.size() < 2) {
      continue;
    }
    for (LinkSpec& l : s.link) {
      l.params.bitflip_ppm = 0;
      l.params.garbage_ppm = 0;
      l.params.icmp_spoof_ppm = 0;
    }
    s.conn[0].bytes_c2s = 100'000;  // full-size datagrams both ways
    s.conn[0].bytes_s2c = 100'000;
    return s;
  }
}

// Runs `cmd` and returns its exit status and output.
std::pair<int, std::string> run(const std::string& cmd) {
  std::string out;
  std::FILE* p = ::popen((cmd + " 2>&1").c_str(), "r");
  if (p == nullptr) {
    return {-1, out};
  }
  std::array<char, 4096> buf{};
  std::size_t n = 0;
  while ((n = std::fread(buf.data(), 1, buf.size(), p)) > 0) {
    out.append(buf.data(), n);
  }
  return {::pclose(p), out};
}

TEST(SimPcap, NanosecondRawFilesPerInterface) {
  TempDir dir;
  const Scenario s = clean_scenario();
  WorldOptions opt;
  opt.pcap_dir = dir.path().string();
  const RunResult r = run_scenario(s, std::move(opt));
  ASSERT_EQ(r.verdict, Verdict::ok);
  std::uint64_t egress = 0, ingress = 0;
  for (const char* name : {"a.egress.pcap", "a.ingress.pcap", "b.egress.pcap", "b.ingress.pcap"}) {
    const auto b = read_file(dir.path() / name);
    ASSERT_GE(b.size(), 24u) << name;
    EXPECT_EQ(le32(b, 0), 0xa1b23c4du) << name;  // nanosecond magic
    EXPECT_EQ(le32(b, 16), 65535u) << name;      // snaplen
    EXPECT_EQ(le32(b, 20), 101u) << name;        // LINKTYPE_RAW
    // Walk the records: times from the run start on, lengths that add up.
    std::size_t at = 24;
    std::uint64_t prev = 0;
    while (at < b.size()) {
      ASSERT_LE(at + 16, b.size()) << name;
      const std::uint64_t t = std::uint64_t{le32(b, at)} * 1'000'000'000 + le32(b, at + 4);
      const std::uint32_t incl = le32(b, at + 8);
      EXPECT_EQ(incl, le32(b, at + 12));
      EXPECT_LT(le32(b, at + 4), 1'000'000'000u);
      EXPECT_GE(t, prev);
      EXPECT_GE(t, static_cast<std::uint64_t>(s.start.ns));
      prev = t;
      at += 16 + incl;
      (std::string_view(name).find("egress") != std::string_view::npos ? egress : ingress) += 1;
    }
    EXPECT_EQ(at, b.size()) << name;
  }
  // Egress: every datagram the nodes handed out. Ingress: what left the last
  // segment of each path, plus ICMP from the routers at a's and b's own
  // segments (links 0 and 2), which reach them directly.
  EXPECT_EQ(egress, r.packets);
  EXPECT_EQ(ingress, r.links[1].delivered + r.links[3].delivered + r.links[0].frag_needed +
                         r.links[2].frag_needed);
  EXPECT_GT(r.links[0].frag_needed + r.links[3].frag_needed, 0u);
}

TEST(SimPcap, TsharkReadsWithoutErrors) {
  if (run("command -v tshark").first != 0) {
    GTEST_SKIP() << "tshark not installed (runs in the testbed image)";
  }
  TempDir dir;
  const Scenario s = clean_scenario();
  WorldOptions opt;
  opt.pcap_dir = dir.path().string();
  ASSERT_EQ(run_scenario(s, std::move(opt)).verdict, Verdict::ok);
  for (const char* name : {"a.egress.pcap", "a.ingress.pcap", "b.egress.pcap", "b.ingress.pcap"}) {
    const std::string file = (dir.path() / name).string();
    const auto [st, expert] = run("tshark -n -r " + file + " -q -z expert");
    EXPECT_EQ(st, 0) << name << ":\n" << expert;
    EXPECT_EQ(expert.find("Errors ("), std::string::npos) << name << ":\n" << expert;
    // Nanosecond timestamps: nine fractional digits, the run's start second.
    const auto [st2, first] = run("tshark -n -r " + file + " -c 1 -T fields -e frame.time_epoch");
    ASSERT_EQ(st2, 0) << first;
    const auto dot = first.find('.');
    ASSERT_NE(dot, std::string::npos) << first;
    EXPECT_EQ(first.find_first_not_of("0123456789", dot + 1), dot + 10) << first;
    EXPECT_GE(std::stoll(first.substr(0, dot)), s.start.ns / 1'000'000'000) << first;
  }
}

}  // namespace
}  // namespace utcp::sim
