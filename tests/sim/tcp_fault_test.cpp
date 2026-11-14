// The planted bug of DESIGN §7.3 (m1-tcp-robust acceptance test 6): with
// TcpConfig::test_fault = overscaled_peer_window on every node, the
// InFlightChecker must fire within the first 100 generated seeds. The
// design named unscaled_peer_window; that fault only makes the sender use a
// smaller window than the peer offered, which no checker can call a
// violation, so overscaled_peer_window (the peer's window field shifted by
// 14 whatever was negotiated) is the planted bug (DESIGN §7.3).
#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

TEST(TcpFaultSim, OverscaledPeerWindowFiresTheInFlightChecker) {
  std::optional<std::uint64_t> fired;
  for (std::uint64_t seed = 0; seed < 100 && !fired; ++seed) {
    Scenario s = generate_scenario(seed);
    for (NodeSpec& n : s.node) {
      n.test_fault = TestFault::overscaled_peer_window;
    }
    const RunResult r = run_scenario(s);
    if (r.verdict == Verdict::inflight) {
      fired = seed;
      ASSERT_FALSE(r.violations.empty());
      EXPECT_NE(r.violations[0].message.find("edge"), std::string::npos) << r.violations[0].message;
    }
  }
  ASSERT_TRUE(fired.has_value());
  // The same seed without the fault passes.
  const RunResult clean = run_scenario(generate_scenario(*fired));
  EXPECT_EQ(clean.verdict, Verdict::ok);
}

}  // namespace
}  // namespace utcp::sim
