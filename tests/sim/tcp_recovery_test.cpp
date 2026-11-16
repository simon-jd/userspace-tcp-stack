// m2a-recovery acceptance test 7 (M2-DESIGN §4.3 directed cases): loss
// recovery end to end in the simulator. A tail loss of the last two packets
// is repaired by a tail loss probe without an RTO in linux_compat and by the
// RTO in rfc; a lost retransmission is repaired by RACK without an RTO in
// linux_compat; 100 MB under 1 % Bernoulli loss and under 5 % burst loss, per
// profile, with SACK on and off, arrive intact (the StreamChecker compares
// every byte) with no checker violation. Every run is repeated and must give
// the same digest.
#include <cstdint>
#include <functional>
#include <memory>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <ostream>

#include "tcp_sim_util.hpp"

namespace utcp::sim {
namespace {

constexpr std::uint32_t seg = 1448;  // MSS 1460 less the timestamp option

std::string profile_name(ProfileId p) { return p == ProfileId::rfc ? "rfc" : "linux_compat"; }

// Drops data segments node 0 sends, chosen by stream offset and copy number
// (`drop(off, copy)`, copy 1 = the first transmission), as M2-DESIGN §4.2's
// scripted drops do.
struct OffsetDropper {
  std::function<bool(std::uint64_t off, std::uint32_t copy)> drop;
  std::optional<Seq32> isn;
  std::map<std::uint64_t, std::uint32_t> copies;
  std::set<std::uint64_t> dropped;

  void install(Tap& tap) {
    tap.egress = [this](Tap&, Time t, std::span<const std::byte> d) {
      const auto s = parse_seg(0, true, t, d);
      if (!s) {
        return true;
      }
      if (s->has(wire::tcp_syn)) {
        isn = s->h.seq;
        return true;
      }
      if (!isn || s->len == 0) {
        return true;
      }
      const std::uint64_t off = s->h.seq - (*isn + 1);
      const std::uint32_t copy = ++copies[off];
      if (drop(off, copy)) {
        dropped.insert(off);
        return false;
      }
      return true;
    };
  }
};

// One bulk transfer from node 0 to node 1 over 10 ms each way, run twice.
struct TwoRuns {
  Outcome first;
  std::uint64_t second_digest = 0;
  std::map<std::uint64_t, std::uint32_t> copies;  // first run: transmissions per offset
};

TwoRuns run_twice(const Scenario& s, const std::function<void(OffsetDropper&)>& set_drops) {
  TwoRuns r;
  for (int i = 0; i < 2; ++i) {
    auto dropper = std::make_shared<OffsetDropper>();
    set_drops(*dropper);
    RunSpec spec;
    spec.keep_wire = i == 0;
    spec.setup = [dropper](std::vector<Tap*>& taps) { dropper->install(*taps[0]); };
    Outcome o = run_sim(s, spec);
    if (i == 0) {
      r.first = std::move(o);
      r.copies = dropper->copies;
    } else {
      r.second_digest = o.result.digest;
    }
  }
  return r;
}

Scenario directed(std::uint64_t seed, ProfileId profile, std::uint64_t bytes) {
  Scenario s = two_node_scenario(seed, clean_link(10ms), clean_link(10ms));
  for (NodeSpec& n : s.node) {
    n.profile = profile;
  }
  s.conn.push_back(bulk(bytes, 0));
  return s;
}

// The first transmissions of the last two packets of a 30-packet transfer
// are lost. linux_compat: the PTO resends the last packet (TLP), whose SACK
// lets RACK mark the other one lost; no RTO. rfc (no TLP): the RTO repairs
// them.
TEST(TcpRecoverySim, TailLossOfTheLastTwoPackets) {
  for (const ProfileId profile : {ProfileId::linux_compat, ProfileId::rfc}) {
    SCOPED_TRACE(profile_name(profile));
    constexpr std::uint64_t total = 30 * std::uint64_t{seg};
    const Scenario s = directed(7100 + static_cast<std::uint64_t>(profile), profile, total);
    const TwoRuns r = run_twice(s, [](OffsetDropper& d) {
      d.drop = [](std::uint64_t off, std::uint32_t copy) {
        return copy == 1 && off >= total - 2 * seg;
      };
    });
    const Outcome& o = r.first;
    ASSERT_TRUE(o.ok()) << o.violations();
    EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
    EXPECT_EQ(r.second_digest, o.result.digest);
    const StackStats& st = o.stats[0];
    if (profile == ProfileId::linux_compat) {
      EXPECT_EQ(st.TcpExtTCPTimeouts, 0u);
      EXPECT_EQ(st.TcpExtTCPLossProbes, 1u);
      EXPECT_EQ(st.TcpExtTCPSackRecovery, 1u);
    } else {
      EXPECT_GE(st.TcpExtTCPTimeouts, 1u);
      EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);
    }
    // Both lost packets were sent again (the application's writes leave a
    // short segment here and there, so the last two start where they start).
    ASSERT_GE(r.copies.size(), 2u);
    const auto last = r.copies.rbegin();
    EXPECT_GE(last->second, 2u);
    EXPECT_GE(std::next(last)->second, 2u);
    EXPECT_GE(std::next(last)->first, total - 2 * seg);
  }
}

// The original and the first retransmission of the first packet starting at
// or after byte 100 * 1448 are lost. RACK finds the
// retransmission lost once packets sent after it are SACKed (Linux
// FLAG_LOST_RETRANS) and sends it a third time; no RTO.
TEST(TcpRecoverySim, LostRetransmissionRepairedByRack) {
  constexpr std::uint64_t total = 300 * std::uint64_t{seg};
  constexpr std::uint64_t victim = 100 * std::uint64_t{seg};
  const Scenario s = directed(7200, ProfileId::linux_compat, total);
  const TwoRuns r = run_twice(s, [](OffsetDropper& d) {
    d.drop = [chosen = std::optional<std::uint64_t>{}](std::uint64_t off,
                                                       std::uint32_t copy) mutable {
      if (!chosen && off >= victim) {
        chosen = off;
      }
      return off == chosen && copy <= 2;
    };
  });
  const Outcome& o = r.first;
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
  EXPECT_EQ(r.second_digest, o.result.digest);
  const StackStats& st = o.stats[0];
  EXPECT_EQ(st.TcpExtTCPTimeouts, 0u);
  EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);
  EXPECT_GE(st.TcpRetransSegs, 2u);
  // Three transmissions of the victim, the third one delivered.
  const auto v = r.copies.lower_bound(victim);
  ASSERT_NE(v, r.copies.end());
  EXPECT_EQ(v->second, 3u);
}

// 100 MB from node 0 to node 1 over 10 ms each way, the data direction lossy:
// 1 % Bernoulli, or 5 % in bursts (Gilbert-Elliott: p = 26316 ppm, r =
// 500000 ppm, everything lost in the bad state: p / (p + r) = 5 %, bursts of
// 2 packets on average). The model's state moves per packet, so a burst that
// catches an RTO retransmission tends to catch the next one too (each stays
// lost with probability 1 - r); the applications' idle limit is raised to
// 20 minutes so that a long backoff chain is not taken for a hang. Per
// profile, SACK on and off.
enum class LossKind : std::uint8_t { bernoulli_1pct, burst_5pct };

struct BulkCase {
  ProfileId profile;
  LossKind loss;
  bool sack;
};

std::string bulk_case_name(const BulkCase& c) {
  return profile_name(c.profile) + (c.loss == LossKind::bernoulli_1pct ? "_loss1" : "_burst5") +
         (c.sack ? "_sack" : "_nosack");
}

// The case's name in gtest output (and so in the ctest name).
void PrintTo(const BulkCase& c, std::ostream* os) { *os << bulk_case_name(c); }

class TcpRecoveryBulkSim : public ::testing::TestWithParam<BulkCase> {};

TEST_P(TcpRecoveryBulkSim, HundredMegabytesArriveIntact) {
  const auto [profile, loss, sack] = GetParam();
  constexpr std::uint64_t total = 100'000'000;
  LinkParams ab = clean_link(10ms);
  if (loss == LossKind::bernoulli_1pct) {
    ab.loss_ppm = 10'000;
  } else {
    ab.burst = GilbertElliott{26'316, 500'000, 1'000'000};
  }
  Scenario s = two_node_scenario(7300 + static_cast<std::uint64_t>(profile) * 4 +
                                     static_cast<std::uint64_t>(loss) * 2 + (sack ? 1 : 0),
                                 ab, clean_link(10ms));
  for (NodeSpec& n : s.node) {
    n.profile = profile;
    n.sack = sack;
  }
  s.app_idle_timeout = 1200s;
  s.conn.push_back(bulk(total, 0));
  RunSpec spec;
  spec.keep_trace = false;
  spec.keep_wire = false;
  const Outcome o = run_sim(s, spec);
  ASSERT_TRUE(o.ok()) << o.violations();
  EXPECT_EQ(o.counts[1].tcp_bytes_received, total);
  const StackStats& st = o.stats[0];
  EXPECT_GT(st.TcpRetransSegs, 0u);
  EXPECT_EQ(st.TcpExtTCPSACKDiscard, 0u);
  if (sack) {
    EXPECT_GT(st.TcpExtTCPSackRecovery, 0u);
  } else {
    EXPECT_GT(st.TcpExtTCPRenoRecovery, 0u);
    EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);  // no TLP without SACK
  }
  if (profile == ProfileId::rfc) {
    EXPECT_EQ(st.TcpExtTCPLossProbes, 0u);
  }
  EXPECT_EQ(run_sim(s, spec).result.digest, o.result.digest);
}

std::string bulk_param_name(const ::testing::TestParamInfo<BulkCase>& p) {
  return bulk_case_name(p.param);
}

INSTANTIATE_TEST_SUITE_P(
    Profiles, TcpRecoveryBulkSim,
    ::testing::Values(BulkCase{ProfileId::linux_compat, LossKind::bernoulli_1pct, true},
                      BulkCase{ProfileId::linux_compat, LossKind::bernoulli_1pct, false},
                      BulkCase{ProfileId::linux_compat, LossKind::burst_5pct, true},
                      BulkCase{ProfileId::linux_compat, LossKind::burst_5pct, false},
                      BulkCase{ProfileId::rfc, LossKind::bernoulli_1pct, true},
                      BulkCase{ProfileId::rfc, LossKind::bernoulli_1pct, false},
                      BulkCase{ProfileId::rfc, LossKind::burst_5pct, true},
                      BulkCase{ProfileId::rfc, LossKind::burst_5pct, false}),
    bulk_param_name);

}  // namespace
}  // namespace utcp::sim
