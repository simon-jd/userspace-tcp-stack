#include "core/ports.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <vector>

#include "core/stack_impl.hpp"
#include "utcp/config.hpp"

namespace {

using utcp::Endpoint;
using utcp::Error;
using utcp::FourTuple;
using utcp::Ipv4Addr;
using utcp::PortAllocator;
using utcp::PortRange;
using utcp::Rng;
using utcp::Seed;
using utcp::SipKey;

const SipKey offset_key{0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};
const SipKey table_key{0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL};
const Ipv4Addr local = Ipv4Addr::from_octets(10, 0, 0, 1);
const Endpoint remote{Ipv4Addr::from_octets(192, 0, 2, 7), 443};
constexpr PortRange linux_range{32768, 60999};

PortAllocator fixed_allocator() {
  return PortAllocator(offset_key, table_key, Rng(Seed::from_u64(42)));
}

std::array<std::byte, 10> fields(Ipv4Addr l, Endpoint r) {
  std::array<std::byte, 10> b{};
  const auto put32 = [&](std::size_t at, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) {
      b[at + i] = static_cast<std::byte>(v >> (24 - 8 * i));
    }
  };
  put32(0, l.v);
  put32(4, r.addr.v);
  b[8] = static_cast<std::byte>(r.port >> 8);
  b[9] = static_cast<std::byte>(r.port & 0xff);
  return b;
}

auto never_used = [](std::uint16_t) { return false; };

// RFC 6056 §3.3.4: offset = F(local, remote addr, remote port), F = the low
// 32 bits of SipHash-2-4 over the fields in network order; index = G(...) mod
// 256; table[] starts with random values below 65536.
TEST(Ports, HashesFollowTheAlgorithm) {
  PortAllocator a = fixed_allocator();
  const auto b = fields(local, remote);
  EXPECT_EQ(a.offset(local, remote), static_cast<std::uint32_t>(utcp::siphash24(offset_key, b)));
  EXPECT_EQ(a.index(local, remote), utcp::siphash24(table_key, b) % 256);
  Rng init(Seed::from_u64(42));
  for (std::size_t i = 0; i < PortAllocator::table_size; ++i) {
    EXPECT_EQ(a.table()[i], init.next() & 0xffffu) << i;
  }
  // The first candidate: min + (offset + table[index]) mod n.
  const std::uint64_t n = linux_range.size();
  const std::uint32_t t = a.table()[a.index(local, remote)];
  const auto want = static_cast<std::uint16_t>(linux_range.lo + (a.offset(local, remote) + t) % n);
  EXPECT_EQ(a.pick(linux_range, local, remote, never_used), want);
  // table[index] counts attempts.
  EXPECT_EQ(a.table()[a.index(local, remote)], t + 1);
}

// m1-ip test 6: with fixed keys the sequence is stable (golden values).
TEST(Ports, GoldenSequence) {
  PortAllocator a = fixed_allocator();
  std::vector<std::uint16_t> got;
  for (int i = 0; i < 6; ++i) {
    got.push_back(*a.pick(linux_range, local, remote, never_used));
  }
  const Endpoint other{Ipv4Addr::from_octets(198, 51, 100, 9), 80};
  for (int i = 0; i < 3; ++i) {
    got.push_back(*a.pick(linux_range, local, other, never_used));
  }
  const std::vector<std::uint16_t> golden{54921, 54922, 54923, 54924, 54925, 54926,
                                          49036, 49037, 49038};
  EXPECT_EQ(got, golden);
}

// Successive connections to one remote get successive ports (the counter
// advances once per attempt), wrapping inside the range.
TEST(Ports, SuccessivePicksForOneRemoteAreConsecutive) {
  PortAllocator a = fixed_allocator();
  const PortRange r{1000, 1009};
  const std::uint16_t first = *a.pick(r, local, remote, never_used);
  for (std::uint32_t i = 1; i < 25; ++i) {
    const std::uint16_t p = *a.pick(r, local, remote, never_used);
    EXPECT_EQ(p, r.lo + (first - r.lo + i) % r.size()) << i;
  }
}

// A fake in-use predicate stands in for TcpEngine::tuple_in_use and
// port_has_listener: the allocator never returns a port it rejects.
TEST(Ports, NeverReturnsAPortInUse) {
  PortAllocator a = fixed_allocator();
  const PortRange r{20000, 20199};
  std::set<FourTuple> conns;           // the "connection and TIME_WAIT tables"
  const std::set<std::uint16_t> listeners{20003, 20050, 20101, 20150};
  std::vector<Endpoint> remotes;
  for (std::uint8_t i = 0; i < 4; ++i) {
    remotes.push_back(Endpoint{Ipv4Addr::from_octets(192, 0, 2, i), 443});
  }
  for (int round = 0; round < 200; ++round) {
    const Endpoint rem = remotes[static_cast<std::size_t>(round) % remotes.size()];
    const auto in_use = [&](std::uint16_t p) {
      return listeners.contains(p) || conns.contains(FourTuple{Endpoint{local, p}, rem});
    };
    const auto p = a.pick(r, local, rem, in_use);
    ASSERT_TRUE(p.has_value());
    EXPECT_FALSE(in_use(*p));
    EXPECT_TRUE(*p >= r.lo && *p <= r.hi);
    conns.insert(FourTuple{Endpoint{local, *p}, rem});
  }
}

// The whole range is tried, each port once, before addr_not_available.
TEST(Ports, WalksTheWholeRangeBeforeFailing) {
  PortAllocator a = fixed_allocator();
  const PortRange r{5000, 5099};
  std::vector<int> tried(65536, 0);
  const auto all_used = [&](std::uint16_t p) {
    ++tried[p];
    return true;
  };
  EXPECT_EQ(a.pick(r, local, remote, all_used), std::unexpected(Error::addr_not_available));
  for (std::uint32_t p = 0; p < 65536; ++p) {
    EXPECT_EQ(tried[p], p >= r.lo && p <= r.hi ? 1 : 0) << p;
  }
  // Only one free port, wherever it is: found.
  for (const std::uint16_t free_port : {std::uint16_t{5000}, std::uint16_t{5057}, std::uint16_t{5099}}) {
    const auto only_one = [&](std::uint16_t p) { return p != free_port; };
    EXPECT_EQ(a.pick(r, local, remote, only_one), free_port);
  }
  // Filling the range one connection at a time: n successes, then failure.
  std::set<std::uint16_t> used;
  const auto in_use = [&](std::uint16_t p) { return used.contains(p); };
  for (std::uint32_t i = 0; i < r.size(); ++i) {
    const auto p = a.pick(r, local, remote, in_use);
    ASSERT_TRUE(p.has_value()) << i;
    EXPECT_TRUE(used.insert(*p).second);
  }
  EXPECT_EQ(a.pick(r, local, remote, in_use), std::unexpected(Error::addr_not_available));
  // An empty range fails at once.
  EXPECT_EQ(a.pick(PortRange{10, 9}, local, remote, never_used),
            std::unexpected(Error::addr_not_available));
}

TEST(Ports, DifferentRemotesStartAtDifferentOffsets) {
  PortAllocator a = fixed_allocator();
  std::set<std::uint32_t> offsets;
  std::set<std::uint16_t> firsts;
  for (std::uint16_t i = 0; i < 16; ++i) {
    const Endpoint rem{Ipv4Addr::from_octets(192, 0, 2, static_cast<std::uint8_t>(i)),
                       static_cast<std::uint16_t>(443 + i)};
    offsets.insert(a.offset(local, rem));
    PortAllocator fresh = fixed_allocator();
    firsts.insert(*fresh.pick(linux_range, local, rem, never_used));
  }
  EXPECT_EQ(offsets.size(), 16u);
  EXPECT_EQ(firsts.size(), 16u);
}

// The stack's allocators: TCP over TcpConfig::ephemeral_ports (the stub
// engine rejects nothing), UDP over the UDP range with remote 0:0.
TEST(Ports, StackAllocatorsUseTheProfileRanges) {
  for (const auto profile : {utcp::ProfileId::linux_compat, utcp::ProfileId::rfc}) {
    utcp::StackConfig cfg;
    cfg.local_addr = local;
    cfg.seed = Seed::from_u64(3);
    cfg.tcp = utcp::tcp_config(profile);
    utcp::StackImpl s(cfg);
    const PortRange tr = cfg.tcp.ephemeral_ports;
    const auto p = s.core.tcp_ephemeral_port(remote);
    ASSERT_TRUE(p.has_value());
    EXPECT_TRUE(*p >= tr.lo && *p <= tr.hi);
    const PortRange ur = utcp::udp_ephemeral_ports(cfg);
    EXPECT_EQ(ur, tr);
    for (int i = 0; i < 20; ++i) {
      const auto h = s.udp.open(Endpoint{});
      ASSERT_TRUE(h.has_value());
      (void)h;
    }
    // udp_ephemeral_port skips bound ports.
    for (int i = 0; i < 20; ++i) {
      const auto q = s.core.udp_ephemeral_port([&](std::uint16_t c) { return s.udp.port_bound(c); });
      ASSERT_TRUE(q.has_value());
      EXPECT_FALSE(s.udp.port_bound(*q));
      EXPECT_TRUE(*q >= ur.lo && *q <= ur.hi);
    }
  }
}

}  // namespace
