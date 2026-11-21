// Scenarios (DESIGN §7.2): everything a run depends on, generated from one
// 64-bit seed and serialised as `key=value` lines with a gen_version.
// `utcp-sim --seed N` regenerates a scenario; `utcp-sim --scenario FILE` runs
// a written one, so a dumped failing scenario replays after the generator
// has changed.
//
// Generation uses integers only (ppm probabilities, nanoseconds, a
// fixed-point log-uniform table, Rng::below) and one named stream per
// consumer ("gen/node/a", "gen/link/a>b", "gen/wl/conn3", ...), so adding a
// consumer does not change what the others draw.
#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "utcp/config.hpp"
#include "utcp/random.hpp"
#include "utcp/sim/link.hpp"
#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp::sim {

// Bumped whenever generate_scenario() changes what a seed produces.
// 2: shared listeners (backlog limits).
// 3: a small ChunkPool (NodeSpec::chunk_limit) in half of the small-queue seeds.
inline constexpr std::uint32_t gen_version = 6;  // current seed generator
inline constexpr std::uint32_t max_gen_version = 6;

enum class NodeKind : std::uint8_t {
  stack,      // StackNode: a Stack running the scripted workload
  synthetic,  // SyntheticNode: the workload as raw UDP datagrams, no Stack
};

// A planted failure for testing the sweep tooling (m1-sim test 9).
enum class Plant : std::uint8_t {
  none,
  fail,   // the run ends with verdict `planted`
  abort,  // the process aborts after `plant_after_events` events
  hang,   // the process spins forever after `plant_after_events` events
  segv,   // the process gets SIGSEGV after `plant_after_events` events
};

// How a TCP workload connection ends (DESIGN §7.2).
enum class CloseMode : std::uint8_t {
  close,         // both sides send, shut down writing, read to EOF, close
  half_close,    // the client sends and shuts down; the server reads to EOF, then sends back
  abort,         // the client aborts abort_after after it connected
  refused,       // the client connects to a port without a listener
  simultaneous,  // both sides connect to each other (fixed ports), then as `close`
};

struct NodeSpec {
  ProfileId profile = ProfileId::linux_compat;
  bool sack = true;
  bool timestamps = true;
  bool window_scaling = true;
  bool nodelay = false;
  std::uint32_t snd_buf = 0;  // payload bytes, fixed; 0 = the profile's default (autotuned)
  std::uint32_t rcv_buf = 0;
  std::optional<std::uint32_t> test_isn;  // TcpConfig::test_isn (sequence wrap)
  std::uint32_t renege_ppm = 0;           // TcpConfig::test_renege_ppm
  TestFault test_fault = TestFault::none;  // TcpConfig::test_fault (planted bug)
  std::uint32_t tx_queue_packets = 1024;
  std::uint32_t pool_buffers = 4096;
  std::uint32_t chunk_limit = 1u << 20;  // serialized count; keep generated scenarios reproducible
  std::uint32_t host_drain_max = 0;  // datagrams the host drains per wake-up; 0 = all
  Duration host_delay{};             // when the host drains the rest

  // Explicit controls in version 4+ scenarios. Older scenarios use the profile.
  CcAlgo cc = CcAlgo::newreno;
  Hystart hystart = Hystart::hystart_classic;
  RecoveryReduction recovery_reduction = RecoveryReduction::prr;
  bool rack_tlp = true;
  Pacing pacing = Pacing::cc_requested;

  bool operator==(const NodeSpec&) const = default;
};

struct LinkSpec {
  std::string name;  // unique; labels the link's random streams ("a>b")
  LinkParams params;

  bool operator==(const LinkSpec&) const = default;
};

// The segments a datagram from node `from` to node `to` crosses, in order.
struct PathSpec {
  std::uint32_t from = 0, to = 1;
  std::vector<std::uint32_t> links;  // indices into Scenario::link

  bool operator==(const PathSpec&) const = default;
};

// Connections of the same server node and server_port (close, half_close or
// abort) share one listener: its backlog is theirs (all equal), and each has
// a distinct fixed client_port, by which the server tells the accepted
// connections apart. A listener with one connection may use an ephemeral
// client port.
struct ConnSpec {
  CloseMode mode = CloseMode::close;
  std::uint32_t client = 0;  // node index; the server is the other node
  std::uint16_t server_port = 5000;
  std::uint16_t client_port = 0;  // 0 = ephemeral (RFC 6056); fixed for `simultaneous` and shared listeners
  std::uint32_t backlog = 1;
  Duration start{};               // after the run start
  std::uint64_t bytes_c2s = 0, bytes_s2c = 0;
  std::uint32_t write_max_c = 65536, write_max_s = 65536;  // each write is 1..write_max bytes
  std::uint64_t pause_every_c = 0;  // the client's reader pauses after this many bytes; 0 = never
  Duration pause_c{};
  std::uint64_t pause_every_s = 0;
  Duration pause_s{};
  Duration abort_after{};  // `abort`: time from connected to tcp_abort

  Duration write_interval{};  // wait after each successful write (both ends)

  bool operator==(const ConnSpec&) const = default;
};

// UDP echo traffic: the client sends `count` datagrams to the server port,
// the server echoes each one. server_bound = false leaves the port unbound,
// so each datagram draws an ICMP port unreachable.
struct UdpSpec {
  std::uint32_t client = 0;
  std::uint16_t server_port = 7, client_port = 0;
  bool server_bound = true;
  std::uint32_t count = 1;
  std::uint32_t size_min = 0, size_max = 0;  // payload bytes
  Duration interval{};
  Duration start{};

  bool operator==(const UdpSpec&) const = default;
};

// ICMP echo: the client pings the other node.
struct PingSpec {
  std::uint32_t client = 0;
  std::uint16_t id = 1;
  std::uint32_t count = 1;
  std::uint32_t size = 56;
  Duration interval{};
  Duration start{};

  bool operator==(const PingSpec&) const = default;
};

struct Scenario {
  // Hand-authored and unversioned scenarios historically use profile-derived TCP settings.
  std::uint32_t gen_version = 3;
  std::uint64_t seed = 0;  // master seed of every random stream of the run
  NodeKind nodes = NodeKind::stack;
  Plant plant = Plant::none;
  std::uint64_t plant_after_events = 1000;
  Time start{1'000'000'000};       // virtual time of the run start (>= 1 s)
  Duration app_idle_timeout{};     // applications close after this long without progress (§7.3)
  std::vector<NodeSpec> node;      // node i has address node_addr(i) and name "a", "b", ...
  std::vector<LinkSpec> link;
  std::vector<PathSpec> path;      // one per ordered pair of nodes
  std::vector<ConnSpec> conn;
  std::vector<UdpSpec> udp;
  std::vector<PingSpec> ping;

  // Some link corrupts with the garbage class (checkers relaxed, §7.3).
  [[nodiscard]] bool has_garbage() const noexcept;
  // Some link flips bits (ingress pcaps then hold malformed frames, §7.4).
  [[nodiscard]] bool has_bitflips() const noexcept;

  bool operator==(const Scenario&) const = default;
};

// "a", "b", ... for node index 0, 1, ...
[[nodiscard]] std::string node_name(std::uint32_t index);

struct GenOptions {
  // Draw from an extra labelled stream first (test: adding a consumer must not
  // change the scenario).
  bool probe_extra_label = false;
  std::uint32_t version = gen_version;
};

// The scenario of `seed` (ranges of DESIGN §7.2).
[[nodiscard]] Scenario generate_scenario(std::uint64_t seed, NodeKind nodes = NodeKind::stack,
                                         const GenOptions& opt = {});

// Two nodes with one segment per direction, `ab` and `ba`, and no workload
// (tests add traffic).
[[nodiscard]] Scenario two_node_scenario(std::uint64_t seed, const LinkParams& ab,
                                         const LinkParams& ba);

// Serialisation: one `key=value` per line, every key written. parse_kv
// accepts blank lines and `#` comments, takes defaults for missing keys and
// rejects unknown keys, malformed values and a gen_version above ours.
[[nodiscard]] std::string to_kv(const Scenario& s);
[[nodiscard]] std::expected<Scenario, std::string> parse_kv(std::string_view text);

// Fixed-point log-uniform integer in [lo, hi] (lo >= 1): the range is cut at
// lo * 2^(k/16) and a piece is chosen uniformly, then a value uniformly inside
// it, so each sixteenth of an octave is equally likely.
[[nodiscard]] std::uint64_t log_uniform(Rng& rng, std::uint64_t lo, std::uint64_t hi);

[[nodiscard]] std::string_view to_string(NodeKind k) noexcept;
[[nodiscard]] std::string_view to_string(Plant p) noexcept;
[[nodiscard]] std::string_view to_string(CloseMode m) noexcept;
[[nodiscard]] std::optional<TestFault> test_fault_from_string(std::string_view s) noexcept;
[[nodiscard]] std::optional<NodeKind> node_kind_from_string(std::string_view s) noexcept;

}  // namespace utcp::sim
