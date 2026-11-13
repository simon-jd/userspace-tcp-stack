// The discrete-event World (DESIGN §7.1): nodes, link segments, the event
// queue, the checkers and the run digest.
//
// Events are datagrams at the entrance of a segment, node wake-ups (one per
// node, re-keyed when its next_deadline() changes; stale ones carry an old
// generation and are skipped), application wake-ups and delayed host drains.
// Virtual time jumps from event to event.
//
// After every node call the World calls advance(now) unless the call was
// one, lets the node's applications act (run_apps), drains pop_transmit()
// into link storage (at most host_drain_max per wake-up, the rest after
// host_delay), runs debug_check(), and calls advance(now) again while
// next_deadline() <= now. So every application action follows an advance(t)
// at its instant (§7.1). Trace events reach the checkers as the stack emits
// them.
//
// The run ends when the workload has finished and every node has settled
// (no connection timer armed, nothing queued, no datagram on a link), or at
// the first violation.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "utcp/random.hpp"
#include "utcp/sim/checkers.hpp"
#include "utcp/sim/digest.hpp"
#include "utcp/sim/event_queue.hpp"
#include "utcp/sim/link.hpp"
#include "utcp/sim/node.hpp"
#include "utcp/sim/pcap_writer.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/time.hpp"
#include "utcp/trace.hpp"

namespace utcp::sim {

// A datagram crossing a node's interface (tests, tools).
struct WireEvent {
  std::uint32_t node = 0;
  bool egress = false;  // handed out by the node (before impairment); else delivered to it
  Time t;
  std::span<const std::byte> datagram;
};

struct WorldOptions {
  // `livelock` limits (§7.1).
  std::uint64_t max_events_per_instant = 1'000'000;
  std::uint64_t max_events = 200'000'000;
  // pcap files <pcap_dir>/<node>.egress.pcap and .ingress.pcap; empty: none.
  std::string pcap_dir;
  std::uint32_t snaplen = 65535;
  // Every trace event, with its node (utcp-sim --trace).
  std::function<void(std::uint32_t node, const TraceEvent&)> trace_out;
  // Every datagram at a node interface.
  std::function<void(const WireEvent&)> on_wire;
};

struct RunResult {
  std::uint64_t seed = 0;
  Verdict verdict = Verdict::ok;
  std::vector<Violation> violations;
  Time start, end;              // virtual times
  std::uint64_t events = 0;     // events processed, re-advances included
  std::uint64_t packets = 0;    // datagrams handed out by the nodes
  std::uint64_t bytes = 0;
  std::uint64_t digest = 0;
  std::vector<LinkStats> links;  // per Scenario::link
};

class World final : public SimContext {
public:
  // Nodes built from the scenario (StackNode or SyntheticNode).
  explicit World(const Scenario& s, WorldOptions opt = {});
  // Nodes given by the caller (tests); nodes[i] takes the place of node i.
  World(const Scenario& s, std::vector<std::unique_ptr<Node>> nodes, WorldOptions opt = {});
  ~World() override;
  World(const World&) = delete;
  World& operator=(const World&) = delete;

  // Runs to the end; call once.
  RunResult run();

  // The live digest and event count, for utcp-sim's SIGABRT handler (§7.2):
  // no allocation, no locks.
  [[nodiscard]] std::uint64_t digest_now() const noexcept { return digest_.value(); }
  [[nodiscard]] std::uint64_t events() const noexcept { return events_; }

  [[nodiscard]] std::uint32_t node_count() const noexcept {
    return static_cast<std::uint32_t>(nodes_.size());
  }
  [[nodiscard]] Node& node(std::uint32_t i) { return *nodes_.at(i).node; }
  [[nodiscard]] const Link& link(std::uint32_t i) const { return links_.at(i); }
  [[nodiscard]] InFlightChecker& inflight() noexcept { return inflight_; }
  [[nodiscard]] TerminationChecker& termination() noexcept { return termination_; }

  // --- SimContext.
  [[nodiscard]] Time now() const override { return now_; }
  [[nodiscard]] const Scenario& scenario() const override { return s_; }
  [[nodiscard]] const Seed& master_seed() const override { return master_; }
  void on_trace(std::uint32_t node, const TraceEvent& e) override;
  void on_socket_event(std::uint32_t node, const SocketEvent& e) override;
  void on_progress() override;
  [[nodiscard]] StreamChecker& stream() override { return stream_; }
  void on_app_close(std::uint32_t node, std::uint32_t conn_id) override;
  void violation(Verdict kind, std::string message) override;
  void note_error(std::uint32_t node, std::string_view what) override;

private:
  struct NodeState {
    std::unique_ptr<Node> node;
    Time wake_at = Time::never();  // scheduled node_wake
    std::uint64_t wake_gen = 0;
    Time app_at = Time::never();   // scheduled app_wake
    std::uint64_t app_gen = 0;
    bool drain_pending = false;
    std::uint64_t drain_gen = 0;
    std::uint32_t drained = 0;     // in the current wake-up
    std::uint32_t drain_max = 0;   // 0 = all
    Duration host_delay{};
    std::optional<PcapWriter> egress, ingress;
  };
  class SegmentSink;

  void init();
  void start_wakeup(std::uint32_t n);
  void deliver(std::uint32_t n, std::span<const std::byte> d);
  void after_call(std::uint32_t n, bool advanced);
  void settle(std::uint32_t n);
  void drain(std::uint32_t n);
  void reschedule(std::uint32_t n);
  void enter(std::uint32_t path, std::uint32_t seg, std::span<const std::byte> d);
  void schedule_packet(Time t, std::uint32_t path, std::uint32_t seg, std::span<const std::byte> d);
  void schedule_reply(Time t, std::uint32_t path, std::uint32_t seg, std::span<const std::byte> d);
  [[nodiscard]] std::optional<std::uint32_t> route(std::uint32_t from,
                                                   std::span<const std::byte> d) const;
  bool count_event();
  void check_plant();
  [[nodiscard]] bool workload_finished() const;
  [[nodiscard]] bool settled() const;
  void finish_checks();
  [[nodiscard]] std::optional<CloseMode> design(std::uint32_t node, const FourTuple& t) const;

  // Packet storage: datagrams in flight are copies, so node buffers return at
  // once (§7.1).
  std::uint64_t store(std::span<const std::byte> d);
  void release(std::uint64_t id);

  Scenario s_;
  WorldOptions opt_;
  Seed master_;
  std::vector<NodeState> nodes_;
  std::vector<Link> links_;
  EventQueue queue_;
  std::vector<std::vector<std::byte>> packets_;
  std::vector<std::uint64_t> free_packets_;
  std::uint64_t in_flight_ = 0;  // datagrams on links
  std::vector<std::byte> cur_;   // the datagram of the current packet event
  std::vector<std::vector<std::uint32_t>> path_of_;  // [from][to] -> Scenario::path index

  StreamChecker stream_;
  TerminationChecker termination_;
  InFlightChecker inflight_;
  ProgressChecker progress_;
  RunDigest digest_;

  Time now_;
  Time instant_;  // the instant instant_events_ counts
  std::uint64_t events_ = 0, instant_events_ = 0;
  std::uint64_t tx_packets_ = 0, tx_bytes_ = 0;
  bool workload_done_ = false;
  Time quiesce_deadline_ = Time::never();
  bool stop_ = false;
  bool ran_ = false;
  bool planted_ = false;
  std::vector<Violation> violations_;
};

// The node a scenario describes: StackNode for NodeKind::stack, SyntheticNode
// for NodeKind::synthetic.
[[nodiscard]] std::unique_ptr<Node> make_node(const Scenario& s, std::uint32_t index);

// Convenience: World(s, opt).run().
[[nodiscard]] RunResult run_scenario(const Scenario& s, WorldOptions opt = {});

}  // namespace utcp::sim
