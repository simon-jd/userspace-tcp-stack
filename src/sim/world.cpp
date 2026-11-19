#include "utcp/sim/world.hpp"

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <utility>

#include "core/wire/ipv4.hpp"
#include "utcp/check.hpp"
#include "utcp/sim/datagram.hpp"
#include "utcp/sim/stack_node.hpp"
#include "utcp/sim/synthetic_node.hpp"

namespace utcp::sim {

namespace {

constexpr std::uint32_t no_path = std::numeric_limits<std::uint32_t>::max();
constexpr std::uint32_t world_node = std::numeric_limits<std::uint32_t>::max();

// Planted hang: a loop with a side effect, so it is not undefined behaviour.
volatile std::uint64_t hang_counter = 0;

}  // namespace

// The sink of one segment of one path: emitted datagrams enter the next
// segment (or reach the destination node); ICMP errors from the router at
// the segment's entrance go back along the reverse path.
class World::SegmentSink final : public LinkSink {
public:
  SegmentSink(World& w, std::uint32_t path, std::uint32_t seg) noexcept
      : w_(w), path_(path), seg_(seg) {}

  void deliver(Time t, std::span<const std::byte> d, const DeliveryInfo& info) override {
    static_cast<void>(info);
    w_.schedule_packet(t, path_, seg_ + 1, d);
  }
  void reply(Time t, std::span<const std::byte> icmp) override {
    w_.schedule_reply(t, path_, seg_, icmp);
  }

private:
  World& w_;
  std::uint32_t path_, seg_;
};

World::World(const Scenario& s, WorldOptions opt) : World(s, {}, std::move(opt)) {}

World::World(const Scenario& s, std::vector<std::unique_ptr<Node>> nodes, WorldOptions opt)
    : s_(s),
      opt_(std::move(opt)),
      master_(Seed::from_u64(s.seed)),
      stream_(master_),
      progress_(Duration{}),
      now_(s.start),
      instant_(s.start) {
  inflight_.set_strict_fast_rexmit(opt_.strict_fast_rexmit);
  if (nodes.empty()) {
    for (std::uint32_t i = 0; i < s_.node.size(); ++i) {
      nodes.push_back(make_node(s_, i));
    }
  }
  UTCP_CHECK(nodes.size() == s_.node.size());
  Duration bound{};
  for (std::uint32_t i = 0; i < nodes.size(); ++i) {
    const TcpConfig* effective = nodes[i]->effective_tcp_config();
    const TcpConfig conf = effective ? *effective : stack_config(s, i).tcp;
    inflight_.set_config(i, conf);
    pacing_.set_config(i, conf);
    bound = std::max(bound, progress_bound(conf));
    NodeState ns;
    ns.node = std::move(nodes[i]);
    nodes_.push_back(std::move(ns));
  }
  progress_ = ProgressChecker(bound);
  links_.reserve(s_.link.size());
  for (const LinkSpec& l : s_.link) {
    links_.emplace_back(l.params, master_, l.name);
  }
  path_of_.assign(nodes_.size(), std::vector<std::uint32_t>(nodes_.size(), no_path));
  for (std::uint32_t p = 0; p < s_.path.size(); ++p) {
    const PathSpec& ps = s_.path[p];
    UTCP_CHECK(ps.from < nodes_.size() && ps.to < nodes_.size());
    for (const std::uint32_t l : ps.links) {
      UTCP_CHECK(l < links_.size());
    }
    path_of_[ps.from][ps.to] = p;
  }
}

World::~World() = default;

std::unique_ptr<Node> make_node(const Scenario& s, std::uint32_t index) {
  if (s.nodes == NodeKind::synthetic) {
    return std::make_unique<SyntheticNode>(s, index);
  }
  return std::make_unique<StackNode>(s, index);
}

RunResult run_scenario(const Scenario& s, WorldOptions opt) {
  World w(s, std::move(opt));
  return w.run();
}

// --- SimContext.

void World::on_trace(std::uint32_t node, const TraceEvent& e) {
  termination_.on_trace(node, e);
  if (auto v = inflight_.on_trace(node, e)) {
    violation(Verdict::inflight, std::move(*v));
  }
  if (auto v = pacing_.on_trace(node, e)) violation(Verdict::pacing, std::move(*v));
  if (e.kind == TraceKind::state) {
    progress_.on_progress(now_);
  }
  if (opt_.trace_out) {
    opt_.trace_out(node, e);
  }
}

void World::on_socket_event(std::uint32_t node, const SocketEvent& e) {
  digest_.socket_event(node, now_, e.h.slot, e.h.gen, static_cast<std::uint8_t>(e.h.proto),
                       e.events);
}

void World::on_progress() { progress_.on_progress(now_); }

void World::on_app_close(std::uint32_t node, std::uint32_t conn_id) {
  termination_.on_app_close(node, conn_id, now_);
}

void World::violation(Verdict kind, std::string message) {
  digest_.text(world_node, now_, to_string(kind), message);
  violations_.push_back(Violation{kind, now_, std::move(message)});
  stop_ = true;
}

void World::note_error(std::uint32_t node, std::string_view what) {
  digest_.text(node, now_, "error", what);
}

// --- Packets.

std::uint64_t World::store(std::span<const std::byte> d) {
  std::uint64_t id = 0;
  if (!free_packets_.empty()) {
    id = free_packets_.back();
    free_packets_.pop_back();
  } else {
    id = packets_.size();
    packets_.emplace_back();
  }
  packets_[id].assign(d.begin(), d.end());
  ++in_flight_;
  return id;
}

void World::release(std::uint64_t id) {
  free_packets_.push_back(id);
  --in_flight_;
}

void World::schedule_packet(Time t, std::uint32_t path, std::uint32_t seg,
                            std::span<const std::byte> d) {
  const std::uint64_t id = store(d);
  queue_.push(std::max(t, now_), EventType::packet, path, seg, id);
}

void World::schedule_reply(Time t, std::uint32_t path, std::uint32_t seg,
                           std::span<const std::byte> d) {
  // The router at the entrance of segment `seg` of path P (a -> b) has
  // crossed P's segments 0..seg-1; its reply crosses the last `seg` segments
  // of the reverse path (b -> a).
  const PathSpec& p = s_.path[path];
  const std::uint32_t rp = path_of_[p.to][p.from];
  if (rp == no_path) {
    return;
  }
  const auto rn = static_cast<std::uint32_t>(s_.path[rp].links.size());
  schedule_packet(t, rp, rn >= seg ? rn - seg : 0, d);
}

void World::enter(std::uint32_t path, std::uint32_t seg, std::span<const std::byte> d) {
  const PathSpec& p = s_.path[path];
  if (seg >= p.links.size()) {
    schedule_packet(now_, path, seg, d);
    return;
  }
  SegmentSink sink(*this, path, seg);
  links_[p.links[seg]].send(now_, d, sink);
}

std::optional<std::uint32_t> World::route(std::uint32_t from, std::span<const std::byte> d) const {
  if (d.size() < wire::ipv4_header_len || (wire::load_u8(d, 0) >> 4) != 4) {
    return std::nullopt;
  }
  const Ipv4Addr dst{wire::load_be32(d, 16)};
  for (std::uint32_t i = 0; i < nodes_.size(); ++i) {
    if (i != from && node_addr(i) == dst && path_of_[from][i] != no_path) {
      return path_of_[from][i];
    }
  }
  return std::nullopt;
}

// --- Node calls.

void World::start_wakeup(std::uint32_t n) { nodes_[n].drained = 0; }

void World::deliver(std::uint32_t n, std::span<const std::byte> d) {
  NodeState& ns = nodes_[n];
  if (ns.ingress) {
    ns.ingress->write(now_, d);
  }
  if (opt_.on_wire) {
    opt_.on_wire(WireEvent{n, false, now_, d});
  }
  digest_.delivery(n, now_, d);
  inflight_.on_ingress(n, d);
  ns.node->receive(now_, d);
  after_call(n, false);
  settle(n);
}

void World::after_call(std::uint32_t n, bool advanced) {
  Node& node = *nodes_[n].node;
  // An application action is always preceded by advance(now) (§7.1): after a
  // receive too, since a StackNode's applications act on every call (they
  // poll events and pump every connection). Timers due at the arrival instant
  // and blocked connections the receive can resume (§3.4) go first; with
  // nothing due, advance(now) does nothing.
  if (!advanced) {
    node.advance(now_);
  }
  node.run_apps(now_);
  drain(n);
  node.debug_check();
}

void World::drain(std::uint32_t n) {
  NodeState& ns = nodes_[n];
  for (;;) {
    if (ns.drain_max != 0 && ns.drained >= ns.drain_max) {
      if (!ns.drain_pending) {
        ns.drain_pending = true;
        ++ns.drain_gen;
        queue_.push(now_ + ns.host_delay, EventType::host_drain, n, 0, ns.drain_gen);
      }
      return;
    }
    std::optional<TxPacket> pkt = ns.node->pop_transmit();
    if (!pkt) {
      return;
    }
    ++ns.drained;
    const std::span<const std::byte> d = pkt->buf.bytes();
    ++tx_packets_;
    tx_bytes_ += d.size();
    digest_.packet(n, now_, d);
    if (ns.egress) {
      ns.egress->write(now_, d);
    }
    if (opt_.on_wire) {
      opt_.on_wire(WireEvent{n, true, now_, d});
    }
    if (auto v = inflight_.on_egress(n, d)) {
      violation(Verdict::inflight, std::move(*v));
    }
    if (const auto path = route(n, d)) {
      enter(*path, 0, d);  // copied into link storage; the buffer returns now
    }
  }
}

void World::settle(std::uint32_t n) {
  Node& node = *nodes_[n].node;
  while (!stop_) {
    if (node.next_deadline() > now_) {
      return;
    }
    const std::uint64_t a0 = node.activity();
    node.advance(now_);
    after_call(n, true);
    if (!count_event()) {
      return;
    }
    if (node.next_deadline() <= now_ && node.activity() == a0) {
      violation(Verdict::stuck, "node " + node_name(n) +
                                    ": advance() fired nothing and left next_deadline() <= now");
      return;
    }
  }
}

void World::reschedule(std::uint32_t n) {
  NodeState& ns = nodes_[n];
  const Time d = ns.node->next_deadline();
  if (d != ns.wake_at) {
    ns.wake_at = d;
    ++ns.wake_gen;
    if (!d.is_never()) {
      queue_.push(std::max(d, now_), EventType::node_wake, n, 0, ns.wake_gen);
    }
  }
  const Time a = ns.node->next_app_deadline();
  if (a != ns.app_at) {
    ns.app_at = a;
    ++ns.app_gen;
    if (!a.is_never()) {
      queue_.push(std::max(a, now_), EventType::app_wake, n, 0, ns.app_gen);
    }
  }
}

// --- The loop.

bool World::count_event() {
  ++events_;
  if (now_ != instant_) {
    instant_ = now_;
    instant_events_ = 0;
  }
  ++instant_events_;
  if (instant_events_ > opt_.max_events_per_instant) {
    violation(Verdict::livelock, "more than " + std::to_string(opt_.max_events_per_instant) +
                                     " events at one instant");
    return false;
  }
  if (events_ > opt_.max_events) {
    violation(Verdict::livelock,
              "more than " + std::to_string(opt_.max_events) + " events in the run");
    return false;
  }
  check_plant();
  return !stop_;
}

void World::check_plant() {
  if (events_ != s_.plant_after_events) {
    return;
  }
  switch (s_.plant) {
    case Plant::none:
      break;
    case Plant::fail:
      planted_ = true;
      violation(Verdict::planted, "planted failure after " + std::to_string(events_) + " events");
      break;
    case Plant::abort:
      std::abort();
    case Plant::segv:
      std::raise(SIGSEGV);
      std::abort();  // not reached unless SIGSEGV is ignored
    case Plant::hang:
      for (;;) {
        hang_counter = hang_counter + 1;
      }
  }
}

bool World::workload_finished() const {
  return std::ranges::all_of(nodes_, [](const NodeState& ns) { return ns.node->finished(); });
}

bool World::settled() const {
  if (in_flight_ != 0) {
    return false;
  }
  for (const NodeState& ns : nodes_) {
    if (ns.drain_pending || !ns.node->next_app_deadline().is_never()) {
      return false;
    }
    if (ns.node->next_deadline().is_never()) {
      continue;
    }
    const auto u = ns.node->debug_usage();
    if (!u || !usage_settled(*u)) {
      return false;
    }
  }
  return true;
}

std::optional<CloseMode> World::design(std::uint32_t node, const FourTuple& t) const {
  for (const ConnSpec& c : s_.conn) {
    const std::uint32_t server = 1 - c.client;
    if (c.mode == CloseMode::simultaneous) {
      const bool mine = (node == c.client && t.local.port == c.client_port &&
                         t.remote.port == c.server_port) ||
                        (node == server && t.local.port == c.server_port &&
                         t.remote.port == c.client_port);
      if (mine) {
        return c.mode;
      }
      continue;
    }
    // A fixed client port (shared listeners) identifies the connection.
    const bool client_side = node == c.client && t.remote.port == c.server_port &&
                             (c.client_port == 0 || t.local.port == c.client_port);
    const bool server_side = node == server && t.local.port == c.server_port &&
                             (c.client_port == 0 || t.remote.port == c.client_port);
    if (client_side || server_side) {
      return c.mode;
    }
  }
  return std::nullopt;
}

void World::finish_checks() {
  for (Violation& v : termination_.finish(now_)) {
    digest_.text(world_node, now_, to_string(v.kind), v.message);
    violations_.push_back(std::move(v));
  }
  for (std::uint32_t n = 0; n < nodes_.size(); ++n) {
    if (const auto u = nodes_[n].node->debug_usage()) {
      if (auto leak = usage_leaks(*u)) {
        violation(Verdict::leak, "node " + node_name(n) + " holds " + *leak);
      }
    }
  }
  if (s_.plant == Plant::fail && !planted_) {
    planted_ = true;
    violation(Verdict::planted, "planted failure at the end of the run");
  }
  stop_ = true;
}

void World::init() {
  stream_.set_enabled(!s_.has_garbage());
  termination_.set_relaxed(s_.has_garbage());
  termination_.set_design(
      [this](std::uint32_t node, const FourTuple& t) { return design(node, t); });
  progress_.on_progress(now_);
  for (std::uint32_t n = 0; n < nodes_.size(); ++n) {
    NodeState& ns = nodes_[n];
    ns.drain_max = s_.node[n].host_drain_max;
    ns.host_delay = s_.node[n].host_delay;
    if (!opt_.pcap_dir.empty()) {
      const std::string base = opt_.pcap_dir + "/" + node_name(n);
      for (const bool egress : {true, false}) {
        auto w = PcapWriter::open(base + (egress ? ".egress.pcap" : ".ingress.pcap"), opt_.snaplen);
        if (!w) {
          std::fprintf(stderr, "utcp-sim: %s\n", w.error().c_str());
          continue;
        }
        (egress ? ns.egress : ns.ingress).emplace(std::move(*w));
      }
    }
    ns.node->attach(*this, n);
  }
  // Every node starts with advance(start); applications act after it.
  for (std::uint32_t n = 0; n < nodes_.size() && !stop_; ++n) {
    start_wakeup(n);
    nodes_[n].node->advance(now_);
    after_call(n, true);
    settle(n);
    reschedule(n);
  }
}

RunResult World::run() {
  UTCP_CHECK(!ran_);
  ran_ = true;
  init();
  while (!stop_) {
    if (!workload_done_ && workload_finished()) {
      workload_done_ = true;
      quiesce_deadline_ = now_ + progress_.bound();
    }
    if (workload_done_ && settled()) {
      finish_checks();
      break;
    }
    if (queue_.empty()) {
      if (!workload_done_) {
        violation(Verdict::progress, "no events left while the workload is unfinished");
      } else {
        finish_checks();
      }
      break;
    }
    const SimEvent e = queue_.top();
    if (!workload_done_ && e.t > progress_.deadline()) {
      now_ = progress_.deadline();
      violation(Verdict::progress, "no progress for " +
                                       std::to_string(progress_.bound().count() / 1'000'000'000) +
                                       " s with the workload unfinished");
      break;
    }
    if (workload_done_ && e.t > quiesce_deadline_) {
      now_ = quiesce_deadline_;
      std::string held;
      for (std::uint32_t n = 0; n < nodes_.size(); ++n) {
        if (const auto u = nodes_[n].node->debug_usage()) {
          if (auto leak = usage_leaks(*u)) {
            held += " node " + node_name(n) + " holds " + *leak + ";";
          }
        }
      }
      violation(Verdict::leak, "not quiescent " +
                                   std::to_string(progress_.bound().count() / 1'000'000'000) +
                                   " s after the workload ended;" + held);
      break;
    }
    queue_.pop();
    UTCP_CHECK(e.t >= now_);
    const std::uint32_t n = e.a;
    switch (e.type) {
      case EventType::packet: {
        cur_.swap(packets_[e.c]);
        release(e.c);
        now_ = e.t;
        if (!count_event()) {
          break;
        }
        const PathSpec& p = s_.path[e.a];
        if (e.b < p.links.size()) {
          SegmentSink sink(*this, e.a, e.b);
          links_[p.links[e.b]].send(now_, cur_, sink);
        } else {
          start_wakeup(p.to);
          deliver(p.to, cur_);
          reschedule(p.to);
        }
        break;
      }
      case EventType::node_wake: {
        NodeState& ns = nodes_[n];
        if (e.c != ns.wake_gen) {
          break;  // stale
        }
        ns.wake_at = Time::never();
        now_ = e.t;
        if (!count_event()) {
          break;
        }
        start_wakeup(n);
        settle(n);
        reschedule(n);
        break;
      }
      case EventType::app_wake: {
        NodeState& ns = nodes_[n];
        if (e.c != ns.app_gen) {
          break;
        }
        ns.app_at = Time::never();
        now_ = e.t;
        if (!count_event()) {
          break;
        }
        start_wakeup(n);
        ns.node->advance(now_);
        after_call(n, true);
        settle(n);
        reschedule(n);
        break;
      }
      case EventType::host_drain: {
        NodeState& ns = nodes_[n];
        if (e.c != ns.drain_gen || !ns.drain_pending) {
          break;
        }
        ns.drain_pending = false;
        now_ = e.t;
        if (!count_event()) {
          break;
        }
        start_wakeup(n);
        ns.node->advance(now_);
        after_call(n, true);
        settle(n);
        reschedule(n);
        break;
      }
    }
  }

  RunResult r;
  r.seed = s_.seed;
  r.verdict = violations_.empty() ? Verdict::ok : violations_.front().kind;
  digest_.text(world_node, now_, "verdict", to_string(r.verdict));
  r.violations = violations_;
  r.start = s_.start;
  r.end = now_;
  r.events = events_;
  r.packets = tx_packets_;
  r.bytes = tx_bytes_;
  r.digest = digest_.value();
  for (const Link& l : links_) {
    r.links.push_back(l.stats());
  }
  return r;
}

}  // namespace utcp::sim
