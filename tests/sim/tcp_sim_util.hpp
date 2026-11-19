// Shared helpers of the directed TCP scenarios in tests/sim/tcp_*_test.cpp
// (m1-tcp-robust acceptance test 6): impaired links, a node wrapper that
// sees, drops and injects datagrams, a node that runs a test-written
// application against a Stack, and a runner that records the trace, the TCP
// segments on the wire and each stack's counters.
//
// Everything is in an anonymous namespace: each test file gets its own copy
// (tests/sim links into one binary, M1-TASKS rules).
#pragma once

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "core/wire/tcp.hpp"
#include "utcp/config.hpp"
#include "utcp/sim/checkers.hpp"
#include "utcp/sim/datagram.hpp"
#include "utcp/sim/node.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/sim/stack_node.hpp"
#include "utcp/sim/world.hpp"
#include "utcp/stack.hpp"
#include "utcp/stats.hpp"
#include "utcp/trace.hpp"

namespace utcp::sim {
namespace {

using namespace std::chrono_literals;

// A one-way path of `delay` without impairment.
inline LinkParams clean_link(Duration delay) {
  LinkParams p;
  p.delay = delay;
  return p;
}

// Bernoulli loss plus reordering (jitter up to half the delay, reorder
// allowed) and optional duplication (the copy one delay later).
inline LinkParams impaired(Duration delay, std::uint32_t loss_ppm, std::uint32_t dup_ppm = 0) {
  LinkParams p;
  p.delay = delay;
  p.jitter = delay / 2;
  p.allow_reorder = true;
  p.loss_ppm = loss_ppm;
  p.dup_ppm = dup_ppm;
  p.dup_extra_delay = delay;
  return p;
}

// A TCP segment seen at a node's interface.
struct Seg {
  std::uint32_t node = 0;  // the sender (egress) or the receiver (ingress)
  bool egress = false;
  Time t;
  Endpoint src, dst;
  wire::TcpHeader h;
  wire::TcpOptions opt;
  std::uint32_t len = 0;  // payload bytes

  [[nodiscard]] bool has(std::uint16_t f) const noexcept { return (h.flags & f) != 0; }
  // Sequence space the segment occupies (payload, SYN and FIN).
  [[nodiscard]] std::uint32_t seq_len() const noexcept {
    return len + (has(wire::tcp_syn) ? 1u : 0u) + (has(wire::tcp_fin) ? 1u : 0u);
  }
};

[[nodiscard]] inline std::optional<Seg> parse_seg(std::uint32_t node, bool egress, Time t,
                                                  std::span<const std::byte> d) {
  const auto p = parse_tcp_packet(d);
  if (!p) {
    return std::nullopt;
  }
  Seg s;
  s.node = node;
  s.egress = egress;
  s.t = t;
  s.src = Endpoint{p->ip.src, p->tcp.h.sport};
  s.dst = Endpoint{p->ip.dst, p->tcp.h.dport};
  s.h = p->tcp.h;
  s.opt = p->tcp.opt;
  s.len = static_cast<std::uint32_t>(p->tcp.payload.size());
  return s;
}

// A Node around another node (a StackNode or an AppNode): hooks see every
// datagram the node hands out and every datagram delivered to it and may
// drop it; inject_at() delivers a crafted datagram to the node's stack, and
// records the stack's counters just before and after, so a test can tell
// what the stack did with exactly that datagram.
class Tap final : public Node {
public:
  using Hook = std::function<bool(Tap&, Time, std::span<const std::byte>)>;

  Tap(std::unique_ptr<Node> inner, Stack* stack) : inner_(std::move(inner)), stack_(stack) {}

  [[nodiscard]] Node& inner() noexcept { return *inner_; }
  [[nodiscard]] Stack& stack() noexcept { return *stack_; }
  [[nodiscard]] Time now() const noexcept { return now_; }

  // false drops the datagram.
  Hook egress, ingress;

  struct Injected {
    Time at;
    std::vector<std::byte> bytes;
    std::function<std::vector<std::byte>()> build;  // if set, makes `bytes` at delivery
    bool delivered = false;
    Time t;  // when delivered
    StackStats before, after;
  };
  // Delivers `d` at the first advance at or after `t`. Returns its index.
  std::size_t inject_at(Time t, std::vector<std::byte> d) {
    injected_.push_back(Injected{t, std::move(d), {}, false, Time{}, {}, {}});
    return injected_.size() - 1;
  }
  // As above, with the datagram built at delivery time (from what the test
  // has seen on the wire by then).
  std::size_t inject_at(Time t, std::function<std::vector<std::byte>()> build) {
    injected_.push_back(Injected{t, {}, std::move(build), false, Time{}, {}, {}});
    return injected_.size() - 1;
  }
  [[nodiscard]] const std::vector<Injected>& injected() const noexcept { return injected_; }
  [[nodiscard]] std::uint64_t dropped_egress() const noexcept { return dropped_egress_; }
  [[nodiscard]] std::uint64_t dropped_ingress() const noexcept { return dropped_ingress_; }

  void receive(Time now, std::span<const std::byte> d) override {
    now_ = now;
    if (ingress && !ingress(*this, now, d)) {
      ++dropped_ingress_;
      ++activity_;
      return;
    }
    inner_->receive(now, d);
  }
  void advance(Time now) override {
    now_ = now;
    for (Injected& i : injected_) {
      if (!i.delivered && i.at <= now) {
        i.delivered = true;
        i.t = now;
        if (i.build) {
          i.bytes = i.build();
        }
        i.before = stack_->stats();
        inner_->receive(now, i.bytes);
        i.after = stack_->stats();
        ++activity_;
      }
    }
    inner_->advance(now);
  }
  std::optional<TxPacket> pop_transmit() override {
    for (;;) {
      auto p = inner_->pop_transmit();
      if (!p || !egress || egress(*this, now_, p->buf.bytes())) {
        return p;
      }
      ++dropped_egress_;
      ++activity_;
    }
  }
  [[nodiscard]] Time next_deadline() const override {
    Time t = inner_->next_deadline();
    for (const Injected& i : injected_) {
      if (!i.delivered) {
        t = std::min(t, i.at);
      }
    }
    return t;
  }
  void attach(SimContext& ctx, std::uint32_t index) override { inner_->attach(ctx, index); }
  [[nodiscard]] Time next_app_deadline() const override { return inner_->next_app_deadline(); }
  void run_apps(Time now) override {
    now_ = now;
    inner_->run_apps(now);
  }
  [[nodiscard]] bool finished() const override { return inner_->finished(); }
  [[nodiscard]] const TcpConfig* effective_tcp_config() const override {
    return inner_->effective_tcp_config();
  }
  void debug_check() const override { inner_->debug_check(); }
  [[nodiscard]] std::optional<StackUsage> debug_usage() const override {
    return inner_->debug_usage();
  }
  [[nodiscard]] std::uint64_t activity() const override {
    return inner_->activity() + activity_;
  }

private:
  std::unique_ptr<Node> inner_;
  Stack* stack_;
  Time now_{};
  std::vector<Injected> injected_;
  std::uint64_t dropped_egress_ = 0, dropped_ingress_ = 0, activity_ = 0;
};

// A Stack driven by a test-written application: `script` runs on every
// run_apps call (after the World's advance at that instant, §7.1) and at the
// times given to wake_at(). The script reports application closes through
// closing() so the TerminationChecker accepts the RSTs they cause, and sets
// `done` when it has finished.
class AppNode final : public Node, public TraceSink {
public:
  AppNode(const Scenario& s, std::uint32_t index,
          const std::function<void(StackConfig&)>& tweak = {})
      : index_(index), stack_(make_config(s, index, tweak)) {}

  [[nodiscard]] Stack& stack() noexcept { return stack_; }
  [[nodiscard]] SimContext& ctx() noexcept { return *ctx_; }
  [[nodiscard]] std::uint32_t index() const noexcept { return index_; }

  std::function<void(AppNode&, Time)> script;
  bool done = false;

  void wake_at(Time t) { wakes_.push_back(t); }
  // The application is about to close or abort `h`.
  void closing(Handle h) {
    if (const auto info = stack_.tcp_info(h)) {
      ctx_->on_app_close(index_, info->conn_id);
    }
  }

  void on_event(const TraceEvent& e) override {
    ++activity_;
    if (ctx_ != nullptr) {
      ctx_->on_trace(index_, e);
    }
  }

  void receive(Time now, std::span<const std::byte> d) override { stack_.receive(now, d); }
  void advance(Time now) override { stack_.advance(now); }
  std::optional<TxPacket> pop_transmit() override {
    auto p = stack_.pop_transmit();
    if (p) {
      ++activity_;
    }
    return p;
  }
  [[nodiscard]] Time next_deadline() const override { return stack_.next_deadline(); }
  void attach(SimContext& ctx, std::uint32_t index) override {
    static_cast<void>(index);
    ctx_ = &ctx;
    stack_.set_trace_sink(this);
  }
  [[nodiscard]] Time next_app_deadline() const override {
    Time t = Time::never();
    for (const Time w : wakes_) {
      t = std::min(t, w);
    }
    return t;
  }
  void run_apps(Time now) override {
    std::erase_if(wakes_, [&](Time w) { return w <= now; });
    if (script) {
      script(*this, now);
    }
  }
  [[nodiscard]] bool finished() const override { return done; }
  [[nodiscard]] const TcpConfig* effective_tcp_config() const override {
    return &stack_.config().tcp;
  }
  void debug_check() const override { stack_.debug_check(); }
  [[nodiscard]] std::optional<StackUsage> debug_usage() const override {
    return stack_.debug_usage();
  }
  [[nodiscard]] std::uint64_t activity() const override { return activity_; }

private:
  static StackConfig make_config(const Scenario& s, std::uint32_t index,
                                 const std::function<void(StackConfig&)>& tweak) {
    StackConfig c = stack_config(s, index);
    if (tweak) {
      tweak(c);
    }
    return c;
  }

  std::uint32_t index_;
  Stack stack_;
  SimContext* ctx_ = nullptr;
  std::vector<Time> wakes_;
  std::uint64_t activity_ = 0;
};

// An AppNode application: connects to node `server`:5000 as workload
// connection `conn` and writes its pattern data as fast as the send buffer
// takes it, then shuts down writing, reads to EOF and closes. The server's
// StackNode runs the matching ConnSpec and checks the bytes. A partly
// accepted write keeps its remainder for the next call, so each byte is
// generated once.
struct BulkClient {
  std::uint32_t conn = 0;
  std::uint32_t server = 1;
  std::uint64_t total = 0;
  Time start;

  std::optional<Handle> h;
  bool connected = false, shut = false;
  std::uint64_t sent = 0;
  std::vector<std::byte> chunk;
  std::size_t used = 0;

  void step(AppNode& n, Time now) {
    Stack& st = n.stack();
    while (const auto ev = st.poll_event()) {
      if (h && ev->h == *h && (ev->events & ev_connected) != 0) {
        connected = true;
      }
    }
    if (!h) {
      if (now < start) {
        n.wake_at(start);
        return;
      }
      const auto c = st.tcp_connect(Endpoint{node_addr(server), 5000}, {});
      ASSERT_TRUE(c.has_value());
      h = *c;
      return;
    }
    if (!connected || n.done) {
      return;
    }
    StreamChecker& sc = n.ctx().stream();
    while (sent < total) {
      if (used == chunk.size()) {
        chunk.resize(static_cast<std::size_t>(std::min<std::uint64_t>(65536, total - sent)));
        sc.tcp_pattern(conn, 0).fill(sent, chunk);
        used = 0;
      }
      const auto r = st.tcp_send(*h, std::span<const std::byte>(chunk).subspan(used));
      if (!r || *r == 0) {
        return;  // the send buffer is full: the next ACK calls us again
      }
      used += *r;
      sent += *r;
      sc.on_written(conn, 0, sent);
    }
    if (!shut) {
      ASSERT_TRUE(st.tcp_shutdown(*h, Shutdown::write).has_value());
      shut = true;
    }
    std::byte b[64];
    const auto r = st.tcp_recv(*h, b);
    if (r && *r == 0) {
      n.closing(*h);
      ASSERT_TRUE(st.tcp_close(*h).has_value());
      n.done = true;
    }
  }
};

// An AppNode application: connects to node `server`:5000 as workload
// connection `conn` (its pattern data, checked by the server's StackNode
// reader), writes `chunk` bytes every `gap` until `total`, then shuts down
// writing, reads to EOF and closes. A StackNode on the server side runs the
// matching ConnSpec (bytes_c2s = total, bytes_s2c = 0).
struct TrickleClient {
  std::uint32_t conn = 0;
  std::uint32_t server = 1;
  std::uint64_t total = 0;
  std::size_t chunk = 100;
  Duration gap = 1ms;
  Time start;
  TcpSocketOptions opts;

  std::optional<Handle> h;
  bool connected = false, shut = false, eof = false;
  std::uint64_t sent = 0;
  Time next_write;

  void step(AppNode& n, Time now) {
    Stack& st = n.stack();
    while (const auto ev = st.poll_event()) {
      if (h && ev->h == *h && (ev->events & ev_connected) != 0) {
        connected = true;
        next_write = now;
      }
    }
    if (!h) {
      if (now < start) {
        n.wake_at(start);
        return;
      }
      const auto c = st.tcp_connect(Endpoint{node_addr(server), 5000}, opts);
      ASSERT_TRUE(c.has_value());
      h = *c;
      return;
    }
    if (!connected || n.done) {
      return;
    }
    StreamChecker& sc = n.ctx().stream();
    while (sent < total && now >= next_write) {
      std::vector<std::byte> buf(std::min<std::uint64_t>(chunk, total - sent));
      sc.tcp_pattern(conn, 0).fill(sent, buf);
      const auto r = st.tcp_send(*h, buf);
      if (!r || *r == 0) {
        break;  // send buffer full: retried at the next call
      }
      sent += *r;
      sc.on_written(conn, 0, sent);
      next_write = next_write + gap;
    }
    if (sent < total) {
      n.wake_at(std::max(next_write, now + 1us));
      return;
    }
    if (!shut) {
      ASSERT_TRUE(st.tcp_shutdown(*h, Shutdown::write).has_value());
      shut = true;
    }
    std::byte b[64];
    const auto r = st.tcp_recv(*h, b);
    if (r && *r == 0) {
      n.closing(*h);
      ASSERT_TRUE(st.tcp_close(*h).has_value());
      n.done = true;
    }
  }
};

struct Rec {
  std::uint32_t node = 0;
  TraceEvent e;
};

// The result of a run with everything a directed test inspects.
struct Outcome {
  RunResult result;
  std::vector<Rec> trace;
  std::vector<Seg> wire;  // TCP segments, egress and ingress, in order
  std::vector<StackStats> stats;
  std::vector<StackNode::Counts> counts;  // zero for AppNodes
  // Each node's Tap::injected(), copied before the World (and its Taps) is
  // destroyed.
  std::vector<std::vector<Tap::Injected>> injected;

  [[nodiscard]] std::string violations() const {
    std::string s;
    for (const Violation& v : result.violations) {
      s += std::string(to_string(v.kind)) + ": " + v.message + "\n";
    }
    // The state changes, for diagnosis.
    s += "run of " + std::to_string((result.end - result.start).count() / 1'000'000) + " ms:\n";
    for (const Rec& r : trace) {
      if (r.e.kind == TraceKind::state) {
        s += "  " + std::to_string((r.e.t - result.start).count() / 1'000) + " us node " +
             std::to_string(r.node) + " conn " + std::to_string(r.e.conn_id) + " " +
             std::string(to_string(r.e.state)) + " " + std::string(to_string(r.e.cause)) + "\n";
      }
    }
    return s;
  }
  [[nodiscard]] bool ok() const { return result.verdict == Verdict::ok; }

  // Trace events of `node` (all nodes if nullopt) that match `pred`.
  template <class Pred>
  [[nodiscard]] std::vector<TraceEvent> events(std::optional<std::uint32_t> node, Pred pred) const {
    std::vector<TraceEvent> v;
    for (const Rec& r : trace) {
      if ((!node || r.node == *node) && pred(r.e)) {
        v.push_back(r.e);
      }
    }
    return v;
  }
  // The TCP segments node `node` sent (egress) or received.
  [[nodiscard]] std::vector<Seg> segs(std::uint32_t node, bool egress) const {
    std::vector<Seg> v;
    for (const Seg& s : wire) {
      if (s.node == node && s.egress == egress) {
        v.push_back(s);
      }
    }
    return v;
  }
  // The close cause of every connection of `node` that reached CLOSED.
  [[nodiscard]] std::vector<CloseCause> closes(std::uint32_t node) const {
    std::vector<CloseCause> v;
    for (const Rec& r : trace) {
      if (r.node == node && r.e.kind == TraceKind::state && r.e.state == TcpState::closed &&
          r.e.cause != CloseCause::none && r.e.tuple.remote.port != 0) {
        v.push_back(r.e.cause);
      }
    }
    return v;
  }
};

struct RunSpec {
  // Node i of the World; default: a StackNode for the scenario.
  std::function<std::unique_ptr<Node>(const Scenario&, std::uint32_t)> make;
  // Called with the taps (one per node) before the run. The taps belong to
  // the World and die with it: use Outcome::injected after the run.
  std::function<void(std::vector<Tap*>&)> setup;
  bool keep_trace = true;
  bool keep_wire = true;
};

// The Stack inside a node built by RunSpec::make (StackNode or AppNode).
[[nodiscard]] inline Stack* stack_of(Node& n) {
  if (auto* s = dynamic_cast<StackNode*>(&n)) {
    return &s->stack();
  }
  if (auto* a = dynamic_cast<AppNode*>(&n)) {
    return &a->stack();
  }
  return nullptr;
}

inline Outcome run_sim(const Scenario& s, const RunSpec& spec = {}) {
  std::vector<std::unique_ptr<Node>> nodes;
  std::vector<Tap*> taps;
  std::vector<Node*> inner;
  for (std::uint32_t i = 0; i < s.node.size(); ++i) {
    std::unique_ptr<Node> n = spec.make ? spec.make(s, i) : nullptr;
    if (!n) {
      n = std::make_unique<StackNode>(s, i);
    }
    inner.push_back(n.get());
    Stack* st = stack_of(*n);
    auto tap = std::make_unique<Tap>(std::move(n), st);
    taps.push_back(tap.get());
    nodes.push_back(std::move(tap));
  }
  if (spec.setup) {
    spec.setup(taps);
  }
  Outcome out;
  WorldOptions opt;
  if (spec.keep_trace) {
    opt.trace_out = [&out](std::uint32_t node, const TraceEvent& e) {
      out.trace.push_back(Rec{node, e});
    };
  }
  if (spec.keep_wire) {
    opt.on_wire = [&out](const WireEvent& w) {
      if (auto seg = parse_seg(w.node, w.egress, w.t, w.datagram)) {
        out.wire.push_back(*seg);
      }
    };
  }
  World world(s, std::move(nodes), opt);
  out.result = world.run();
  for (std::uint32_t i = 0; i < s.node.size(); ++i) {
    Stack* st = stack_of(*inner[i]);
    out.stats.push_back(st != nullptr ? st->stats() : StackStats{});
    auto* sn = dynamic_cast<StackNode*>(inner[i]);
    out.counts.push_back(sn != nullptr ? sn->counts() : StackNode::Counts{});
    out.injected.push_back(taps[i]->injected());
  }
  return out;
}

// One connection from node 0 (client) to node 1 (server) carrying `c2s` and
// `s2c` bytes, closed by both sides.
inline ConnSpec bulk(std::uint64_t c2s, std::uint64_t s2c, CloseMode mode = CloseMode::close) {
  ConnSpec c;
  c.mode = mode;
  c.client = 0;
  c.server_port = 5000;
  c.start = 1ms;
  c.bytes_c2s = c2s;
  c.bytes_s2c = s2c;
  return c;
}

// Every TCP segment both nodes sent and received keeps its SACK blocks
// inside the payload the other side sent (DESIGN §3.2: ACK and SACK ranges
// are clipped to [una, end()], D-SACK covers payload only), given each
// sender's ISN from its SYN: no block below ISN + 1 or above ISN + 1 +
// payload bytes. Returns the first offending segment as text.
inline std::optional<std::string> sack_outside_payload(const Outcome& o) {
  struct Flow {
    Endpoint src, dst;
    Seq32 isn;
    std::uint32_t max_end = 0;  // payload bytes past isn + 1
  };
  std::vector<Flow> flows;
  for (const Seg& s : o.wire) {
    if (!s.egress) {
      continue;
    }
    auto it = std::ranges::find_if(flows, [&](const Flow& f) { return f.src == s.src && f.dst == s.dst; });
    if (s.has(wire::tcp_syn)) {
      if (it == flows.end()) {
        flows.push_back(Flow{s.src, s.dst, s.h.seq, 0});
      }
      continue;
    }
    if (it != flows.end() && s.len > 0) {
      const std::uint32_t end = (s.h.seq + s.len).raw() - (it->isn + 1).raw();
      if (end < (1u << 31)) {
        it->max_end = std::max(it->max_end, end);
      }
    }
  }
  for (const Seg& s : o.wire) {
    if (!s.egress || s.opt.sack_count == 0) {
      continue;
    }
    // The blocks describe data the receiver got from the other direction.
    const auto it = std::ranges::find_if(flows, [&](const Flow& f) { return f.src == s.dst && f.dst == s.src; });
    if (it == flows.end()) {
      return "SACK on a connection without a SYN seen";
    }
    for (std::uint8_t i = 0; i < s.opt.sack_count; ++i) {
      const auto [b, e] = s.opt.sack[i];
      const std::uint32_t lo = b.raw() - (it->isn + 1).raw();
      const std::uint32_t hi = e.raw() - (it->isn + 1).raw();
      if (lo >= (1u << 31) || hi >= (1u << 31) || hi > it->max_end || lo >= hi) {
        return "node " + std::to_string(s.node) + " t=" + std::to_string(s.t.ns) + " block [" +
               std::to_string(lo) + ", " + std::to_string(hi) + ") outside payload [0, " +
               std::to_string(it->max_end) + ")";
      }
    }
  }
  return std::nullopt;
}

}  // namespace
}  // namespace utcp::sim
