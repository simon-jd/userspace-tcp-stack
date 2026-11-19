// A simulated host (DESIGN §7.1): a Stack plus scripted applications
// (StackNode), or a test node that emits synthetic IPv4 datagrams
// (SyntheticNode, ScriptedNode).
//
// The World drives every node through the same host contract as a real
// backend (§3.4): receive() for each delivered datagram, advance() when
// now >= next_deadline(), pop_transmit() after every call. The World copies
// each transmitted datagram into link storage at once, so the node's packet
// buffers return to its pool while the datagram is in flight.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "utcp/packet.hpp"
#include "utcp/random.hpp"
#include "utcp/stack.hpp"
#include "utcp/time.hpp"
#include "utcp/trace.hpp"

namespace utcp::sim {

struct Scenario;
class StreamChecker;
enum class Verdict : std::uint8_t;

// The World as seen by a node: virtual time, the scenario, and the checker
// inputs that only the applications know.
class SimContext {
public:
  virtual ~SimContext() = default;

  [[nodiscard]] virtual Time now() const = 0;
  [[nodiscard]] virtual const Scenario& scenario() const = 0;
  // Seed::from_u64(scenario().seed); every random consumer derives a named
  // stream from it (§7.2).
  [[nodiscard]] virtual const Seed& master_seed() const = 0;

  // A trace event of the node's stack (TerminationChecker, InFlightChecker,
  // ProgressChecker on state changes, --trace output).
  virtual void on_trace(std::uint32_t node, const TraceEvent& e) = 0;
  // A socket event the node's applications took from poll_event (run digest).
  virtual void on_socket_event(std::uint32_t node, const SocketEvent& e) = 0;
  // Application progress: bytes delivered to an application or an endpoint
  // finished (ProgressChecker).
  virtual void on_progress() = 0;
  // The StreamChecker, fed by the applications' writes and reads.
  [[nodiscard]] virtual StreamChecker& stream() = 0;
  // The application closed or aborted TCP connection `conn_id` (TcpInfo::
  // conn_id): an RST that the close causes is designed (TerminationChecker).
  virtual void on_app_close(std::uint32_t node, std::uint32_t conn_id) = 0;
  // A checker or the workload found a violation.
  virtual void violation(Verdict kind, std::string message) = 0;
  // An API error the workload tolerates, e.g. connection_refused in a
  // refused-mode connection (run digest).
  virtual void note_error(std::uint32_t node, std::string_view what) = 0;
};

class Node {
public:
  virtual ~Node() = default;

  // --- Host interface (§3.4, §7.1).
  virtual void receive(Time now, std::span<const std::byte> datagram) = 0;
  virtual void advance(Time now) = 0;
  virtual std::optional<TxPacket> pop_transmit() = 0;
  [[nodiscard]] virtual Time next_deadline() const = 0;

  // --- Optional parts; the defaults suit a node without applications.
  // Called once before the run; `index` is the node's index in the scenario.
  virtual void attach(SimContext& ctx, std::uint32_t index) {
    static_cast<void>(ctx);
    static_cast<void>(index);
  }
  // Earliest application action (an application timer); never if none.
  [[nodiscard]] virtual Time next_app_deadline() const { return Time::never(); }
  // Lets the applications act: take socket events, run due application
  // timers. The World calls it after every receive/advance and at
  // next_app_deadline(), each time right after an advance(now) at the same
  // instant (the World calls advance(t) before every application action,
  // §7.1).
  virtual void run_apps(Time now) { static_cast<void>(now); }
  // All applications have finished (sockets closed).
  [[nodiscard]] virtual bool finished() const { return true; }
  // SelfCheck: Stack::debug_check() after every call.
  virtual void debug_check() const {}
  // Effective settings for the World's checkers; nodes without a Stack use the scenario.
  [[nodiscard]] virtual const TcpConfig* effective_tcp_config() const { return nullptr; }
  // QuiescenceChecker input; nullopt for nodes without a Stack.
  [[nodiscard]] virtual std::optional<StackUsage> debug_usage() const { return std::nullopt; }
  // A counter of everything observable the node did (trace events, socket
  // events, packets handed out, datagrams emitted). An advance() that leaves
  // next_deadline() <= now without changing it is `stuck` (§7.1).
  [[nodiscard]] virtual std::uint64_t activity() const { return 0; }
};

}  // namespace utcp::sim
