// The simulator's invariant checkers (DESIGN §7.3). Each is fed by the World
// (wire datagrams, trace events) and by the workload applications (stream
// data, application closes); tests feed them synthetic sequences directly.
//
// | Checker            | Input                                    | Relaxed for garbage runs |
// | StreamChecker      | application writes and reads             | off                      |
// | TerminationChecker | TraceKind::state events, app closes      | any close cause          |
// | InFlightChecker    | wire datagrams, TraceKind::tx events     | on                       |
// | ProgressChecker    | progress events (World)                  | on                       |
// | QuiescenceChecker  | Stack::debug_usage() at the end (World)  | on                       |
// SelfCheck (Stack::debug_check() after every call) is in the World.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "utcp/config.hpp"
#include "utcp/random.hpp"
#include "utcp/seq.hpp"
#include "utcp/sim/pattern.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/stack.hpp"
#include "utcp/time.hpp"
#include "utcp/trace.hpp"
#include "utcp/types.hpp"

namespace utcp::sim {

// Outcome of a run. `ok` and the violation kinds come from the World; the
// sweep adds `timeout` and `crash` for runs it had to kill or that aborted.
enum class Verdict : std::uint8_t {
  ok,
  stream,       // StreamChecker
  termination,  // TerminationChecker
  inflight,     // InFlightChecker
  progress,     // ProgressChecker: no progress within the bound, or no events left
  leak,         // QuiescenceChecker
  stuck,        // an advance() that fired nothing left next_deadline() <= now (§7.1)
  livelock,     // too many events at one instant or in the run (§7.1)
  workload,     // an API call failed in a way the workload does not allow
  planted,      // Scenario::plant == fail
};
inline constexpr int verdict_count = 10;

[[nodiscard]] std::string_view to_string(Verdict v) noexcept;
[[nodiscard]] std::optional<Verdict> verdict_from_string(std::string_view s) noexcept;

struct Violation {
  Verdict kind = Verdict::ok;
  Time t;
  std::string message;

  bool operator==(const Violation&) const = default;
};

// --- StreamChecker: each received byte equals the expected byte at its
// offset; at EOF the length equals the bytes the sender wrote.
class StreamChecker {
public:
  explicit StreamChecker(const Seed& master);

  // Off for runs with garbage corruption (valid-checksum segments can carry
  // wrong data, §7.3).
  void set_enabled(bool on) noexcept { enabled_ = on; }
  [[nodiscard]] bool enabled() const noexcept { return enabled_; }

  // The data of TCP workload connection `conn`, direction `dir` (0 = client
  // to server). Senders take their bytes from it.
  [[nodiscard]] const Pattern& tcp_pattern(std::uint32_t conn, std::uint8_t dir);
  // The data of UDP flow `flow`; datagram `seq` carries the bytes at offset
  // seq << 16 (see udp_payload).
  [[nodiscard]] const Pattern& udp_pattern(std::uint32_t flow, std::uint8_t dir);

  // The sender of (conn, dir) has written `total` bytes so far.
  void on_written(std::uint32_t conn, std::uint8_t dir, std::uint64_t total);
  // `data` was read at stream offset `offset`; a message if a byte differs.
  [[nodiscard]] std::optional<std::string> on_read(std::uint32_t conn, std::uint8_t dir,
                                                   std::uint64_t offset,
                                                   std::span<const std::byte> data);
  // End of stream after `total` bytes; a message unless it equals the bytes
  // written.
  [[nodiscard]] std::optional<std::string> on_eof(std::uint32_t conn, std::uint8_t dir,
                                                  std::uint64_t total);
  // A UDP datagram of flow `flow` (built with udp_payload); a message if it
  // is not one the sender could have sent.
  [[nodiscard]] std::optional<std::string> on_datagram(std::uint32_t flow, std::uint8_t dir,
                                                       std::span<const std::byte> payload);

  // Fills `out` with the payload of datagram `seq`: the sequence number in
  // the first 4 bytes (big-endian, truncated for shorter payloads), then the
  // pattern bytes at offset (seq << 16) + 4.
  void udp_payload(std::uint32_t flow, std::uint8_t dir, std::uint32_t seq,
                   std::span<std::byte> out);

private:
  using Key = std::pair<std::uint32_t, std::uint32_t>;  // (flow, dir), UDP flows offset by 2^31
  const Pattern& pattern_(std::string_view kind, std::uint32_t flow, std::uint8_t dir);

  Seed master_;
  bool enabled_ = true;
  std::map<Key, Pattern> patterns_;
  std::map<Key, std::uint64_t> written_;
};

// --- TerminationChecker (§7.3): every connection ends in CLOSED, through a
// legal end:
// - after a FIN exchange both ways: last_ack, time_wait_expired, time_wait_reused;
// - retry exhaustion: timed_out (RST sent if synchronized), synack_timed_out
//   (a SYN-RECEIVED child freed after synack_retries);
// - fin_wait2_timeout from FIN-WAIT-2 (an orphan whose FIN was ACKed);
// - aborted: only if the application closed or aborted the connection;
// - listener_closed: a listener the application closed, or a child of one;
// - rst_received: the peer's matching connection ended before, and either the
//   peer sent the RST on purpose (aborted, timed_out, synack_timed_out,
//   listener_closed, child_reset, refused, time_wait_rst) or we were in
//   FIN-WAIT-1, FIN-WAIT-2, CLOSING or LAST-ACK (the peer's TIME_WAIT or
//   orphan FIN-WAIT-2 entry ended first, checked in the peer's trace);
// - refused: a refused-mode connection, or the peer's connection ended before;
// - child_reset, time_wait_rst: the peer's connection ended before.
// Relaxed (garbage runs): any close cause, but every connection must end.
class TerminationChecker {
public:
  // The designed close mode of the connection with this tuple on this node;
  // nullopt if it is not a workload connection.
  using DesignFn = std::function<std::optional<CloseMode>(std::uint32_t node, const FourTuple&)>;

  void set_relaxed(bool on) noexcept { relaxed_ = on; }
  void set_design(DesignFn fn) { design_ = std::move(fn); }

  // TraceKind::state events; other kinds are ignored.
  void on_trace(std::uint32_t node, const TraceEvent& e);
  // The application closed or aborted connection `conn_id` of `node` at t.
  void on_app_close(std::uint32_t node, std::uint32_t conn_id, Time t);

  // Connections seen in the traces that have not reached CLOSED.
  [[nodiscard]] std::size_t open_connections() const noexcept;
  [[nodiscard]] std::size_t connections() const noexcept { return conns_.size(); }
  // Every illegal end and every connection not in CLOSED; call at the end.
  [[nodiscard]] std::vector<Violation> finish(Time now) const;

private:
  struct Conn {
    std::uint32_t node = 0, conn_id = 0;
    FourTuple tuple;
    bool listener = false;
    bool passive = false;  // first state was syn_received
    TcpState state = TcpState::closed;
    TcpState before_close = TcpState::closed;
    bool closed = false;
    CloseCause cause = CloseCause::none;
    Time start, end;
    std::optional<Time> app_close;
  };

  [[nodiscard]] std::optional<std::string> judge(const Conn& c) const;
  [[nodiscard]] const Conn* peer_of(const Conn& c) const;

  bool relaxed_ = false;
  DesignFn design_;
  std::vector<Conn> conns_;  // in order of first appearance
  std::map<std::pair<std::uint32_t, std::uint32_t>, std::size_t> by_id_;  // (node, conn_id)
};

// --- InFlightChecker (§7.3).
// Wire shadow: per sending direction, the window scale each side announced in
// its SYN (scaling only if both SYNs carried it; SYN windows unscaled), and
// the highest right edge ack + (win << wscale) over the ACKs delivered to the
// sender. Each new-data segment (one that ends above everything sent before)
// must end at or before that edge; retransmissions are exempt. Only
// datagrams that pass the IPv4 and TCP checksum checks count, and a delivered
// SYN counts only if its sequence number is the ISN its sender actually used.
// Self-reported (TraceKind::tx events of data segments): packets_in_flight <=
// cwnd, except fast_rexmit, rto_rexmit and tlp (RFC 6675 §5 (4.3), RFC 8985
// §7.3); in Open with no loss marks, the wire bytes in flight (highest sent -
// highest delivered ACK - bytes SACKed on the wire) <= cwnd * mss. Trace tx
// events carry in_flight after the transmission.
class InFlightChecker {
public:
  // A datagram `node` handed to the host (before impairment).
  [[nodiscard]] std::optional<std::string> on_egress(std::uint32_t node,
                                                     std::span<const std::byte> datagram);
  // A datagram delivered to `node` (after impairment).
  void on_ingress(std::uint32_t node, std::span<const std::byte> datagram);
  // A trace event of `node`'s stack.
  [[nodiscard]] std::optional<std::string> on_trace(std::uint32_t node, const TraceEvent& e);

  // The edge the shadow holds for data sent from `local` to `remote`.
  [[nodiscard]] std::optional<Seq32> right_edge(const FourTuple& sender) const;

private:
  struct Dir {
    bool own_syn = false;  // the sender's SYN (or SYN-ACK) seen on egress
    Seq32 iss{0};
    std::optional<std::uint8_t> own_ws;
    bool peer_syn = false;  // the peer's SYN delivered to the sender
    Seq32 peer_isn{0};
    std::optional<std::uint8_t> peer_ws;
    std::optional<Seq32> edge, high_sent, high_ack;
    std::vector<std::pair<Seq32, Seq32>> sacked;  // disjoint, above high_ack
  };
  [[nodiscard]] std::uint8_t peer_shift(const Dir& d) const noexcept;
  void add_sack(Dir& d, Seq32 begin, Seq32 end);
  [[nodiscard]] static std::uint32_t sacked_bytes(const Dir& d) noexcept;

  std::map<FourTuple, Dir> dirs_;  // keyed by (sender, receiver)
};

// --- ProgressChecker: while any workload connection is unfinished, some
// progress (bytes delivered, a state change, a connection end) occurs within
// `bound` of virtual time.
class ProgressChecker {
public:
  explicit ProgressChecker(Duration bound) noexcept : bound_(bound) {}
  void on_progress(Time t) noexcept { last_ = t; }
  [[nodiscard]] Time deadline() const noexcept { return last_ + bound_; }
  [[nodiscard]] Duration bound() const noexcept { return bound_; }

private:
  Duration bound_;
  Time last_{};
};

// B = retry_abort_time(data_retries, rto_min, rto_max) + time_wait + 120 s.
[[nodiscard]] Duration progress_bound(const TcpConfig& c) noexcept;

// --- QuiescenceChecker: after all workload connections end, the World runs
// until no connection timer is armed and nothing is queued (only the stack's
// pmtu_expiry timer may remain); then nothing may be live.
// True when `u` can be judged: no connection timers, queued packets or
// blocked connections remain.
[[nodiscard]] bool usage_settled(const StackUsage& u) noexcept;
// What is still held, or nullopt: live TCP or UDP slots, TIME_WAIT entries,
// queued packets, events or echo replies, blocked connections, armed
// connection timers, packet buffers or chunks not free.
[[nodiscard]] std::optional<std::string> usage_leaks(const StackUsage& u);

}  // namespace utcp::sim
