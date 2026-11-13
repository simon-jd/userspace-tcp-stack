// Nodes without a Stack, which emit synthetic IPv4 datagrams (DESIGN §7.1;
// the simulator's own tests need no other M1 task).
//
// SyntheticNode runs a scenario's workload as raw UDP: each ConnSpec is a
// flow of DF datagrams in each direction (bytes_c2s / bytes_s2c, capped),
// sent open-loop at a fixed gap and checked by the receiver through the
// StreamChecker; frag-needed lowers the datagram size; echo requests are
// answered. utcp-sim --nodes synthetic uses it, so sweeps, digests and pcaps
// can be exercised before the TCP engine exists.
//
// ScriptedNode is the test node: datagrams sent at given times, hooks on
// receipt and on application actions, and a log of the World's calls.
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "utcp/packet.hpp"
#include "utcp/sim/node.hpp"
#include "utcp/sim/scenario.hpp"

namespace utcp::sim {

// Bytes per direction a synthetic flow sends at most.
inline constexpr std::uint64_t synthetic_flow_cap = 512 * 1024;
// Gap between a flow's datagrams.
inline constexpr Duration synthetic_gap{200'000};

class SyntheticNode final : public Node {
public:
  SyntheticNode(const Scenario& s, std::uint32_t index);
  ~SyntheticNode() override;
  SyntheticNode(const SyntheticNode&) = delete;
  SyntheticNode& operator=(const SyntheticNode&) = delete;

  void receive(Time now, std::span<const std::byte> datagram) override;
  void advance(Time now) override;
  std::optional<TxPacket> pop_transmit() override;
  [[nodiscard]] Time next_deadline() const override;
  void attach(SimContext& ctx, std::uint32_t index) override;
  [[nodiscard]] bool finished() const override;
  [[nodiscard]] std::uint64_t activity() const override;

  [[nodiscard]] std::uint64_t datagrams_received() const noexcept;
  [[nodiscard]] std::uint64_t bytes_received() const noexcept;
  [[nodiscard]] std::uint64_t frag_needed_received() const noexcept;
  [[nodiscard]] std::uint64_t bad_checksums() const noexcept;

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

class ScriptedNode final : public Node {
public:
  explicit ScriptedNode(std::uint32_t pool_buffers = 64);
  ~ScriptedNode() override;
  ScriptedNode(const ScriptedNode&) = delete;
  ScriptedNode& operator=(const ScriptedNode&) = delete;

  // Queues `datagram` for pop_transmit at the first advance(t') with t' >= t.
  void send_at(Time t, std::vector<std::byte> datagram);
  // Queues `datagram` for pop_transmit now (from a hook).
  void send_now(std::span<const std::byte> datagram);
  // An application action at t (next_app_deadline).
  void app_at(Time t);

  struct Received {
    Time t;
    std::vector<std::byte> bytes;
  };
  [[nodiscard]] const std::vector<Received>& received() const noexcept { return received_; }
  // 'r' receive, 'a' advance, 'p' run_apps that acted, in call order.
  [[nodiscard]] const std::vector<std::pair<char, Time>>& calls() const noexcept { return calls_; }
  [[nodiscard]] std::uint32_t pool_available() const noexcept { return pool_.available(); }
  [[nodiscard]] std::uint32_t pool_size() const noexcept { return pool_.count(); }
  // Datagrams not queued because the pool was empty.
  [[nodiscard]] std::uint64_t alloc_failures() const noexcept { return alloc_failures_; }
  // The World (after attach), for hooks that report progress or violations.
  [[nodiscard]] SimContext* ctx() const noexcept { return ctx_; }
  [[nodiscard]] std::uint32_t index() const noexcept { return index_; }

  std::function<void(ScriptedNode&, Time, std::span<const std::byte>)> on_receive;
  std::function<void(ScriptedNode&, Time)> on_app;

  // Test behaviours. fixed_deadline: next_deadline() always returns it (a
  // deadline that never moves). activity_per_advance: advance() bumps
  // activity() by this much. usage: what debug_usage() reports (nullopt: a
  // node without a Stack). act_on_every_call: run_apps() acts (logs 'p',
  // calls on_app) on every call, as StackNode's applications do, not only
  // when an app_at time is due.
  std::optional<Time> fixed_deadline;
  std::uint64_t activity_per_advance = 0;
  std::optional<StackUsage> usage;
  bool act_on_every_call = false;
  bool done = true;  // finished()

  void receive(Time now, std::span<const std::byte> datagram) override;
  void advance(Time now) override;
  std::optional<TxPacket> pop_transmit() override;
  [[nodiscard]] Time next_deadline() const override;
  void attach(SimContext& ctx, std::uint32_t index) override;
  [[nodiscard]] Time next_app_deadline() const override;
  void run_apps(Time now) override;
  [[nodiscard]] bool finished() const override { return done; }
  // `usage`, with the datagrams still to send counted as tx_queued.
  [[nodiscard]] std::optional<StackUsage> debug_usage() const override;
  [[nodiscard]] std::uint64_t activity() const override { return activity_; }

private:
  void enqueue(std::span<const std::byte> datagram);

  PacketPool pool_;
  std::vector<std::pair<Time, std::vector<std::byte>>> pending_;  // sorted by time, stable
  std::deque<TxPacket> out_;
  std::vector<Time> app_times_;  // sorted
  std::vector<Received> received_;
  std::vector<std::pair<char, Time>> calls_;
  std::uint64_t activity_ = 0;
  std::uint64_t alloc_failures_ = 0;
  SimContext* ctx_ = nullptr;
  std::uint32_t index_ = 0;
};

}  // namespace utcp::sim
