// StackNode (DESIGN §7.1): a Stack plus the scenario's scripted workload for
// that node, written against the Stack TCP, UDP and ICMP API.
//
// TCP connections (ConnSpec): listeners and clients (a listener accepts
// every client designed for its port, then closes; with a shared listener
// the client port tells which ConnSpec an accepted connection is), writes of
// 1..write_max bytes of pattern data, readers that check every byte through the
// StreamChecker and pause (zero windows), the close modes of §7.2, and an
// application idle timeout after which an endpoint closes (§7.3: a survivor
// whose peer failed must still end by its own retry rules). UDP echo flows
// (UdpSpec) and pings (PingSpec).
//
// The stack runs with assert_time_monotonic and every trace kind; trace
// events go to the World as the stack emits them.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include "utcp/sim/node.hpp"
#include "utcp/sim/scenario.hpp"
#include "utcp/stack.hpp"

namespace utcp::sim {

// The StackConfig of node `index` of `s`.
[[nodiscard]] StackConfig stack_config(const Scenario& s, std::uint32_t index);

class StackNode final : public Node {
public:
  StackNode(const Scenario& s, std::uint32_t index);
  ~StackNode() override;
  StackNode(const StackNode&) = delete;
  StackNode& operator=(const StackNode&) = delete;

  void receive(Time now, std::span<const std::byte> datagram) override;
  void advance(Time now) override;
  std::optional<TxPacket> pop_transmit() override;
  [[nodiscard]] Time next_deadline() const override;

  void attach(SimContext& ctx, std::uint32_t index) override;
  [[nodiscard]] Time next_app_deadline() const override;
  void run_apps(Time now) override;
  [[nodiscard]] bool finished() const override;
  void debug_check() const override;
  [[nodiscard]] std::optional<StackUsage> debug_usage() const override;
  [[nodiscard]] std::uint64_t activity() const override;

  [[nodiscard]] Stack& stack() noexcept;
  [[nodiscard]] const Stack& stack() const noexcept;

  // Workload results, for tests.
  struct Counts {
    std::uint64_t udp_sent = 0, udp_echoed = 0, udp_replies = 0;
    std::uint64_t pings_sent = 0, ping_replies = 0;
    std::uint64_t tcp_bytes_sent = 0, tcp_bytes_received = 0;
    std::uint32_t tcp_errors = 0;
  };
  [[nodiscard]] const Counts& counts() const noexcept;

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace utcp::sim
