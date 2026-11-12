// Workload data (DESIGN §7.2): every byte is a function of (seed, flow,
// direction, offset), so senders produce it on the fly and receivers check
// every byte without storing the stream.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "utcp/random.hpp"

namespace utcp::sim {

class Pattern {
public:
  // `kind` separates flow families ("tcp", "udp", "synthetic"); `flow` is the
  // index within the family; `dir` 0 is client to server, 1 the reverse.
  Pattern(const Seed& master, std::string_view kind, std::uint32_t flow, std::uint8_t dir) noexcept;

  [[nodiscard]] std::byte at(std::uint64_t offset) const noexcept;
  // out[i] = at(offset + i).
  void fill(std::uint64_t offset, std::span<std::byte> out) const noexcept;
  // The offset of the first byte of `data` (read at `offset`) that differs
  // from the pattern, or nullopt.
  [[nodiscard]] std::optional<std::uint64_t> mismatch(std::uint64_t offset,
                                                      std::span<const std::byte> data) const noexcept;

private:
  [[nodiscard]] std::uint64_t block(std::uint64_t index) const noexcept;
  std::uint64_t key_;
};

}  // namespace utcp::sim
