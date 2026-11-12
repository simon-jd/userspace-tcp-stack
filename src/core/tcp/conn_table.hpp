// Connection demultiplexing table: FourTuple -> slot (DESIGN §4.3).
// Interface declared by m1-found; implemented by m1-ip (conn_table.cpp).
//
// A hash map keyed with SipHash-1-3 under the stack's hash_key (resists hash
// flooding). It is only looked up, never iterated: there is deliberately no
// iteration API, so no behaviour can depend on hash order (§13.1). Iteration
// over connections walks the engine's slot vector in index order.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "utcp/random.hpp"
#include "utcp/types.hpp"

namespace utcp {

class ConnTable {
public:
  explicit ConnTable(const SipKey& hash_key);

  // Adds `tuple` -> `slot`; false (and no change) if the tuple is present.
  bool insert(const FourTuple& tuple, std::uint32_t slot);
  [[nodiscard]] std::optional<std::uint32_t> find(const FourTuple& tuple) const;
  // False if the tuple was not present.
  bool erase(const FourTuple& tuple);
  [[nodiscard]] std::size_t size() const;

  // Table structure consistent; aborts on failure (Stack::debug_check).
  void check_invariants() const;

private:
  // Implementation state is m1-ip's.
};

}  // namespace utcp
