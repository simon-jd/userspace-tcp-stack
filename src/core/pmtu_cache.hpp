// Path MTU cache (RFC 1191; DESIGN §4.13, cache part).
//
// A sorted vector keyed by destination address, at most `capacity` entries
// (256 in a Stack). Destinations without an entry use the interface MTU.
// Entries are only ever lowered (never raised from ICMP), never below
// min_pmtu, and expire `expiry` after their last update (RFC 1191 §6.3), which
// restores the interface MTU. Expiry is checked lazily by lookups and driven
// by the stack's pmtu_expiry timer at next_expiry(). When the cache is full a
// new destination evicts the entry with the oldest update (ties: the lowest
// address), so eviction depends only on input history.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {

class PmtuCache {
public:
  static constexpr std::size_t default_capacity = 256;

  struct Entry {
    Ipv4Addr dst;
    std::uint16_t mtu = 0;
    Time updated;  // last lowered
    Time expires;  // updated + expiry

    bool operator==(const Entry&) const = default;
  };

  PmtuCache(std::uint16_t if_mtu, std::uint16_t min_pmtu, Duration expiry,
            std::size_t capacity = default_capacity);

  // The path MTU to `dst` at `now`: the entry's value if it has not expired
  // (expires > now), else the interface MTU.
  [[nodiscard]] std::uint16_t get(Ipv4Addr dst, Time now) const noexcept;
  // As get(), and removes the entry for `dst` if it has expired.
  std::uint16_t lookup(Ipv4Addr dst, Time now);

  // Lowers the path MTU to `dst` to `mtu` (RFC 1191 §6): a value below
  // min_pmtu is raised to min_pmtu (Linux __ip_rt_update_pmtu); the result is
  // kept only if it is below the current value. Returns true if the cache
  // changed.
  bool lower(Ipv4Addr dst, std::uint16_t mtu, Time now);

  // Removes every entry with expires <= now; returns how many. Each removed
  // destination is passed to `on_expired` if given.
  template <class F>
  std::size_t expire(Time now, F&& on_expired) {
    std::size_t removed = 0;
    std::size_t out = 0;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
      if (entries_[i].expires <= now) {
        on_expired(entries_[i].dst);
        ++removed;
      } else {
        entries_[out++] = entries_[i];
      }
    }
    entries_.resize(out);
    return removed;
  }
  std::size_t expire(Time now) {
    return expire(now, [](Ipv4Addr) {});
  }

  // Earliest expiry of any entry; Time::never() if there are none.
  [[nodiscard]] Time next_expiry() const noexcept;

  [[nodiscard]] std::uint16_t interface_mtu() const noexcept { return if_mtu_; }
  [[nodiscard]] std::uint16_t min_pmtu() const noexcept { return min_pmtu_; }
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
  // Sorted by destination.
  [[nodiscard]] std::span<const Entry> entries() const noexcept { return entries_; }

  // Sorted, unique, within capacity, every value in [min_pmtu, if_mtu),
  // expires = updated + expiry; aborts on failure.
  void check_invariants() const;

private:
  [[nodiscard]] std::size_t lower_bound(Ipv4Addr dst) const noexcept;

  std::uint16_t if_mtu_, min_pmtu_;
  Duration expiry_;
  std::size_t capacity_;
  std::vector<Entry> entries_;
};

}  // namespace utcp
