#include "core/pmtu_cache.hpp"

#include <algorithm>

#include "utcp/check.hpp"

namespace utcp {

PmtuCache::PmtuCache(std::uint16_t if_mtu, std::uint16_t min_pmtu, Duration expiry,
                     std::size_t capacity)
    : if_mtu_(if_mtu), min_pmtu_(min_pmtu), expiry_(expiry), capacity_(capacity) {
  UTCP_CHECK(capacity_ > 0);
  entries_.reserve(capacity_);
}

std::size_t PmtuCache::lower_bound(Ipv4Addr dst) const noexcept {
  const auto it = std::lower_bound(entries_.begin(), entries_.end(), dst,
                                   [](const Entry& e, Ipv4Addr d) { return e.dst < d; });
  return static_cast<std::size_t>(it - entries_.begin());
}

std::uint16_t PmtuCache::get(Ipv4Addr dst, Time now) const noexcept {
  const std::size_t i = lower_bound(dst);
  if (i < entries_.size() && entries_[i].dst == dst && entries_[i].expires > now) {
    return entries_[i].mtu;
  }
  return if_mtu_;
}

std::uint16_t PmtuCache::lookup(Ipv4Addr dst, Time now) {
  const std::size_t i = lower_bound(dst);
  if (i < entries_.size() && entries_[i].dst == dst) {
    if (entries_[i].expires > now) {
      return entries_[i].mtu;
    }
    // RFC 1191 §6.3: an expired estimate returns to the first-hop MTU.
    entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
  }
  return if_mtu_;
}

bool PmtuCache::lower(Ipv4Addr dst, std::uint16_t mtu, Time now) {
  const std::uint16_t current = get(dst, now);
  // Linux __ip_rt_update_pmtu: a value below ip_rt_min_pmtu is raised to it.
  const std::uint16_t v = std::max(mtu, min_pmtu_);
  // RFC 1191 §6: "never raise" from ICMP; only a decrease is kept.
  if (v >= current) {
    return false;
  }
  const Entry e{dst, v, now, now + expiry_};
  std::size_t i = lower_bound(dst);
  if (i < entries_.size() && entries_[i].dst == dst) {
    entries_[i] = e;
    return true;
  }
  if (entries_.size() == capacity_) {
    // Evict the entry with the oldest update; the first in address order on
    // ties. An expired entry has the oldest update of all live ones or is
    // older still, so it goes first.
    std::size_t victim = 0;
    for (std::size_t k = 1; k < entries_.size(); ++k) {
      if (entries_[k].updated < entries_[victim].updated) {
        victim = k;
      }
    }
    entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(victim));
    i = lower_bound(dst);
  }
  entries_.insert(entries_.begin() + static_cast<std::ptrdiff_t>(i), e);
  return true;
}

Time PmtuCache::next_expiry() const noexcept {
  Time t = Time::never();
  for (const Entry& e : entries_) {
    t = std::min(t, e.expires);
  }
  return t;
}

void PmtuCache::check_invariants() const {
  UTCP_CHECK(entries_.size() <= capacity_);
  for (std::size_t i = 0; i < entries_.size(); ++i) {
    const Entry& e = entries_[i];
    UTCP_CHECK(i == 0 || entries_[i - 1].dst < e.dst);
    UTCP_CHECK(e.mtu < if_mtu_);
    UTCP_CHECK(e.mtu >= min_pmtu_);
    UTCP_CHECK(e.expires == e.updated + expiry_);
  }
}

}  // namespace utcp
