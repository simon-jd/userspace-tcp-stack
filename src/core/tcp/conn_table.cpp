#include "core/tcp/conn_table.hpp"

#include <utility>

#include "core/util/siphash.hpp"
#include "utcp/check.hpp"

namespace utcp {

namespace {

constexpr std::size_t initial_capacity = 16;

}  // namespace

ConnTable::ConnTable(const SipKey& hash_key) : key_(hash_key), entries_(initial_capacity) {}

std::uint64_t ConnTable::hash(const FourTuple& t) const noexcept {
  // §4.3: SipHash-1-3 keyed by hash_key, so an attacker cannot choose tuples
  // that collide.
  SipHasher13 h(key_);
  h.update_u32(t.local.addr.v);
  h.update_u16(t.local.port);
  h.update_u32(t.remote.addr.v);
  h.update_u16(t.remote.port);
  return h.finish();
}

std::size_t ConnTable::home(const FourTuple& tuple) const noexcept {
  return static_cast<std::size_t>(hash(tuple)) & (entries_.size() - 1);
}

std::size_t ConnTable::probe(const FourTuple& tuple) const noexcept {
  const std::size_t mask = entries_.size() - 1;
  std::size_t i = home(tuple);
  while (entries_[i].used && entries_[i].tuple != tuple) {
    i = (i + 1) & mask;
  }
  return i;
}

void ConnTable::grow() {
  std::vector<Entry> old(entries_.size() * 2);
  old.swap(entries_);
  for (const Entry& e : old) {
    if (e.used) {
      entries_[probe(e.tuple)] = e;
    }
  }
}

bool ConnTable::insert(const FourTuple& tuple, std::uint32_t slot) {
  std::size_t i = probe(tuple);
  if (entries_[i].used) {
    return false;
  }
  if (2 * (size_ + 1) > entries_.size()) {
    grow();
    i = probe(tuple);
  }
  entries_[i] = Entry{tuple, slot, true};
  ++size_;
  return true;
}

std::optional<std::uint32_t> ConnTable::find(const FourTuple& tuple) const {
  const std::size_t i = probe(tuple);
  if (entries_[i].used) {
    return entries_[i].slot;
  }
  return std::nullopt;
}

bool ConnTable::erase(const FourTuple& tuple) {
  const std::size_t mask = entries_.size() - 1;
  std::size_t hole = probe(tuple);
  if (!entries_[hole].used) {
    return false;
  }
  // Backward-shift deletion: move each later entry of the probe run whose
  // home is not in (hole, j] into the hole.
  std::size_t j = hole;
  for (;;) {
    j = (j + 1) & mask;
    if (!entries_[j].used) {
      break;
    }
    const std::size_t k = home(entries_[j].tuple);
    // k lies cyclically in (hole, j]: the entry may not move before its home.
    const bool k_in_range = hole <= j ? (hole < k && k <= j) : (hole < k || k <= j);
    if (!k_in_range) {
      entries_[hole] = entries_[j];
      hole = j;
    }
  }
  entries_[hole] = Entry{};
  --size_;
  return true;
}

std::size_t ConnTable::size() const { return size_; }

void ConnTable::check_invariants() const {
  const std::size_t cap = entries_.size();
  UTCP_CHECK(cap >= initial_capacity && (cap & (cap - 1)) == 0);
  UTCP_CHECK(2 * size_ <= cap);
  std::size_t used = 0;
  for (std::size_t i = 0; i < cap; ++i) {
    if (!entries_[i].used) {
      continue;
    }
    ++used;
    // No empty entry between the home and the position (the probe finds it),
    // and no duplicate.
    UTCP_CHECK(probe(entries_[i].tuple) == i);
  }
  UTCP_CHECK(used == size_);
}

}  // namespace utcp
