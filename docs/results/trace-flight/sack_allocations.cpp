// Count allocations made by each ordinary SACK once the send queue is populated.
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <span>
#include <vector>

#include "core/tcp/send_queue.hpp"

namespace {
std::atomic<std::size_t> allocations;
}

void* operator new(std::size_t size) {
  void* p = std::malloc(std::max<std::size_t>(size, 1));
  if (!p) throw std::bad_alloc();
  ++allocations;
  return p;
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

int main() {
  constexpr unsigned mss = 100, segments = 64, length = mss * segments;
  utcp::ChunkPool pool(4);
  utcp::SendQueue queue(pool, length);
  std::vector<std::byte> data(length);
  if (queue.write(data) != length) return 1;
  for (unsigned off = 0; off < length; off += mss) {
    queue.on_transmit(off, mss, false, {}, {});
  }

  std::array<bool, length> sacked{};
  auto ack = [&](utcp::Range block) {
    const auto before = allocations.load();
    queue.on_sack(std::span(&block, 1), {}, [](const auto&, bool) {});
    const auto delta = allocations.load() - before;
    std::fill(sacked.begin() + block.begin, sacked.begin() + block.end, true);
    const auto expected = std::count(sacked.begin(), sacked.end(), false);
    if (queue.in_flight_bytes() != expected) {
      std::fprintf(stderr, "byte oracle mismatch: got %u, expected %td\n",
                   queue.in_flight_bytes(), expected);
      std::abort();
    }
    return delta;
  };
  // One hole at the head. The peer adds a full segment to a contiguous block,
  // re-advertises it, then reports a second disjoint group farther ahead.
  const auto first = ack({mss, 2 * mss});
  std::size_t aligned_growth = 0, repeats = 0, disjoint = 0, partial_growth = 0;
  for (unsigned i = 3; i <= 32; ++i) {
    aligned_growth += ack({mss, i * mss});
    repeats += ack({mss, i * mss});
  }
  for (unsigned i = 35; i <= 47; i += 2) disjoint += ack({i * mss, (i + 1) * mss});
  const auto first_partial = ack({5050, 5051});
  for (unsigned hi = 5052; hi <= 5099; ++hi) {
    partial_growth += ack({5050, hi});
    repeats += ack({5050, hi});
  }
  // Once another partial interval is separated by a fully tagged segment, the
  // moving right edge should reuse its node on later segment boundaries.
  const auto second_interval = ack({5050, 5201});
  std::size_t across_segments = 0;
  for (unsigned hi = 5202; hi <= 6100; ++hi) across_segments += ack({5050, hi});
  std::printf("aligned_first=%zu aligned_growth=%zu disjoint_aligned=%zu "
              "first_partial=%zu partial_growth=%zu second_interval=%zu across_segments=%zu "
              "repeats=%zu outstanding=%u\n",
              first, aligned_growth, disjoint, first_partial, partial_growth, second_interval, across_segments,
              repeats, queue.in_flight_bytes());
  return first + aligned_growth + disjoint + partial_growth + repeats + across_segments != 0 ||
         first_partial > 2 || second_interval > 1;
}
