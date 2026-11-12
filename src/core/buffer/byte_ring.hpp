// Offset-addressed byte storage over ChunkPool chunks (DESIGN §3.3).
//
// A ByteRing holds bytes of one stream direction, addressed by 64-bit stream
// offset. It covers the window [begin(), limit()), limit() = begin() +
// capacity(); capacity is a limit, not an allocation. A chunk is taken from
// the pool when a byte in it is first written and returned once every byte in
// it lies below begin(), so an idle ring holds no chunks. Writes may land
// anywhere in the window (out-of-order data is stored at its final offset);
// unwritten gaps take no chunks.
//
// The only heap use is the chunk table, a power-of-two circular array that
// grows by doubling to the number of chunks the window spans.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "core/buffer/chunk_pool.hpp"

namespace utcp {

class ByteRing {
public:
  static constexpr std::uint32_t chunk_size = ChunkPool::chunk_size;

  ByteRing(ChunkPool& pool, std::uint64_t capacity, std::uint64_t begin = 0) noexcept;
  ~ByteRing();
  ByteRing(ByteRing&& other) noexcept;
  ByteRing& operator=(ByteRing&& other) noexcept;
  ByteRing(const ByteRing&) = delete;
  ByteRing& operator=(const ByteRing&) = delete;

  // First offset of the window. Bytes below it are gone.
  [[nodiscard]] std::uint64_t begin() const noexcept { return begin_; }
  [[nodiscard]] std::uint64_t capacity() const noexcept { return capacity_; }
  [[nodiscard]] std::uint64_t limit() const noexcept { return begin_ + capacity_; }
  // Changes the window size. Bytes already written above the new limit stay
  // readable; new writes must end at or before limit().
  void set_capacity(std::uint64_t capacity) noexcept { capacity_ = capacity; }

  // Copies `data` to offsets [off, off + data.size()). Precondition (checked):
  // begin() <= off and off + data.size() <= limit(). Returns the number of
  // bytes written, from the front: fewer than data.size() only if the chunk
  // pool is exhausted, in which case [off + result, ...) is not stored.
  std::size_t write_at(std::uint64_t off, std::span<const std::byte> data) noexcept;

  // Copies offsets [off, off + out.size()) to `out`. Precondition (checked):
  // begin() <= off. Bytes never written read as unspecified (deterministic)
  // values; bytes in a range without a chunk read as zero (debug builds abort).
  void read_at(std::uint64_t off, std::span<std::byte> out) const noexcept;

  // Moves begin() forward by n bytes and returns the chunks left wholly below
  // it, or every chunk once begin() reaches high_water().
  void consume(std::uint64_t n) noexcept;

  // Forgets every byte at or above `off` (reneging, memory pressure) and
  // returns the chunks that lie wholly at or above it.
  void release_from(std::uint64_t off) noexcept;

  // One past the highest byte written and still held; begin() if none.
  [[nodiscard]] std::uint64_t high_water() const noexcept { return high_; }
  // True if the chunk containing `off` is held.
  [[nodiscard]] bool has_chunk(std::uint64_t off) const noexcept;
  [[nodiscard]] std::uint32_t chunks_held() const noexcept { return held_; }
  // Memory held: chunks_held() * chunk_size.
  [[nodiscard]] std::uint64_t bytes_held() const noexcept {
    return std::uint64_t{held_} * chunk_size;
  }

private:
  [[nodiscard]] std::size_t slot_index(std::size_t i) const noexcept {
    return (head_ + i) & (slots_.size() - 1);
  }
  ChunkPool::ChunkId& slot(std::size_t i) noexcept { return slots_[slot_index(i)]; }
  [[nodiscard]] ChunkPool::ChunkId slot(std::size_t i) const noexcept {
    return slots_[slot_index(i)];
  }
  void ensure_slots(std::size_t n);
  void release_all() noexcept;

  ChunkPool* pool_;
  std::uint64_t capacity_;
  std::uint64_t begin_;
  std::uint64_t high_;
  std::uint64_t base_;       // offset of slot 0's first byte, a multiple of chunk_size
  std::vector<ChunkPool::ChunkId> slots_;  // circular, size 0 or a power of two
  std::size_t head_ = 0;     // index in slots_ of slot 0
  std::size_t count_ = 0;    // slots covering [base_, base_ + count_ * chunk_size)
  std::uint32_t held_ = 0;   // slots holding a chunk
};

}  // namespace utcp
