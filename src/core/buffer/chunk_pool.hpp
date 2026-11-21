// Pool of fixed-size chunks backing every ByteRing of a Stack (DESIGN §3.3).
//
// Chunks are allocated from the heap on demand, up to `limit` chunks, and
// never returned to the heap; freed chunks are reused LIFO. A chunk is
// zero-filled when first allocated; a reused chunk keeps the bytes of its
// previous user. Under ASan, free chunks are poisoned.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include "utcp/ring_config.hpp"

namespace utcp {

class ChunkPool {
public:
  using ChunkId = std::uint32_t;
  static constexpr std::uint32_t chunk_size = ring_chunk_bytes;
  static constexpr ChunkId no_chunk = 0xffff'ffff;

  // `limit`: the most chunks that may exist (StackConfig::chunk_limit).
  explicit ChunkPool(std::uint32_t limit);
  // Every chunk must have been freed (checked).
  ~ChunkPool();
  ChunkPool(const ChunkPool&) = delete;
  ChunkPool& operator=(const ChunkPool&) = delete;

  // A chunk, or nullopt (counted in failures()) when `limit` chunks are in use.
  [[nodiscard]] std::optional<ChunkId> alloc() noexcept;
  void free(ChunkId id) noexcept;

  [[nodiscard]] std::byte* data(ChunkId id) noexcept { return chunks_[id].get(); }
  [[nodiscard]] const std::byte* data(ChunkId id) const noexcept { return chunks_[id].get(); }

  [[nodiscard]] std::uint32_t limit() const noexcept { return limit_; }
  // Chunks allocated from the heap so far.
  [[nodiscard]] std::uint32_t allocated() const noexcept {
    return static_cast<std::uint32_t>(chunks_.size());
  }
  [[nodiscard]] std::uint32_t free_count() const noexcept {
    return static_cast<std::uint32_t>(free_.size());
  }
  [[nodiscard]] std::uint32_t in_use() const noexcept { return allocated() - free_count(); }
  [[nodiscard]] std::uint64_t failures() const noexcept { return failures_; }

private:
  std::uint32_t limit_;
  std::vector<std::unique_ptr<std::byte[]>> chunks_;
  std::vector<ChunkId> free_;      // LIFO
  std::vector<bool> in_use_;       // per chunk; catches double frees
  std::uint64_t failures_ = 0;
};

}  // namespace utcp
