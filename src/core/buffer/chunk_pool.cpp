#include "core/buffer/chunk_pool.hpp"

#include "utcp/check.hpp"

#if defined(__SANITIZE_ADDRESS__)
#define UTCP_CHUNK_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UTCP_CHUNK_ASAN 1
#endif
#endif

#ifdef UTCP_CHUNK_ASAN
#include <sanitizer/asan_interface.h>
#endif

namespace utcp {
namespace {

void poison(const std::byte* p) noexcept {
#ifdef UTCP_CHUNK_ASAN
  ASAN_POISON_MEMORY_REGION(p, ChunkPool::chunk_size);
#else
  static_cast<void>(p);
#endif
}

void unpoison(const std::byte* p) noexcept {
#ifdef UTCP_CHUNK_ASAN
  ASAN_UNPOISON_MEMORY_REGION(p, ChunkPool::chunk_size);
#else
  static_cast<void>(p);
#endif
}

}  // namespace

ChunkPool::ChunkPool(std::uint32_t limit) : limit_(limit) {
  UTCP_CHECK(limit < no_chunk);
}

ChunkPool::~ChunkPool() {
  UTCP_CHECK(in_use() == 0);
  for (const auto& c : chunks_) {
    unpoison(c.get());
  }
}

std::optional<ChunkPool::ChunkId> ChunkPool::alloc() noexcept {
  if (!free_.empty()) {
    const ChunkId id = free_.back();
    free_.pop_back();
    unpoison(chunks_[id].get());
    in_use_[id] = true;
    return id;
  }
  if (chunks_.size() >= limit_) {
    ++failures_;
    return std::nullopt;
  }
  chunks_.push_back(std::make_unique<std::byte[]>(chunk_size));
  in_use_.push_back(true);
  return static_cast<ChunkId>(chunks_.size() - 1);
}

void ChunkPool::free(ChunkId id) noexcept {
  UTCP_CHECK(id < chunks_.size() && in_use_[id]);
  in_use_[id] = false;
  poison(chunks_[id].get());
  free_.push_back(id);
}

}  // namespace utcp
