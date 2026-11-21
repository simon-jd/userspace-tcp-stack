#include "core/buffer/byte_ring.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include "utcp/check.hpp"

namespace utcp {
namespace {

constexpr std::uint64_t align_down(std::uint64_t off) noexcept {
  return off - off % ByteRing::chunk_size;
}

}  // namespace

ByteRing::ByteRing(ChunkPool& pool, std::uint64_t capacity, std::uint64_t begin) noexcept
    : pool_(&pool), capacity_(capacity), begin_(begin), high_(begin), base_(align_down(begin)) {}

ByteRing::~ByteRing() { release_all(); }

ByteRing::ByteRing(ByteRing&& other) noexcept
    : pool_(other.pool_),
      capacity_(other.capacity_),
      begin_(other.begin_),
      high_(other.high_),
      base_(other.base_),
      slots_(std::move(other.slots_)),
      head_(other.head_),
      count_(other.count_),
      held_(other.held_) {
  other.slots_.clear();
  other.head_ = 0;
  other.count_ = 0;
  other.held_ = 0;
}

ByteRing& ByteRing::operator=(ByteRing&& other) noexcept {
  if (this != &other) {
    release_all();
    pool_ = other.pool_;
    capacity_ = other.capacity_;
    begin_ = other.begin_;
    high_ = other.high_;
    base_ = other.base_;
    slots_ = std::move(other.slots_);
    head_ = other.head_;
    count_ = other.count_;
    held_ = other.held_;
    other.slots_.clear();
    other.head_ = 0;
    other.count_ = 0;
    other.held_ = 0;
  }
  return *this;
}

void ByteRing::release_all() noexcept {
  for (std::size_t i = 0; i < count_; ++i) {
    ChunkPool::ChunkId& id = slot(i);
    if (id != ChunkPool::no_chunk) {
      pool_->free(id);
      id = ChunkPool::no_chunk;
    }
  }
  held_ = 0;
  head_ = 0;
  count_ = 0;
  base_ = align_down(begin_);
}

void ByteRing::ensure_slots(std::size_t n) {
  if (n <= count_) {
    return;
  }
  if (n > slots_.size()) {
    std::size_t cap = std::max<std::size_t>(slots_.size(), 4);
    while (cap < n) {
      cap *= 2;
    }
    std::vector<ChunkPool::ChunkId> grown(cap, ChunkPool::no_chunk);
    for (std::size_t i = 0; i < count_; ++i) {
      grown[i] = slot(i);
    }
    slots_ = std::move(grown);
    head_ = 0;
  }
  for (std::size_t i = count_; i < n; ++i) {
    slot(i) = ChunkPool::no_chunk;
  }
  count_ = n;
}

std::size_t ByteRing::write_at(std::uint64_t off, std::span<const std::byte> data) noexcept {
  return store_at<true>(off, data.size(), data.data());
}

std::size_t ByteRing::reserve_at(std::uint64_t off, std::size_t len) noexcept {
  return store_at<false>(off, len, nullptr);
}

template <bool materialize>
std::size_t ByteRing::store_at(std::uint64_t off, std::size_t len, const std::byte* data) noexcept {
  UTCP_CHECK(off >= begin_ && off <= limit() && len <= limit() - off);
  if (len == 0) {
    return 0;
  }
  if (count_ == 0) {
    base_ = align_down(begin_);
  }
  std::size_t written = 0;
  while (written < len) {
    const std::uint64_t pos = off + written;
    const auto idx = static_cast<std::size_t>((pos - base_) / chunk_size);
    ensure_slots(idx + 1);
    ChunkPool::ChunkId& id = slot(idx);
    if (id == ChunkPool::no_chunk) {
      const auto got = pool_->alloc();
      if (!got) {
        break;
      }
      id = *got;
      ++held_;
    }
    const auto in_chunk = static_cast<std::size_t>(pos % chunk_size);
    const std::size_t n = std::min(len - written, chunk_size - in_chunk);
    if constexpr (materialize) {
      std::memcpy(pool_->data(id) + in_chunk, data + written, n);
    }
    written += n;
  }
  high_ = std::max(high_, off + written);
  return written;
}

void ByteRing::read_at(std::uint64_t off, std::span<std::byte> out) const noexcept {
  UTCP_CHECK(off >= begin_);
  std::size_t done = 0;
  while (done < out.size()) {
    const std::uint64_t pos = off + done;
    const auto in_chunk = static_cast<std::size_t>(pos % chunk_size);
    const std::size_t n = std::min(out.size() - done, chunk_size - in_chunk);
    const auto idx = static_cast<std::size_t>((pos - base_) / chunk_size);
    const ChunkPool::ChunkId id = idx < count_ ? slot(idx) : ChunkPool::no_chunk;
    UTCP_DCHECK(id != ChunkPool::no_chunk);
    if (id == ChunkPool::no_chunk) {
      std::memset(out.data() + done, 0, n);
    } else {
      std::memcpy(out.data() + done, pool_->data(id) + in_chunk, n);
    }
    done += n;
  }
}

void ByteRing::consume(std::uint64_t n) noexcept {
  begin_ += n;
  if (begin_ >= high_) {
    high_ = begin_;
    release_all();
    return;
  }
  while (count_ > 0 && base_ + chunk_size <= begin_) {
    ChunkPool::ChunkId& id = slot(0);
    if (id != ChunkPool::no_chunk) {
      pool_->free(id);
      id = ChunkPool::no_chunk;
      --held_;
    }
    head_ = slot_index(1);
    --count_;
    base_ += chunk_size;
  }
  if (count_ == 0) {
    base_ = align_down(begin_);
  }
}

void ByteRing::release_from(std::uint64_t off) noexcept {
  off = std::max(off, begin_);
  if (off <= begin_) {
    high_ = begin_;
    release_all();
    return;
  }
  // First slot whose chunk lies wholly at or above off.
  const std::uint64_t first = (off - base_ + chunk_size - 1) / chunk_size;
  for (auto i = static_cast<std::size_t>(first); i < count_; ++i) {
    ChunkPool::ChunkId& id = slot(i);
    if (id != ChunkPool::no_chunk) {
      pool_->free(id);
      id = ChunkPool::no_chunk;
      --held_;
    }
  }
  count_ = std::min(count_, static_cast<std::size_t>(first));
  high_ = std::min(high_, off);
}

bool ByteRing::has_chunk(std::uint64_t off) const noexcept {
  if (off < base_) {
    return false;
  }
  const std::uint64_t idx = (off - base_) / chunk_size;
  return idx < count_ && slot(static_cast<std::size_t>(idx)) != ChunkPool::no_chunk;
}

}  // namespace utcp
