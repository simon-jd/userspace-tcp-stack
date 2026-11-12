#include <utility>

#include "utcp/check.hpp"
#include "utcp/packet.hpp"

#if defined(__SANITIZE_ADDRESS__)
#define UTCP_PACKET_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UTCP_PACKET_ASAN 1
#endif
#endif

#ifdef UTCP_PACKET_ASAN
#include <sanitizer/asan_interface.h>
#endif

namespace utcp {
namespace {

// Free buffers are poisoned under ASan, so a use after return is reported.
void poison(const std::byte* p, std::size_t n) noexcept {
#ifdef UTCP_PACKET_ASAN
  ASAN_POISON_MEMORY_REGION(p, n);
#else
  static_cast<void>(p);
  static_cast<void>(n);
#endif
}

void unpoison(const std::byte* p, std::size_t n) noexcept {
#ifdef UTCP_PACKET_ASAN
  ASAN_UNPOISON_MEMORY_REGION(p, n);
#else
  static_cast<void>(p);
  static_cast<void>(n);
#endif
}

}  // namespace

// --- PacketBuf

// The source is left empty as after reset(): size(), headroom() and
// tailroom() are 0.
PacketBuf::PacketBuf(PacketBuf&& other) noexcept
    : pool_(std::exchange(other.pool_, nullptr)),
      index_(std::exchange(other.index_, 0)),
      head_(std::exchange(other.head_, 0)),
      tail_(std::exchange(other.tail_, 0)) {}

PacketBuf& PacketBuf::operator=(PacketBuf&& other) noexcept {
  if (this != &other) {
    reset();
    pool_ = std::exchange(other.pool_, nullptr);
    index_ = std::exchange(other.index_, 0);
    head_ = std::exchange(other.head_, 0);
    tail_ = std::exchange(other.tail_, 0);
  }
  return *this;
}

PacketBuf::~PacketBuf() { reset(); }

void PacketBuf::reset() noexcept {
  if (pool_ != nullptr) {
    pool_->release(index_);
    pool_ = nullptr;
  }
  index_ = head_ = tail_ = 0;
}

std::byte* PacketBuf::base() const noexcept { return pool_->buffer(index_); }

std::span<std::byte> PacketBuf::bytes() noexcept {
  if (pool_ == nullptr) {
    return {};
  }
  return {base() + head_, size()};
}

std::span<const std::byte> PacketBuf::bytes() const noexcept {
  if (pool_ == nullptr) {
    return {};
  }
  return {base() + head_, size()};
}

std::byte* PacketBuf::prepend(std::size_t n) noexcept {
  UTCP_CHECK(pool_ != nullptr && n <= head_);
  head_ -= static_cast<std::uint32_t>(n);
  return base() + head_;
}

std::byte* PacketBuf::append(std::size_t n) noexcept {
  UTCP_CHECK(pool_ != nullptr && n <= tailroom());
  std::byte* p = base() + tail_;
  tail_ += static_cast<std::uint32_t>(n);
  return p;
}

void PacketBuf::truncate(std::size_t n) noexcept {
  UTCP_CHECK(n <= size());
  tail_ = head_ + static_cast<std::uint32_t>(n);
}

std::size_t PacketBuf::capacity() const noexcept {
  return pool_ == nullptr ? 0 : pool_->buf_size();
}

std::size_t PacketBuf::tailroom() const noexcept { return capacity() - tail_; }

// --- PacketPool

PacketPool::PacketPool(std::uint32_t count, std::uint32_t buf_size)
    : count_(count),
      buf_size_(buf_size),
      storage_(std::make_unique<std::byte[]>(std::size_t{count} * buf_size)) {
  free_.reserve(count);
  // Index 0 ends up on top, so a fresh pool hands out buffers in index order.
  for (std::uint32_t i = count; i > 0; --i) {
    free_.push_back(i - 1);
    poison(buffer(i - 1), buf_size_);
  }
}

PacketPool::~PacketPool() {
  UTCP_CHECK(free_.size() == count_);
  unpoison(storage_.get(), std::size_t{count_} * buf_size_);
}

std::optional<PacketBuf> PacketPool::alloc(std::uint32_t min_size,
                                           std::uint32_t headroom) noexcept {
  if (free_.empty() || std::uint64_t{min_size} + headroom > buf_size_) {
    return std::nullopt;
  }
  const std::uint32_t index = free_.back();
  free_.pop_back();
  unpoison(buffer(index), buf_size_);
  return PacketBuf(this, index, headroom);
}

void PacketPool::release(std::uint32_t index) noexcept {
  UTCP_DCHECK(index < count_ && free_.size() < count_);
  poison(buffer(index), buf_size_);
  free_.push_back(index);
}

std::byte* PacketPool::buffer(std::uint32_t index) const noexcept {
  return storage_.get() + std::size_t{index} * buf_size_;
}

}  // namespace utcp
