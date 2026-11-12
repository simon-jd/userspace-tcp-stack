// Packet buffers and the host interface's packet types (DESIGN §3.3).
//
// A PacketPool owns a preallocated array of fixed-size buffers with a LIFO
// free list. A PacketBuf is one buffer taken from it: move-only, and its
// destructor returns the buffer. Headers are built back to front: reserve
// headroom at alloc, append the payload, then prepend each header.
// Offsets are 32-bit so that the M4 64 KiB class plus a virtio_net_hdr fit.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace utcp {

class PacketPool;

class PacketBuf {
public:
  PacketBuf() noexcept = default;  // empty: no buffer
  PacketBuf(PacketBuf&& other) noexcept;
  PacketBuf& operator=(PacketBuf&& other) noexcept;
  PacketBuf(const PacketBuf&) = delete;
  PacketBuf& operator=(const PacketBuf&) = delete;
  ~PacketBuf();

  // False for a default-constructed or moved-from PacketBuf.
  [[nodiscard]] bool valid() const noexcept { return pool_ != nullptr; }
  explicit operator bool() const noexcept { return valid(); }

  // The packet: bytes [head, tail).
  [[nodiscard]] std::span<std::byte> bytes() noexcept;
  [[nodiscard]] std::span<const std::byte> bytes() const noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return tail_ - head_; }

  // Grows the packet at the front by n bytes into the headroom and returns a
  // pointer to the new first byte. Precondition (checked): n <= headroom().
  std::byte* prepend(std::size_t n) noexcept;
  // Grows the packet at the back by n bytes and returns a pointer to the first
  // new byte. Precondition (checked): n <= tailroom().
  std::byte* append(std::size_t n) noexcept;
  // Shortens the packet to its first n bytes. Precondition (checked): n <= size().
  void truncate(std::size_t n) noexcept;

  [[nodiscard]] std::size_t headroom() const noexcept { return head_; }
  [[nodiscard]] std::size_t tailroom() const noexcept;
  [[nodiscard]] std::size_t capacity() const noexcept;

  // Returns the buffer to its pool now; the PacketBuf becomes empty.
  void reset() noexcept;

private:
  friend class PacketPool;
  PacketBuf(PacketPool* pool, std::uint32_t index, std::uint32_t headroom) noexcept
      : pool_(pool), index_(index), head_(headroom), tail_(headroom) {}
  [[nodiscard]] std::byte* base() const noexcept;

  PacketPool* pool_ = nullptr;
  std::uint32_t index_ = 0, head_ = 0, tail_ = 0;
};

class PacketPool {
public:
  // Preallocates `count` buffers of `buf_size` bytes, zero-filled.
  PacketPool(std::uint32_t count, std::uint32_t buf_size);
  // Every PacketBuf must have been returned (checked).
  ~PacketPool();
  PacketPool(const PacketPool&) = delete;
  PacketPool& operator=(const PacketPool&) = delete;

  // A buffer with `headroom` bytes reserved in front and room for at least
  // `min_size` bytes after it; nullopt if the pool is empty or
  // headroom + min_size > buf_size() (M1 has one size class). The most
  // recently returned buffer is reused first.
  [[nodiscard]] std::optional<PacketBuf> alloc(std::uint32_t min_size,
                                               std::uint32_t headroom) noexcept;

  [[nodiscard]] std::uint32_t available() const noexcept {
    return static_cast<std::uint32_t>(free_.size());
  }
  [[nodiscard]] std::uint32_t count() const noexcept { return count_; }
  [[nodiscard]] std::uint32_t buf_size() const noexcept { return buf_size_; }

private:
  friend class PacketBuf;
  void release(std::uint32_t index) noexcept;
  [[nodiscard]] std::byte* buffer(std::uint32_t index) const noexcept;

  std::uint32_t count_, buf_size_;
  std::unique_ptr<std::byte[]> storage_;
  std::vector<std::uint32_t> free_;  // LIFO
};

// One complete IPv4 datagram for the host to send.
struct TxPacket {
  PacketBuf buf;
  std::uint16_t gso_size = 0;   // M4: > 0 means a TCP super-segment split by the kernel
  bool csum_partial = false;    // M4: TCP checksum left to the kernel
};

// Metadata of a received datagram. M1 hosts leave it zero.
struct RxMeta {
  bool csum_verified = false;  // M4: VIRTIO_NET_HDR_F_DATA_VALID; skip transport checksum check
  bool csum_partial = false;   // M4: NEEDS_CSUM (field holds the pseudo-header sum); treated as verified
  std::uint16_t gso_size = 0;  // M4: GRO super-segment; rcv_mss uses it (tcp_measure_rcv_mss)
};

}  // namespace utcp
