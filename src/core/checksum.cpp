#include "utcp/checksum.hpp"

#include <bit>
#include <cstring>

namespace utcp {
namespace {

// Folds a one's-complement sum held in a wider integer to 16 bits by adding
// the carries back in (end-around carry).
constexpr std::uint16_t fold16(std::uint64_t sum) noexcept {
  sum = (sum & 0xFFFF'FFFFu) + (sum >> 32);
  while ((sum >> 16) != 0) {
    sum = (sum & 0xFFFFu) + (sum >> 16);
  }
  return static_cast<std::uint16_t>(sum);
}

// One's-complement sum of `data` read as big-endian 16-bit words starting at
// an even offset, with an odd final byte padded by a zero byte.
//
// It loads 8 bytes at a time in native byte order and adds them with
// end-around carry. Since 2^16 = 1 (mod 2^16 - 1), summing 64-bit words and
// then folding gives the same result as summing 16-bit words (RFC 1071
// section 2(C)), and on a little-endian machine the native sum is the
// byte-swapped big-endian sum (section 2(B)), so one swap at the end fixes it.
// memcpy makes the loads safe for any alignment.
std::uint16_t sum_words(const std::byte* p, std::size_t n) noexcept {
  std::uint64_t acc = 0;
  auto add64 = [&acc](std::uint64_t w) {
    acc += w;
    acc += static_cast<std::uint64_t>(acc < w);  // end-around carry
  };
  while (n >= 8) {
    std::uint64_t w = 0;
    std::memcpy(&w, p, 8);
    add64(w);
    p += 8;
    n -= 8;
  }
  if (n > 0) {
    // The zero bytes after the tail are the RFC 1071 padding.
    std::uint64_t w = 0;
    std::memcpy(&w, p, n);
    add64(w);
  }
  const std::uint16_t native = fold16(acc);
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(native);
  } else {
    return native;
  }
}

constexpr std::uint16_t complement(std::uint16_t v) noexcept {
  return static_cast<std::uint16_t>(~v);
}

}  // namespace

void ChecksumAccumulator::add(std::span<const std::byte> data) noexcept {
  std::uint16_t s = sum_words(data.data(), data.size());
  if (bytes_ % 2 != 0) {
    // The data starts at an odd offset in the stream, so every byte sits in
    // the other half of its word; that is the byte-swapped sum.
    s = std::byteswap(s);
  }
  acc_ += s;
  bytes_ += data.size();
}

void ChecksumAccumulator::add_u16(std::uint16_t value) noexcept {
  acc_ += (bytes_ % 2 != 0) ? std::byteswap(value) : value;
  bytes_ += 2;
}

void ChecksumAccumulator::add_u32(std::uint32_t value) noexcept {
  add_u16(static_cast<std::uint16_t>(value >> 16));
  add_u16(static_cast<std::uint16_t>(value & 0xFFFFu));
}

std::uint16_t ChecksumAccumulator::sum() const noexcept { return fold16(acc_); }

std::uint16_t internet_checksum(std::span<const std::byte> data) noexcept {
  ChecksumAccumulator acc;
  acc.add(data);
  return acc.checksum();
}

bool checksum_valid(std::span<const std::byte> data) noexcept {
  ChecksumAccumulator acc;
  acc.add(data);
  return acc.valid();
}

// RFC 1624 section 3, eqn. 3: HC' = ~(~HC + ~m + m').
std::uint16_t checksum_update16(std::uint16_t checksum, std::uint16_t old_word,
                                std::uint16_t new_word) noexcept {
  const std::uint64_t s = std::uint64_t{complement(checksum)} + complement(old_word) + new_word;
  return complement(fold16(s));
}

std::uint16_t checksum_update32(std::uint16_t checksum, std::uint32_t old_value,
                                std::uint32_t new_value) noexcept {
  const auto hi = [](std::uint32_t v) { return static_cast<std::uint16_t>(v >> 16); };
  const auto lo = [](std::uint32_t v) { return static_cast<std::uint16_t>(v & 0xFFFFu); };
  const std::uint64_t s = std::uint64_t{complement(checksum)} + complement(hi(old_value)) +
                          complement(lo(old_value)) + hi(new_value) + lo(new_value);
  return complement(fold16(s));
}

void add_ipv4_pseudo_header(ChecksumAccumulator& acc, std::uint32_t src, std::uint32_t dst,
                            std::uint8_t protocol, std::uint16_t length) noexcept {
  acc.add_u32(src);
  acc.add_u32(dst);
  acc.add_u16(protocol);  // zero byte, then the protocol byte
  acc.add_u16(length);
}

namespace {

ChecksumAccumulator transport_sum(std::uint32_t src, std::uint32_t dst, std::uint8_t protocol,
                                  std::span<const std::byte> payload) noexcept {
  ChecksumAccumulator acc;
  add_ipv4_pseudo_header(acc, src, dst, protocol, static_cast<std::uint16_t>(payload.size()));
  acc.add(payload);
  return acc;
}

}  // namespace

std::uint16_t ipv4_transport_checksum(std::uint32_t src, std::uint32_t dst,
                                      std::uint8_t protocol,
                                      std::span<const std::byte> payload) noexcept {
  return transport_sum(src, dst, protocol, payload).checksum();
}

bool ipv4_transport_checksum_valid(std::uint32_t src, std::uint32_t dst, std::uint8_t protocol,
                                   std::span<const std::byte> payload) noexcept {
  return transport_sum(src, dst, protocol, payload).valid();
}

}  // namespace utcp
