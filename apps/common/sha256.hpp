// SHA-256 (FIPS 180-4), streaming. The apps hash every byte stream they send
// or receive and print the digest (DESIGN §9).
//
// Two implementations of the compression function: a portable one and one
// using the x86 SHA extensions (SHA-NI), chosen at run time when the CPU has
// them. Both give the same digests; the tests run both.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace utcp::app {

class Sha256 {
public:
  static constexpr std::size_t digest_size = 32;
  static constexpr std::size_t block_size = 64;
  using Digest = std::array<std::uint8_t, digest_size>;

  enum class Impl : std::uint8_t {
    best,      // shani if available, else portable
    portable,  // FIPS 180-4 §6.2.2 in C++
    shani,     // SHA-NI instructions; only valid if shani_available()
  };

  explicit Sha256(Impl impl = Impl::best) noexcept;

  void update(std::span<const std::byte> data) noexcept;
  void update(std::string_view s) noexcept { update(std::as_bytes(std::span(s.data(), s.size()))); }
  // Pads (FIPS 180-4 §5.1.1) and returns the digest; then the object starts
  // a new message (as after reset()).
  [[nodiscard]] Digest finish() noexcept;
  void reset() noexcept;

  // Bytes hashed so far in the current message.
  [[nodiscard]] std::uint64_t size() const noexcept { return total_; }
  // The implementation in use (best is resolved at construction).
  [[nodiscard]] Impl impl() const noexcept { return impl_; }
  // The CPU has SHA-NI, SSSE3 and SSE4.1.
  [[nodiscard]] static bool shani_available() noexcept;

private:
  void blocks(const std::uint8_t* p, std::size_t n) noexcept;

  std::array<std::uint32_t, 8> h_{};
  std::array<std::uint8_t, block_size> buf_{};
  std::size_t buf_len_ = 0;
  std::uint64_t total_ = 0;
  Impl impl_ = Impl::portable;
};

// Lower-case hexadecimal.
[[nodiscard]] std::string to_hex(std::span<const std::uint8_t> bytes);
[[nodiscard]] std::string sha256_hex(std::span<const std::byte> data);
[[nodiscard]] std::string sha256_hex(std::string_view data);

}  // namespace utcp::app
