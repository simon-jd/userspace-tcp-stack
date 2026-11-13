#include "common/sha256.hpp"

#include <algorithm>
#include <bit>
#include <cstring>

#if defined(__x86_64__)
#include <cpuid.h>
#include <immintrin.h>
#endif

#include "utcp/check.hpp"

namespace utcp::app {

namespace {

// FIPS 180-4 §4.2.2.
constexpr std::array<std::uint32_t, 64> k = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// FIPS 180-4 §5.3.3.
constexpr std::array<std::uint32_t, 8> h0 = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

std::uint32_t load_be32(const std::uint8_t* p) noexcept {
  return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) |
         std::uint32_t{p[3]};
}

// FIPS 180-4 §6.2.2, one 64-byte block at a time.
void blocks_portable(std::array<std::uint32_t, 8>& h, const std::uint8_t* p, std::size_t n) noexcept {
  for (; n > 0; --n, p += 64) {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t t = 0; t < 16; ++t) {
      w[t] = load_be32(p + 4 * t);
    }
    for (std::size_t t = 16; t < 64; ++t) {
      const std::uint32_t s0 = std::rotr(w[t - 15], 7) ^ std::rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
      const std::uint32_t s1 = std::rotr(w[t - 2], 17) ^ std::rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
      w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (std::size_t t = 0; t < 64; ++t) {
      const std::uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      const std::uint32_t ch = (e & f) ^ (~e & g);
      const std::uint32_t t1 = hh + s1 + ch + k[t] + w[t];
      const std::uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t t2 = s0 + maj;
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
}

#if defined(__x86_64__)

// The same function with the SHA-NI instructions (Intel, "New Instructions
// Supporting the Secure Hash Algorithm on Intel Architecture Processors",
// 2013). The state is kept as ABEF/CDGH; each group of 4 rounds adds K to the
// message words, runs two sha256rnds2 and extends the schedule with
// sha256msg1/msg2 (W[t] for t >= 16).
__attribute__((target("sha,sse4.1,ssse3"))) void blocks_shani(std::array<std::uint32_t, 8>& h,
                                                               const std::uint8_t* p,
                                                               std::size_t n) noexcept {
  const __m128i byteswap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
  __m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&h[0]));      // DCBA
  __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&h[4]));   // HGFE
  tmp = _mm_shuffle_epi32(tmp, 0xB1);                                           // CDAB
  state1 = _mm_shuffle_epi32(state1, 0x1B);                                     // EFGH
  __m128i state0 = _mm_alignr_epi8(tmp, state1, 8);                             // ABEF
  state1 = _mm_blend_epi16(state1, tmp, 0xF0);                                  // CDGH

  for (; n > 0; --n, p += 64) {
    const __m128i abef_save = state0;
    const __m128i cdgh_save = state1;
    __m128i m[4];
    for (int g = 0; g < 16; ++g) {
      __m128i& cur = m[g & 3];
      if (g < 4) {
        cur = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 16 * g)),
                               byteswap);
      }
      __m128i msg =
          _mm_add_epi32(cur, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&k[std::size_t(4 * g)])));
      state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
      if (g >= 3 && g < 15) {
        __m128i& next = m[(g + 1) & 3];
        next = _mm_add_epi32(next, _mm_alignr_epi8(cur, m[(g + 3) & 3], 4));
        next = _mm_sha256msg2_epu32(next, cur);
      }
      msg = _mm_shuffle_epi32(msg, 0x0E);
      state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
      if (g >= 1 && g < 13) {
        __m128i& prev = m[(g + 3) & 3];
        prev = _mm_sha256msg1_epu32(prev, cur);
      }
    }
    state0 = _mm_add_epi32(state0, abef_save);
    state1 = _mm_add_epi32(state1, cdgh_save);
  }

  tmp = _mm_shuffle_epi32(state0, 0x1B);        // FEBA
  state1 = _mm_shuffle_epi32(state1, 0xB1);     // DCHG
  state0 = _mm_blend_epi16(tmp, state1, 0xF0);  // DCBA
  state1 = _mm_alignr_epi8(state1, tmp, 8);     // HGFE
  _mm_storeu_si128(reinterpret_cast<__m128i*>(&h[0]), state0);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(&h[4]), state1);
}

bool detect_shani() noexcept {
  unsigned a = 0, b = 0, c = 0, d = 0;
  if (__get_cpuid(1, &a, &b, &c, &d) == 0) {
    return false;
  }
  const bool ssse3 = (c & (1u << 9)) != 0;
  const bool sse41 = (c & (1u << 19)) != 0;
  if (__get_cpuid_count(7, 0, &a, &b, &c, &d) == 0) {
    return false;
  }
  const bool sha = (b & (1u << 29)) != 0;
  return ssse3 && sse41 && sha;
}

#endif

}  // namespace

bool Sha256::shani_available() noexcept {
#if defined(__x86_64__)
  static const bool available = detect_shani();
  return available;
#else
  return false;
#endif
}

Sha256::Sha256(Impl impl) noexcept {
  if (impl == Impl::best) {
    impl = shani_available() ? Impl::shani : Impl::portable;
  }
  UTCP_CHECK(impl != Impl::shani || shani_available());
  impl_ = impl;
  reset();
}

void Sha256::reset() noexcept {
  h_ = h0;
  buf_len_ = 0;
  total_ = 0;
}

void Sha256::blocks(const std::uint8_t* p, std::size_t n) noexcept {
#if defined(__x86_64__)
  if (impl_ == Impl::shani) {
    blocks_shani(h_, p, n);
    return;
  }
#endif
  blocks_portable(h_, p, n);
}

void Sha256::update(std::span<const std::byte> data) noexcept {
  const auto* p = reinterpret_cast<const std::uint8_t*>(data.data());
  std::size_t n = data.size();
  total_ += n;
  if (buf_len_ > 0) {
    const std::size_t take = std::min(n, block_size - buf_len_);
    std::memcpy(buf_.data() + buf_len_, p, take);
    buf_len_ += take;
    p += take;
    n -= take;
    if (buf_len_ < block_size) {
      return;
    }
    blocks(buf_.data(), 1);
    buf_len_ = 0;
  }
  if (n >= block_size) {
    blocks(p, n / block_size);
    p += n - n % block_size;
    n %= block_size;
  }
  if (n > 0) {
    std::memcpy(buf_.data(), p, n);
    buf_len_ = n;
  }
}

Sha256::Digest Sha256::finish() noexcept {
  // FIPS 180-4 §5.1.1: a 1 bit, zeros to 56 mod 64 bytes, the length in bits.
  const std::uint64_t bits = total_ * 8;
  buf_[buf_len_++] = 0x80;
  if (buf_len_ > 56) {
    std::memset(buf_.data() + buf_len_, 0, block_size - buf_len_);
    blocks(buf_.data(), 1);
    buf_len_ = 0;
  }
  std::memset(buf_.data() + buf_len_, 0, 56 - buf_len_);
  for (int i = 0; i < 8; ++i) {
    buf_[56 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
  }
  blocks(buf_.data(), 1);
  Digest out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[4 * i] = static_cast<std::uint8_t>(h_[i] >> 24);
    out[4 * i + 1] = static_cast<std::uint8_t>(h_[i] >> 16);
    out[4 * i + 2] = static_cast<std::uint8_t>(h_[i] >> 8);
    out[4 * i + 3] = static_cast<std::uint8_t>(h_[i]);
  }
  reset();
  return out;
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string s;
  s.reserve(bytes.size() * 2);
  for (const std::uint8_t b : bytes) {
    s += digits[b >> 4];
    s += digits[b & 0xf];
  }
  return s;
}

std::string sha256_hex(std::span<const std::byte> data) {
  Sha256 h;
  h.update(data);
  const Sha256::Digest d = h.finish();
  return to_hex(d);
}

std::string sha256_hex(std::string_view data) {
  return sha256_hex(std::as_bytes(std::span(data.data(), data.size())));
}

}  // namespace utcp::app
