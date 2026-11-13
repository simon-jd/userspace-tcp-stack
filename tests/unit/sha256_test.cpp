#include "common/sha256.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace utcp::app {
namespace {

// FIPS 180-4 examples (NIST CSRC "SHA256.pdf" example values, and the one
// million 'a' vector of FIPS 180-2 appendix B.3).
struct Vector {
  std::string message;
  const char* digest;
};

std::vector<Vector> vectors() {
  return {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",  // 448 bits
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {std::string(1'000'000, 'a'),
       "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
  };
}

std::vector<Sha256::Impl> impls() {
  std::vector<Sha256::Impl> out{Sha256::Impl::portable};
  if (Sha256::shani_available()) {
    out.push_back(Sha256::Impl::shani);
  }
  return out;
}

std::string digest_of(Sha256& h) { return to_hex(h.finish()); }

TEST(Sha256, FipsVectorsInOneUpdate) {
  for (const Sha256::Impl impl : impls()) {
    for (const Vector& v : vectors()) {
      Sha256 h(impl);
      h.update(v.message);
      EXPECT_EQ(h.size(), v.message.size());
      EXPECT_EQ(digest_of(h), v.digest) << "impl " << int(impl) << " len " << v.message.size();
    }
  }
}

TEST(Sha256, StreamingInPiecesGivesTheSameDigest) {
  for (const Sha256::Impl impl : impls()) {
    for (const Vector& v : vectors()) {
      for (const std::size_t piece : {std::size_t{1}, std::size_t{63}, std::size_t{64}, std::size_t{65}}) {
        Sha256 h(impl);
        for (std::size_t off = 0; off < v.message.size(); off += piece) {
          h.update(std::string_view(v.message).substr(off, piece));
        }
        EXPECT_EQ(digest_of(h), v.digest) << "impl " << int(impl) << " piece " << piece;
      }
    }
  }
}

TEST(Sha256, ImplementationsAgreeOnEveryLengthUpTo300) {
  if (!Sha256::shani_available()) {
    GTEST_SKIP() << "no SHA-NI on this CPU";
  }
  std::string msg;
  for (std::size_t len = 0; len <= 300; ++len) {
    Sha256 a(Sha256::Impl::portable);
    Sha256 b(Sha256::Impl::shani);
    a.update(msg);
    b.update(msg);
    EXPECT_EQ(to_hex(a.finish()), to_hex(b.finish())) << len;
    msg += static_cast<char>((len * 131 + 7) & 0xff);
  }
}

TEST(Sha256, FinishStartsANewMessage) {
  Sha256 h;
  h.update("garbage");
  (void)h.finish();
  EXPECT_EQ(h.size(), 0u);
  h.update("abc");
  EXPECT_EQ(digest_of(h), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256, HexHelpers) {
  EXPECT_EQ(sha256_hex(std::string_view("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const std::uint8_t b[] = {0x00, 0x0f, 0xa5, 0xff};
  EXPECT_EQ(to_hex(b), "000fa5ff");
}

}  // namespace
}  // namespace utcp::app
