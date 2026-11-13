#include "common/chunked.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace utcp::app {
namespace {

// RFC 9112 §7.1 example shapes: extensions on chunks and on the last chunk,
// a quoted-string extension value with a quoted-pair, trailer fields, and
// data that contains CRLF and hexadecimal-looking bytes.
const std::string body_data = "Wiki\r\npedia in\r\n\r\nchunks.0\r\n";
const std::string encoded =
    "4;name=value\r\nWiki\r\n"
    "5 ; a ; b = \"q\\\"uoted\"\r\n\r\nped\r\n"
    "F\r\nia in\r\n\r\nchunks\r\n"
    "000004\r\n.0\r\n\r\n"
    "0;last=\"yes\"\r\n"
    "Expires: never\r\nX-Sum:  abc  \r\n"
    "\r\n";

struct Decoded {
  std::string data;
  std::size_t consumed = 0;
  bool done = false;
  std::string error;
};

// Feeds `in` in pieces of the given sizes (cycled), continuing after each
// piece with the rest of that piece, as a reader would.
Decoded decode(ChunkedDecoder& d, const std::string& in, const std::vector<std::size_t>& pieces) {
  Decoded out;
  std::size_t pos = 0, k = 0;
  while (pos < in.size() && !d.done()) {
    const std::size_t n = std::min(pieces[k++ % pieces.size()], in.size() - pos);
    auto r = d.feed(std::string_view(in).substr(pos, n), out.data);
    if (!r) {
      out.error = r.error();
      break;
    }
    pos += *r;
    if (*r < n) {
      break;  // body ended inside the piece
    }
  }
  out.consumed = pos;
  out.done = d.done();
  return out;
}

TEST(ChunkedDecoder, WholeInput) {
  ChunkedDecoder d;
  const Decoded r = decode(d, encoded + "NEXT", {encoded.size() + 4});
  ASSERT_TRUE(r.error.empty()) << r.error;
  EXPECT_TRUE(r.done);
  EXPECT_EQ(r.data, body_data);
  EXPECT_EQ(r.consumed, encoded.size());  // "NEXT" belongs to the next message
  EXPECT_EQ(d.chunks(), 4u);
  EXPECT_EQ(d.data_bytes(), body_data.size());
  ASSERT_EQ(d.trailers().size(), 2u);
  EXPECT_EQ(*d.trailers().get("expires"), "never");
  EXPECT_EQ(*d.trailers().get("x-sum"), "abc");
}

TEST(ChunkedDecoder, OneByteAtATime) {
  ChunkedDecoder d;
  const Decoded r = decode(d, encoded, {1});
  ASSERT_TRUE(r.error.empty()) << r.error;
  EXPECT_TRUE(r.done);
  EXPECT_EQ(r.data, body_data);
  EXPECT_EQ(d.trailers().size(), 2u);
}

TEST(ChunkedDecoder, RandomSplitsOfALargeBody) {
  std::mt19937_64 rng(42);
  std::string data(300000, '\0');
  for (char& c : data) {
    c = static_cast<char>(rng());
  }
  // Encode with random chunk sizes and occasional extensions.
  std::string enc;
  std::size_t pos = 0;
  while (pos < data.size()) {
    const std::size_t n = std::min<std::size_t>(data.size() - pos, 1 + rng() % 20000);
    char hex[32];
    std::snprintf(hex, sizeof hex, (rng() % 2) ? "%zx" : "%zX", n);
    enc += hex;
    if (rng() % 3 == 0) {
      enc += ";ext=" + std::to_string(n);
    }
    enc += (rng() % 4 == 0) ? "\n" : "\r\n";  // bare LF accepted (RFC 9112 §2.2)
    enc.append(data, pos, n);
    enc += "\r\n";
    pos += n;
  }
  enc += "0\r\nT: 1\r\n\r\n";
  for (int round = 0; round < 50; ++round) {
    std::vector<std::size_t> pieces;
    for (int i = 0; i < 64; ++i) {
      pieces.push_back(1 + rng() % (round < 25 ? 17 : 70000));
    }
    ChunkedDecoder d;
    const Decoded r = decode(d, enc, pieces);
    ASSERT_TRUE(r.error.empty()) << r.error;
    ASSERT_TRUE(r.done) << round;
    ASSERT_EQ(r.data.size(), data.size());
    ASSERT_TRUE(r.data == data) << round;
    EXPECT_EQ(r.consumed, enc.size());
  }
}

TEST(ChunkedDecoder, EmptyBody) {
  ChunkedDecoder d;
  const Decoded r = decode(d, "0\r\n\r\n", {1});
  EXPECT_TRUE(r.done);
  EXPECT_EQ(r.data, "");
  EXPECT_EQ(d.chunks(), 0u);
}

TEST(ChunkedDecoder, Errors) {
  for (const char* bad : {
           "\r\n",                          // size missing
           "g\r\n",                         // not hex
           "-1\r\n",                        // sign
           "4x\r\nWiki\r\n0\r\n\r\n",       // junk after the size
           "4;\r\nWiki\r\n0\r\n\r\n",       // extension without a name
           "4;a=\r\nWiki\r\n0\r\n\r\n",     // extension without a value
           "4;a=\"x\r\nWiki\r\n0\r\n\r\n",  // unterminated quoted-string
           "4\r\nWikiX\r\n0\r\n\r\n",       // data longer than the size
           "4\r\nWiki\rX",                  // bare CR after data
           "4\rX",                          // bare CR in the size line
           "0\r\n folded: x\r\n\r\n",       // obs-fold in the trailers
           "0\r\nno colon\r\n\r\n",         // malformed trailer
           "1000000000000000000\r\n",       // size too large
       }) {
    ChunkedDecoder d;
    const Decoded r = decode(d, bad, {1});
    EXPECT_FALSE(r.error.empty()) << bad;
    // Failed stays failed.
    std::string sink;
    EXPECT_FALSE(d.feed("0\r\n\r\n", sink)) << bad;
  }
}

TEST(ChunkedDecoder, LineAndTrailerLimits) {
  ChunkedLimits l;
  l.max_line = 16;
  l.max_trailers = 32;
  l.max_trailer_fields = 1;
  {
    ChunkedDecoder d(l);
    EXPECT_FALSE(decode(d, "1;" + std::string(20, 'a') + "\r\n", {1}).error.empty());
  }
  {
    ChunkedDecoder d(l);
    EXPECT_FALSE(decode(d, "0\r\nA: " + std::string(40, 'v') + "\r\n\r\n", {3}).error.empty());
  }
  {
    ChunkedDecoder d(l);
    EXPECT_FALSE(decode(d, "0\r\nA: 1\r\nB: 2\r\n\r\n", {3}).error.empty());
  }
  {
    ChunkedDecoder d(l);
    EXPECT_TRUE(decode(d, "0\r\nA: 1\r\n\r\n", {3}).done);
  }
}

}  // namespace
}  // namespace utcp::app
