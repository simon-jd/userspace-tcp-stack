#include "common/http.hpp"

#include <gtest/gtest.h>

#include <string>

namespace utcp::app {
namespace {

std::expected<HttpRequestHead, HttpError> req(std::string_view s, const HttpLimits& l = {}) {
  return parse_request_head(s, l);
}
std::expected<HttpResponseHead, HttpError> resp(std::string_view s, const HttpLimits& l = {}) {
  return parse_response_head(s, l);
}

// --- Request line and fields.

TEST(HttpRequest, ParsesRequestLineAndFields) {
  const auto r = req("GET /a/b?q=1 HTTP/1.1\r\nHost: example.test\r\nAccept:  */*  \r\nX-Empty:\r\n\r\n");
  ASSERT_TRUE(r) << r.error().message;
  EXPECT_EQ(r->method, "GET");
  EXPECT_EQ(r->target, "/a/b?q=1");
  EXPECT_EQ(r->minor, 1);
  ASSERT_EQ(r->fields.size(), 3u);
  EXPECT_EQ(*r->fields.get("host"), "example.test");
  EXPECT_EQ(*r->fields.get("ACCEPT"), "*/*");  // OWS trimmed, names case-insensitive
  EXPECT_EQ(*r->fields.get("x-empty"), "");
  EXPECT_EQ(r->fields.get("missing"), nullptr);
}

TEST(HttpRequest, BareLfAndLeadingEmptyLinesAreAccepted) {
  // RFC 9112 §2.2: a recipient may accept LF alone and ignore empty lines
  // before the request-line.
  const auto r = req("\r\n\nHEAD / HTTP/1.0\nHost: h\n\n");
  ASSERT_TRUE(r) << r.error().message;
  EXPECT_EQ(r->method, "HEAD");
  EXPECT_EQ(r->minor, 0);
}

TEST(HttpRequest, MalformedRequestLinesAre400) {
  for (const char* bad : {"GET  / HTTP/1.1\r\n\r\n", "GET / HTTP/1.1 x\r\n\r\n", "GET /\r\n\r\n",
                          "G(T / HTTP/1.1\r\n\r\n", "GET / HTTP/1.x\r\n\r\n", "GET / http/1.1\r\n\r\n",
                          "GET /a\x01 HTTP/1.1\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n"}) {
    const auto r = req(bad);
    ASSERT_FALSE(r) << bad;
    EXPECT_EQ(r.error().status, 400) << bad;
  }
}

TEST(HttpRequest, OtherMajorVersionIs505) {
  const auto r = req("GET / HTTP/2.0\r\n\r\n");
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().status, 505);
}

TEST(HttpRequest, ObsoleteLineFoldingIsRejected) {
  // RFC 9112 §5.2: a server rejects obs-fold in a request with 400.
  for (const char* bad : {"GET / HTTP/1.1\r\nHost: a\r\nX-Long: one\r\n two\r\n\r\n",
                          "GET / HTTP/1.1\r\nX: a\r\n\tb\r\n\r\n",
                          "GET / HTTP/1.1\r\n first: line\r\n\r\n"}) {
    const auto r = req(bad);
    ASSERT_FALSE(r) << bad;
    EXPECT_EQ(r.error().status, 400);
  }
}

TEST(HttpRequest, InvalidFieldLinesAre400) {
  for (const char* bad : {"GET / HTTP/1.1\r\nHost : a\r\n\r\n",  // space before the colon (§5.1)
                          "GET / HTTP/1.1\r\nNoColon\r\n\r\n", "GET / HTTP/1.1\r\n: v\r\n\r\n",
                          "GET / HTTP/1.1\r\nX: a\x7f\r\n\r\n"}) {
    const auto r = req(bad);
    ASSERT_FALSE(r) << bad;
    EXPECT_EQ(r.error().status, 400) << bad;
  }
}

// --- Limits.

TEST(HttpLimits, HeadSizeFindsTheEndOfTheSection) {
  const std::string head = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
  for (std::size_t n = 0; n < head.size(); ++n) {
    const auto s = http_head_size(std::string_view(head).substr(0, n), {}, true);
    ASSERT_TRUE(s);
    EXPECT_EQ(*s, 0u) << n;
  }
  const auto s = http_head_size(head + "GET /next", {}, true);
  ASSERT_TRUE(s);
  EXPECT_EQ(*s, head.size());
}

TEST(HttpLimits, LongRequestLineIs414AndLargeSectionIs431) {
  HttpLimits l;
  l.max_start_line = 100;
  l.max_head = 300;
  const std::string longline = "GET /" + std::string(200, 'a') + " HTTP/1.1\r\n";
  // Detected while the line is still incomplete, and when complete.
  auto s = http_head_size(longline.substr(0, 150), l, true);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().status, 414);
  s = http_head_size(longline + "\r\n", l, true);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().status, 414);
  const auto r = req(longline + "\r\n", l);
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().status, 414);

  std::string big = "GET / HTTP/1.1\r\n";
  while (big.size() < 400) {
    big += "X-Filler: 0123456789\r\n";
  }
  s = http_head_size(big, l, true);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().status, 431);
}

TEST(HttpLimits, TooManyFieldsIs431) {
  HttpLimits l;
  l.max_fields = 3;
  const auto r = req("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n", l);
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().status, 431);
  EXPECT_TRUE(req("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", l));
}

// --- Status line.

TEST(HttpResponse, StatusLine) {
  auto r = resp("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
  ASSERT_TRUE(r) << r.error().message;
  EXPECT_EQ(r->status, 200);
  EXPECT_EQ(r->reason, "OK");
  EXPECT_EQ(r->minor, 1);
  r = resp("HTTP/1.0 404 Not  Found here\r\n\r\n");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->status, 404);
  EXPECT_EQ(r->reason, "Not  Found here");
  EXPECT_EQ(r->minor, 0);
  // An empty reason phrase, with or without the SP (RFC 9112 §4).
  r = resp("HTTP/1.1 204 \r\n\r\n");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->reason, "");
  r = resp("HTTP/1.1 204\r\n\r\n");
  ASSERT_TRUE(r);
  EXPECT_EQ(r->status, 204);
}

TEST(HttpResponse, MalformedStatusLines) {
  for (const char* bad : {"HTTP/1.1 20 OK\r\n\r\n", "HTTP/1.1 2000 OK\r\n\r\n", "HTTP/1.1  200 OK\r\n\r\n",
                          "HTTP/1.1 099 Low\r\n\r\n", "HTTP/1.1 600 High\r\n\r\n", "HTTP/1.1\r\n\r\n",
                          "HTTP/1.1 abc OK\r\n\r\n", "ICY 200 OK\r\n\r\n", "HTTP/1.1 200 O\x01K\r\n\r\n"}) {
    EXPECT_FALSE(resp(bad)) << bad;
  }
  const auto r = resp("HTTP/3.0 200 OK\r\n\r\n");
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().status, 505);
}

TEST(HttpResponse, ObsoleteLineFoldingIsReplacedBySpace) {
  // RFC 9112 §5.2: a user agent replaces each obs-fold in a response with SP.
  const auto r = resp("HTTP/1.1 200 OK\r\nX-Long: one\r\n   two\r\n\tthree\r\nY: y\r\n\r\n");
  ASSERT_TRUE(r) << r.error().message;
  EXPECT_EQ(*r->fields.get("x-long"), "one two three");
  EXPECT_EQ(*r->fields.get("y"), "y");
}

// --- Framing and persistence.

TEST(HttpFraming, RequestBodies) {
  auto r = req("POST / HTTP/1.1\r\nContent-Length: 12\r\n\r\n");
  EXPECT_EQ(*request_body_framing(*r), (BodyFraming{BodyFraming::Kind::length, 12}));
  r = req("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r)->kind, BodyFraming::Kind::chunked);
  r = req("GET / HTTP/1.1\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r)->kind, BodyFraming::Kind::none);
  r = req("GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r)->kind, BodyFraming::Kind::none);
  // RFC 9112 §6.3: TE and CL together, chunked not last, a bad or
  // conflicting Content-Length: 400; another coding: 501.
  r = req("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r).error().status, 400);
  r = req("POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r).error().status, 400);
  r = req("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r).error().status, 501);
  r = req("POST / HTTP/1.1\r\nContent-Length: 1x\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r).error().status, 400);
  r = req("POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r).error().status, 400);
  r = req("POST / HTTP/1.1\r\nContent-Length: 3, 3\r\nContent-Length: 3\r\n\r\n");
  EXPECT_EQ(*request_body_framing(*r), (BodyFraming{BodyFraming::Kind::length, 3}));
  r = req("POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n");
  EXPECT_EQ(request_body_framing(*r).error().status, 400);
}

TEST(HttpFraming, ResponseBodies) {
  auto r = resp("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n");
  EXPECT_EQ(*response_body_framing(*r, false), (BodyFraming{BodyFraming::Kind::length, 7}));
  EXPECT_EQ(response_body_framing(*r, true)->kind, BodyFraming::Kind::none);  // HEAD
  r = resp("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 7\r\n\r\n");
  EXPECT_EQ(response_body_framing(*r, false)->kind, BodyFraming::Kind::chunked);
  r = resp("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n");
  EXPECT_EQ(response_body_framing(*r, false)->kind, BodyFraming::Kind::until_close);
  r = resp("HTTP/1.1 200 OK\r\n\r\n");
  EXPECT_EQ(response_body_framing(*r, false)->kind, BodyFraming::Kind::until_close);
  for (const char* none : {"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n",
                           "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
                           "HTTP/1.1 100 Continue\r\n\r\n"}) {
    EXPECT_EQ(response_body_framing(*resp(none), false)->kind, BodyFraming::Kind::none) << none;
  }
  EXPECT_FALSE(response_body_framing(*resp("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"), false));
}

TEST(HttpFraming, Persistence) {
  EXPECT_TRUE(request_keep_alive(*req("GET / HTTP/1.1\r\n\r\n")));
  EXPECT_FALSE(request_keep_alive(*req("GET / HTTP/1.1\r\nConnection: Close\r\n\r\n")));
  EXPECT_FALSE(request_keep_alive(*req("GET / HTTP/1.1\r\nConnection: x, close\r\n\r\n")));
  EXPECT_FALSE(request_keep_alive(*req("GET / HTTP/1.0\r\n\r\n")));
  EXPECT_TRUE(request_keep_alive(*req("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")));
  EXPECT_FALSE(response_keep_alive(*resp("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")));
  EXPECT_TRUE(response_keep_alive(*resp("HTTP/1.1 200 OK\r\n\r\n")));
}

// --- Paths, URLs and helpers.

TEST(HttpPath, DecodesAndNormalizes) {
  EXPECT_EQ(*request_path("/"), "/");
  EXPECT_EQ(*request_path("/a/b.txt?x=../.."), "/a/b.txt");
  EXPECT_EQ(*request_path("/a//b/./c/"), "/a/b/c/");
  EXPECT_EQ(*request_path("/a/b/../c"), "/a/c");
  EXPECT_EQ(*request_path("/a/b/.."), "/a/");
  EXPECT_EQ(*request_path("/a%20b/%41"), "/a b/A");
  EXPECT_EQ(*request_path("http://host:8080/x/y"), "/x/y");
  EXPECT_EQ(*request_path("http://host?q"), "/");
}

TEST(HttpPath, RejectsEscapesAndBadForms) {
  for (const char* bad : {"/..", "/../etc/passwd", "/a/../../b", "/%2e%2e/x", "/a/%2E%2E/%2e%2E/x",
                          "/..%2fx", "/%00", "/%zz", "/%4", "*", "host/x", "https://h/x", "http:///x"}) {
    const auto p = request_path(bad);
    ASSERT_FALSE(p) << bad << " -> " << *p;
    EXPECT_EQ(p.error().status, 400) << bad;
  }
}

TEST(HttpUrl, Parses) {
  auto u = parse_http_url("http://Example.TEST:8080/a/b?c=d#frag");
  ASSERT_TRUE(u) << u.error();
  EXPECT_EQ(*u, (HttpUrl{"example.test", 8080, "/a/b?c=d"}));
  u = parse_http_url("http://10.0.0.1");
  ASSERT_TRUE(u);
  EXPECT_EQ(*u, (HttpUrl{"10.0.0.1", 80, "/"}));
  u = parse_http_url("http://h?x");
  ASSERT_TRUE(u);
  EXPECT_EQ(u->target, "/?x");
  for (const char* bad : {"https://h/", "ftp://h", "http://", "http://:80/", "http://h:0/", "http://h:65536/",
                          "http://h:8a/", "http://u@h/", "http://[::1]/", "http://h/a b", "h/x"}) {
    EXPECT_FALSE(parse_http_url(bad)) << bad;
  }
}

TEST(HttpMisc, DateReasonMimeToken) {
  EXPECT_EQ(http_date(784111777), "Sun, 06 Nov 1994 08:49:37 GMT");  // RFC 9110 §5.6.7
  EXPECT_EQ(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
  EXPECT_EQ(status_reason(404), "Not Found");
  EXPECT_EQ(status_reason(505), "HTTP Version Not Supported");
  EXPECT_EQ(mime_type("/a/b.HTML"), "text/html; charset=utf-8");
  EXPECT_EQ(mime_type("/x.bin"), "application/octet-stream");
  EXPECT_EQ(mime_type("/.hidden"), "application/octet-stream");
  EXPECT_EQ(mime_type("/dir.d/file"), "application/octet-stream");
  EXPECT_TRUE(is_token("X-Custom_1!"));
  EXPECT_FALSE(is_token("a b"));
  EXPECT_FALSE(is_token(""));
  HttpFields f;
  f.add("Connection", "keep-alive, Upgrade");
  f.add("connection", " , close ,");
  EXPECT_EQ(f.list("CONNECTION"), (std::vector<std::string_view>{"keep-alive", "Upgrade", "close"}));
  EXPECT_TRUE(f.has_token("connection", "UPGRADE"));
  EXPECT_EQ(f.count("connection"), 2u);
}

}  // namespace
}  // namespace utcp::app
