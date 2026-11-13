// utcp-httpd's logic against the fake Transport (DESIGN §9).
#include "utcp-httpd/httpd.hpp"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "common/fake_transport.hpp"
#include "common/sha256.hpp"

namespace utcp::app::httpd {
namespace {

constexpr Endpoint target{Ipv4Addr{0x0a000001}, 80};

// A document root with a few files, removed at the end.
class Root {
public:
  Root() {
    dir_ = testing::TempDir() + "/httpd_test_root_" + std::to_string(::getpid());
    ::mkdir(dir_.c_str(), 0755);
    ::mkdir((dir_ + "/sub").c_str(), 0755);
    ::mkdir((dir_ + "/noindex").c_str(), 0755);
    write("a.txt", "hello\n");
    write("empty.txt", "");
    write("sub/index.html", "<p>index</p>\n");
    std::mt19937 rng(5);
    big_.resize(300'000);
    for (char& c : big_) c = static_cast<char>(rng());
    write("big.bin", big_);
    // Outside the root: what an escaping path would reach.
    std::ofstream(testing::TempDir() + "/httpd_test_secret.txt") << "secret";
  }
  ~Root() {
    for (const char* f : {"a.txt", "empty.txt", "sub/index.html", "big.bin"}) ::unlink((dir_ + "/" + f).c_str());
    ::rmdir((dir_ + "/sub").c_str());
    ::rmdir((dir_ + "/noindex").c_str());
    ::rmdir(dir_.c_str());
    ::unlink((testing::TempDir() + "/httpd_test_secret.txt").c_str());
  }
  const std::string& dir() const { return dir_; }
  const std::string& big() const { return big_; }

private:
  void write(const char* name, const std::string& data) { std::ofstream(dir_ + "/" + name, std::ios::binary) << data; }
  std::string dir_, big_;
};

// One client connection: sends `request` (in pieces of `piece` bytes),
// collects everything until the server closes or `stop_after` bytes arrived.
class Client final : public Handler {
public:
  Client(Transport& t, HttpServer& s, std::string request, std::size_t piece = 1 << 20)
      : t_(t), s_(s), req_(std::move(request)), piece_(piece) {}
  void start() { c_ = *t_.connect(target, {}); }
  void on_accept(ConnId l, ConnId c) override { s_.on_accept(l, c); }
  void on_connected(ConnId id) override { id == c_ ? pump() : s_.on_connected(id); }
  void on_writable(ConnId id) override { id == c_ ? pump() : s_.on_writable(id); }
  void on_closed(ConnId id) override { id == c_ ? void(closed = true) : s_.on_closed(id); }
  void on_error(ConnId id, Error e) override { id == c_ ? void(error = true) : s_.on_error(id, e); }
  void on_readable(ConnId id) override {
    if (id != c_) {
      s_.on_readable(id);
      return;
    }
    std::vector<std::byte> b(8192);
    while (true) {
      auto r = t_.recv(c_, b);
      if (!r) return;
      if (*r == 0) {
        eof = true;
        t_.close(c_);
        return;
      }
      response.append(reinterpret_cast<const char*>(b.data()), *r);
    }
  }
  void pump() {
    while (off_ < req_.size()) {
      const std::size_t n = std::min(piece_, req_.size() - off_);
      auto r = t_.send(c_, std::as_bytes(std::span(req_)).subspan(off_, n));
      if (!r) return;
      off_ += *r;
    }
  }

  std::string response;
  bool eof = false, closed = false, error = false;

private:
  Transport& t_;
  HttpServer& s_;
  std::string req_;
  std::size_t piece_, off_ = 0;
  ConnId c_ = no_conn;
};

struct Response {
  int status = 0;
  HttpFields fields;
  std::string body;
};

// Splits a byte stream into responses (Content-Length framing, as the server
// writes them; `head_only` marks responses to HEAD).
std::vector<Response> split(std::string s, const std::vector<bool>& head_only = {}) {
  std::vector<Response> out;
  while (!s.empty()) {
    const auto n = http_head_size(s, {}, false);
    if (!n || *n == 0) break;
    auto h = parse_response_head(std::string_view(s).substr(0, *n));
    EXPECT_TRUE(h);
    if (!h) break;
    s.erase(0, *n);
    Response r{h->status, h->fields, {}};
    const bool head = out.size() < head_only.size() && head_only[out.size()];
    const std::uint64_t len = head ? 0 : **content_length(h->fields);
    r.body = s.substr(0, len);
    s.erase(0, len);
    out.push_back(std::move(r));
  }
  return out;
}

struct Outcome {
  std::vector<Response> responses;
  bool closed_by_server = false;
  Stats stats;
};

Outcome talk(const Root& root, const std::string& request, std::vector<bool> head_only = {},
             std::size_t piece = 1 << 20, std::uint32_t rcv_buf = 64 * 1024) {
  FakeTransport t({.rcv_buf = rcv_buf});
  Options o;
  o.local = Endpoint{Ipv4Addr{}, 80};
  o.root = root.dir();
  o.idle_timeout = Duration::zero();
  HttpServer server(t, o);
  EXPECT_TRUE(server.start());
  Client c(t, server, request, piece);
  c.start();
  t.run(c);
  Outcome r;
  r.responses = split(c.response, head_only);
  r.closed_by_server = c.eof;
  r.stats = server.stats();
  return r;
}

TEST(HttpdGet, FileWithLengthTypeAndClose) {
  Root root;
  const Outcome r = talk(root, "GET /a.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  ASSERT_EQ(r.responses.size(), 1u);
  EXPECT_EQ(r.responses[0].status, 200);
  EXPECT_EQ(r.responses[0].body, "hello\n");
  EXPECT_EQ(*r.responses[0].fields.get("content-type"), "text/plain; charset=utf-8");
  EXPECT_EQ(*r.responses[0].fields.get("content-length"), "6");
  EXPECT_TRUE(r.responses[0].fields.has_token("connection", "close"));
  EXPECT_NE(r.responses[0].fields.get("date"), nullptr);
  EXPECT_TRUE(r.closed_by_server);
}

TEST(HttpdGet, LargeFileThroughASmallWindowInPieces) {
  Root root;
  const Outcome r = talk(root, "GET /big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", {}, 3, 1500);
  ASSERT_EQ(r.responses.size(), 1u);
  EXPECT_EQ(r.responses[0].status, 200);
  EXPECT_EQ(r.responses[0].body.size(), root.big().size());
  EXPECT_EQ(sha256_hex(r.responses[0].body), sha256_hex(root.big()));
  EXPECT_EQ(r.stats.body_bytes, root.big().size());
}

TEST(HttpdGet, EmptyFileAndDirectoryIndex) {
  Root root;
  const Outcome r = talk(root,
                         "GET /empty.txt HTTP/1.1\r\nHost: x\r\n\r\n"
                         "GET /sub/ HTTP/1.1\r\nHost: x\r\n\r\n"
                         "GET /noindex/ HTTP/1.1\r\nHost: x\r\n\r\n"
                         "GET /sub HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
  ASSERT_EQ(r.responses.size(), 4u);
  EXPECT_EQ(r.responses[0].status, 200);
  EXPECT_EQ(r.responses[0].body, "");
  EXPECT_EQ(r.responses[1].status, 200);
  EXPECT_EQ(r.responses[1].body, "<p>index</p>\n");
  EXPECT_EQ(*r.responses[1].fields.get("content-type"), "text/html; charset=utf-8");
  EXPECT_EQ(r.responses[2].status, 404);
  EXPECT_EQ(r.responses[3].status, 404);  // a directory without the slash
}

TEST(HttpdGet, PipelinedRequestsAnsweredInOrderOnOneConnection) {
  Root root;
  const Outcome r = talk(root,
                         "GET /a.txt HTTP/1.1\r\nHost: x\r\n\r\n"
                         "HEAD /big.bin HTTP/1.1\r\nHost: x\r\n\r\n"
                         "GET /missing HTTP/1.1\r\nHost: x\r\n\r\n"
                         "GET /a.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                         {false, true, false, false}, 7);
  ASSERT_EQ(r.responses.size(), 4u);
  EXPECT_EQ(r.responses[0].status, 200);
  EXPECT_EQ(r.responses[0].body, "hello\n");
  EXPECT_EQ(r.responses[1].status, 200);  // HEAD: the length, no body
  EXPECT_EQ(*r.responses[1].fields.get("content-length"), "300000");
  EXPECT_EQ(r.responses[2].status, 404);
  EXPECT_EQ(r.responses[3].body, "hello\n");
  EXPECT_EQ(r.stats.accepted, 1u);
  EXPECT_EQ(r.stats.requests, 4u);
  EXPECT_TRUE(r.closed_by_server);
}

TEST(HttpdGet, PersistentUntilTheClientCloses) {
  Root root;
  const Outcome r = talk(root, "GET /a.txt HTTP/1.1\r\nHost: x\r\n\r\n");
  ASSERT_EQ(r.responses.size(), 1u);
  EXPECT_FALSE(r.closed_by_server);
  EXPECT_EQ(r.responses[0].fields.get("connection"), nullptr);
  // HTTP/1.0 with keep-alive gets it confirmed; without, the server closes.
  const Outcome k = talk(root, "GET /a.txt HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
  ASSERT_EQ(k.responses.size(), 1u);
  EXPECT_TRUE(k.responses[0].fields.has_token("connection", "keep-alive"));
  EXPECT_FALSE(k.closed_by_server);
  const Outcome c = talk(root, "GET /a.txt HTTP/1.0\r\n\r\n");
  ASSERT_EQ(c.responses.size(), 1u);
  EXPECT_TRUE(c.closed_by_server);
}

TEST(HttpdErrors, EscapingPathsAre400) {
  Root root;
  for (const char* p : {"/../httpd_test_secret.txt", "/sub/../../httpd_test_secret.txt",
                        "/%2e%2e/httpd_test_secret.txt", "/..%2Fhttpd_test_secret.txt"}) {
    const Outcome r = talk(root, std::string("GET ") + p + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    ASSERT_EQ(r.responses.size(), 1u) << p;
    EXPECT_EQ(r.responses[0].status, 400) << p;
    EXPECT_EQ(r.responses[0].body.find("secret"), std::string::npos) << p;
  }
}

TEST(HttpdErrors, StatusCodes) {
  Root root;
  struct Case {
    std::string request;
    int status;
    bool closes;
  };
  const std::vector<Case> cases = {
      {"GET /missing HTTP/1.1\r\nHost: x\r\n\r\n", 404, false},
      {"POST /a.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc", 405, false},
      {"GET /a.txt HTTP/1.1\r\n\r\n", 400, true},                      // no Host (RFC 9112 §3.2)
      {"GET /a.txt HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400, true},  // two Hosts
      {"GET /a.txt HTTP/2.0\r\nHost: x\r\n\r\n", 505, true},
      {"GET /" + std::string(9000, 'a') + " HTTP/1.1\r\nHost: x\r\n\r\n", 414, true},
      {"GET /a.txt HTTP/1.1\r\nHost: x\r\nX: a\r\n b\r\n\r\n", 400, true},  // obs-fold
      {"GET /a.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", 501, true},
      {"BREW /a.txt HTTP/1.1\r\nHost: x\r\n\r\n", 405, false},
      {"garbage\r\n\r\n", 400, true},
  };
  for (const Case& c : cases) {
    const Outcome r = talk(root, c.request);
    ASSERT_GE(r.responses.size(), 1u) << c.request.substr(0, 60);
    EXPECT_EQ(r.responses[0].status, c.status) << c.request.substr(0, 60);
    EXPECT_EQ(r.closed_by_server, c.closes) << c.request.substr(0, 60);
    if (c.status == 405) {
      EXPECT_EQ(*r.responses[0].fields.get("allow"), "GET, HEAD");
    }
  }
}

TEST(HttpdErrors, HeaderSectionTooLargeIs431) {
  Root root;
  std::string req = "GET /a.txt HTTP/1.1\r\nHost: x\r\n";
  while (req.size() < 70'000) req += "X-Fill: 0123456789012345678901234567890123456789\r\n";
  const Outcome r = talk(root, req + "\r\n", {}, 1000);
  ASSERT_GE(r.responses.size(), 1u);
  EXPECT_EQ(r.responses[0].status, 431);
  EXPECT_TRUE(r.closed_by_server);
}

TEST(HttpdBodies, RequestBodiesAreSkipped) {
  Root root;
  const Outcome r = talk(root,
                         "GET /a.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789"
                         "GET /a.txt HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                         "3;e=1\r\nabc\r\n0\r\nT: v\r\n\r\n"
                         "GET /empty.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                         {}, 5);
  ASSERT_EQ(r.responses.size(), 3u);
  EXPECT_EQ(r.responses[0].body, "hello\n");
  EXPECT_EQ(r.responses[1].body, "hello\n");
  EXPECT_EQ(r.responses[2].status, 200);
  EXPECT_EQ(r.stats.requests, 3u);
}

TEST(HttpdIdle, IdleConnectionsAreClosed) {
  Root root;
  FakeTransport t;
  Options o;
  o.root = root.dir();
  o.idle_timeout = std::chrono::seconds(5);
  HttpServer server(t, o);
  ASSERT_TRUE(server.start());
  Client c(t, server, "GET /a.txt HTTP/1.1\r\nHost: x\r\n\r\n");
  c.start();
  t.add_oneshot(std::chrono::seconds(30), [&] { t.stop(); });
  t.run(c);
  EXPECT_TRUE(c.eof);
  EXPECT_EQ(server.stats().idle_closed, 1u);
  EXPECT_EQ(split(c.response).size(), 1u);
  server.close_all();
}

TEST(HttpdOptions, Parse) {
  Root root;
  CliParser cli("utcp-httpd", "");
  add_options(cli);
  const auto parse = [&](std::vector<std::string_view> w) -> std::expected<Options, std::string> {
    auto a = cli.parse(w);
    if (!a) return std::unexpected(a.error());
    return parse_options(*a);
  };
  const std::string dir = root.dir() + "/";
  auto o = parse({"--listen", "8080", "--root", dir, "--idle-timeout", "0"});
  ASSERT_TRUE(o) << o.error();
  EXPECT_EQ(o->local.port, 8080);
  EXPECT_EQ(o->root, root.dir());  // trailing slash dropped
  EXPECT_EQ(o->idle_timeout, Duration::zero());
  EXPECT_FALSE(parse({"--root", root.dir() + "/a.txt"}));
  EXPECT_FALSE(parse({"--listen", "99999"}));
}

}  // namespace
}  // namespace utcp::app::httpd
