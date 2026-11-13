// utcp-http-get's logic against the fake Transport (DESIGN §9).
#include "utcp-http-get/http_get.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "common/dns.hpp"
#include "common/fake_transport.hpp"

namespace utcp::app::http_get {
namespace {

// A scripted HTTP server on port 80 of the fake host: reads the request head,
// then sends `response` in pieces of `piece` bytes and closes (or not).
// Optionally a DNS server on port 53 answering A queries with `dns_addr`.
class World final : public Handler {
public:
  World(FakeTransport& t, HttpGet& g) : t_(t), g_(g) {}

  std::string response;
  std::size_t piece = 1 << 20;
  bool close_after = true;
  std::string request;  // as received
  std::optional<Ipv4Addr> dns_addr;
  int dns_queries = 0;

  void start() {
    l_ = *t_.listen(Endpoint{Ipv4Addr{}, 80}, 8, {});
    if (dns_addr) {
      dns_ = *t_.udp_open(Endpoint{Ipv4Addr{}, dns_port});
    }
  }
  bool mine(ConnId id) const { return id == l_ || id == c_ || id == dns_; }

  void on_accept(ConnId, ConnId c) override { c_ = c; }
  void on_connected(ConnId id) override { g_.on_connected(id); }
  void on_writable(ConnId id) override { mine(id) ? pump() : g_.on_writable(id); }
  void on_closed(ConnId id) override {
    if (!mine(id)) g_.on_closed(id);
  }
  void on_error(ConnId id, Error e) override {
    if (!mine(id)) g_.on_error(id, e);
  }
  void on_readable(ConnId id) override {
    if (id == dns_) {
      answer_dns();
      return;
    }
    if (!mine(id)) {
      g_.on_readable(id);
      return;
    }
    std::vector<std::byte> b(4096);
    while (auto r = t_.recv(c_, b)) {
      if (*r == 0) return;
      request.append(reinterpret_cast<const char*>(b.data()), *r);
    }
    if (!sending_ && request.find("\r\n\r\n") != std::string::npos) {
      sending_ = true;
      pump();
    }
  }

private:
  void pump() {
    while (sent_ < response.size()) {
      const std::size_t n = std::min(piece, response.size() - sent_);
      auto r = t_.send(c_, std::as_bytes(std::span(response)).subspan(sent_, n));
      if (!r) return;
      sent_ += *r;
    }
    if (close_after && !closed_) {
      closed_ = true;
      t_.shutdown_write(c_);
    }
  }
  void answer_dns() {
    std::vector<std::byte> q(512);
    while (auto r = t_.recv_from(dns_, q)) {
      ++dns_queries;
      // Header with QR, RD, RA; the question copied; one A answer whose
      // owner is a pointer to the question (RFC 1035 §4.1.4).
      std::vector<std::byte> a(q.begin(), q.begin() + static_cast<std::ptrdiff_t>(r->len));
      a[2] = std::byte{0x81};
      a[3] = std::byte{0x80};
      a[7] = std::byte{1};  // ANCOUNT
      const std::uint32_t ip = dns_addr->v;
      for (const int x : {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}) a.push_back(static_cast<std::byte>(x));
      for (int i = 3; i >= 0; --i) a.push_back(static_cast<std::byte>(ip >> (8 * i)));
      (void)t_.send_to(dns_, r->from, a);
    }
  }

  FakeTransport& t_;
  HttpGet& g_;
  ConnId l_ = no_conn, c_ = no_conn, dns_ = no_conn;
  std::size_t sent_ = 0;
  bool sending_ = false, closed_ = false;
};

Options options(const std::string& url) {
  Options o;
  o.url_text = url;
  o.url = *parse_http_url(url);
  return o;
}

struct Got {
  Result result;
  std::string body;
  std::string request;
  int dns_queries = 0;
};

Got fetch(const Options& o, const std::string& response, std::size_t piece = 1 << 20,
          bool close_after = true, std::optional<Ipv4Addr> dns_addr = {}) {
  FakeTransport t({.rcv_buf = 3000});
  Got g;
  HttpGet get(t, o, [&g](std::span<const std::byte> b) {
    g.body.append(reinterpret_cast<const char*>(b.data()), b.size());
    return true;
  });
  World w(t, get);
  w.response = response;
  w.piece = piece;
  w.close_after = close_after;
  w.dns_addr = dns_addr;
  w.start();
  auto s = get.start();
  if (!s) {
    g.result.error = s.error();
    return g;
  }
  t.run(w);
  EXPECT_TRUE(get.done());
  g.result = get.result();
  g.request = w.request;
  g.dns_queries = w.dns_queries;
  return g;
}

const std::string body = "The quick brown fox\r\njumps over\r\n\r\nthe lazy dog. 0123456789";

TEST(HttpGetFetch, SendsAMinimalRequest) {
  const Got g = fetch(options("http://10.0.0.1:80/p/q?x=1"), "HTTP/1.1 204 No Content\r\n\r\n");
  EXPECT_EQ(g.request,
            "GET /p/q?x=1 HTTP/1.1\r\nHost: 10.0.0.1\r\nUser-Agent: utcp-http-get\r\nAccept: */*\r\n"
            "Connection: close\r\n\r\n");
  EXPECT_TRUE(g.result.ok) << g.result.error;
  EXPECT_EQ(g.result.status, 204);
  // Nothing listens on 8080 of the fake host.
  const Got p = fetch(options("http://10.0.0.1:8080/"), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  EXPECT_FALSE(p.result.ok);
  EXPECT_NE(p.result.error.find("connection_refused"), std::string::npos) << p.result.error;
}

TEST(HttpGetFetch, ContentLengthBody) {
  for (const std::size_t piece : {std::size_t{1}, std::size_t{7}, std::size_t{1} << 20}) {
    const Got g = fetch(options("http://10.0.0.1/f"),
                        "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
                            "\r\n\r\n" + body,
                        piece);
    EXPECT_TRUE(g.result.ok) << g.result.error;
    EXPECT_EQ(g.body, body);
    EXPECT_EQ(g.result.framing, "length");
    EXPECT_EQ(g.result.sha256, sha256_hex(body));
    EXPECT_EQ(g.result.body_bytes, body.size());
  }
}

TEST(HttpGetFetch, ContentLengthDoesNotNeedTheClose) {
  // The body ends at Content-Length even if the server keeps the connection.
  const Got g = fetch(options("http://10.0.0.1/f"),
                      "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 1 << 20, false);
  EXPECT_TRUE(g.result.ok) << g.result.error;
  EXPECT_EQ(g.body, "hello");
}

TEST(HttpGetFetch, BytesAfterTheBodyAreNotPartOfIt) {
  // Connection: close was requested, so whatever follows the framed body is
  // not ours (RFC 9112 §6.3, §9.6): it must not reach the body or its hash.
  const std::string length = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
  const std::string chunked =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nEXTRA";
  for (const std::string* resp : {&length, &chunked}) {
    for (const std::size_t piece : {std::size_t{1}, std::size_t{3}, std::size_t{1} << 20}) {
      for (const bool close_after : {true, false}) {
        const Got g = fetch(options("http://10.0.0.1/x"), *resp, piece, close_after);
        EXPECT_TRUE(g.result.ok) << g.result.error;
        EXPECT_EQ(g.body, "hello") << piece;
        EXPECT_EQ(g.result.body_bytes, 5u) << piece;
        EXPECT_EQ(g.result.sha256, sha256_hex(std::string_view("hello"))) << piece;
      }
    }
  }
}

TEST(HttpGetFetch, ChunkedWithExtensionsAndTrailersOneByteAtATime) {
  const std::string resp =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-A\r\n\r\n"
      "13;ext=\"v\"\r\nThe quick brown fox\r\n"
      "28 ; e\r\n\r\njumps over\r\n\r\nthe lazy dog. 0123456789\r\n"
      "0\r\nX-A: 1\r\nX-B: two\r\n\r\n";
  for (const std::size_t piece : {std::size_t{1}, std::size_t{5}, std::size_t{1} << 20}) {
    const Got g = fetch(options("http://10.0.0.1/c"), resp, piece);
    EXPECT_TRUE(g.result.ok) << g.result.error;
    EXPECT_EQ(g.body, body);
    EXPECT_EQ(g.result.framing, "chunked");
    ASSERT_EQ(g.result.trailers.size(), 2u);
    EXPECT_EQ(*g.result.trailers.get("x-b"), "two");
  }
}

TEST(HttpGetFetch, ReadToClose) {
  const Got g = fetch(options("http://10.0.0.1/r"), "HTTP/1.0 200 OK\r\n\r\n" + body, 11);
  EXPECT_TRUE(g.result.ok) << g.result.error;
  EXPECT_EQ(g.body, body);
  EXPECT_EQ(g.result.framing, "until_close");
}

TEST(HttpGetFetch, InterimResponsesAreSkipped) {
  const Got g = fetch(options("http://10.0.0.1/i"),
                      "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
                      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                      3);
  EXPECT_TRUE(g.result.ok) << g.result.error;
  EXPECT_EQ(g.result.status, 200);
  EXPECT_EQ(g.body, "ok");
}

TEST(HttpGetErrors, RedirectIsAnError) {
  const Got g = fetch(options("http://10.0.0.1/old"),
                      "HTTP/1.1 301 Moved Permanently\r\nLocation: http://elsewhere/\r\nContent-Length: 0\r\n\r\n");
  EXPECT_FALSE(g.result.ok);
  EXPECT_EQ(g.result.status, 301);
  EXPECT_NE(g.result.error.find("redirect 301 to http://elsewhere/"), std::string::npos) << g.result.error;
}

TEST(HttpGetErrors, NonSuccessStatusReadsTheBodyButFails) {
  const Got g = fetch(options("http://10.0.0.1/x"), "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope");
  EXPECT_FALSE(g.result.ok);
  EXPECT_EQ(g.result.status, 404);
  EXPECT_EQ(g.body, "nope");
}

TEST(HttpGetErrors, TruncatedBodies) {
  Got g = fetch(options("http://10.0.0.1/t"), "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort");
  EXPECT_FALSE(g.result.ok);
  EXPECT_NE(g.result.error.find("before the end of the body"), std::string::npos) << g.result.error;
  g = fetch(options("http://10.0.0.1/t"), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab");
  EXPECT_FALSE(g.result.ok);
  g = fetch(options("http://10.0.0.1/t"), "");
  EXPECT_FALSE(g.result.ok);
  EXPECT_NE(g.result.error.find("without a response"), std::string::npos) << g.result.error;
  g = fetch(options("http://10.0.0.1/t"), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n");
  EXPECT_FALSE(g.result.ok);
  EXPECT_NE(g.result.error.find("chunked"), std::string::npos) << g.result.error;
  g = fetch(options("http://10.0.0.1/t"), "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab");
  EXPECT_FALSE(g.result.ok);
}

TEST(HttpGetResolve, ResolveOptionAndDnsQuery) {
  Options o = options("http://files.example.test/f");
  o.resolve.emplace_back("FILES.example.test", Ipv4Addr::from_octets(10, 9, 8, 7));
  Got g = fetch(o, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
  EXPECT_TRUE(g.result.ok) << g.result.error;
  EXPECT_EQ(to_string(g.result.addr), "10.9.8.7");
  EXPECT_EQ(g.dns_queries, 0);
  EXPECT_NE(g.request.find("Host: files.example.test\r\n"), std::string::npos);

  o = options("http://files.example.test/f");
  o.dns = Ipv4Addr::from_octets(10, 0, 0, 1);  // the fake host's address: replies come from it
  g = fetch(o, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 1 << 20, true,
            Ipv4Addr::from_octets(10, 1, 2, 3));
  EXPECT_TRUE(g.result.ok) << g.result.error;
  EXPECT_EQ(g.dns_queries, 1);
  EXPECT_EQ(to_string(g.result.addr), "10.1.2.3");
  EXPECT_EQ(g.body, "ok");
}

TEST(HttpGetResolve, DnsTimeoutRetriesThenFails) {
  Options o = options("http://nowhere.test/");
  o.dns = Ipv4Addr::from_octets(10, 0, 0, 53);
  o.dns_tries = 3;
  FakeTransport t;
  HttpGet get(t, o);
  ASSERT_TRUE(get.start());
  const Time t0 = t.now();
  t.run(get);
  ASSERT_TRUE(get.done());
  EXPECT_FALSE(get.result().ok);
  EXPECT_NE(get.result().error.find("after 3 tries"), std::string::npos) << get.result().error;
  EXPECT_EQ(t.udp_dropped(), 3u);  // three queries, nobody on port 53
  EXPECT_EQ(t.now() - t0, 3 * o.dns_timeout);
}

TEST(HttpGetResolve, UnresolvableWithoutDnsOrResolve) {
  FakeTransport t;
  HttpGet get(t, options("http://name.test/"));
  const auto s = get.start();
  ASSERT_FALSE(s);
  EXPECT_NE(s.error().find("--resolve"), std::string::npos);
}

TEST(HttpGetOptions, Parse) {
  CliParser cli("utcp-http-get", "");
  add_options(cli);
  auto a = cli.parse(std::vector<std::string_view>{"http://h:81/x", "--resolve", "h:1.2.3.4", "--dns", "8.8.8.8"});
  ASSERT_TRUE(a) << a.error();
  auto o = parse_options(*a);
  ASSERT_TRUE(o) << o.error();
  EXPECT_EQ(o->url, (HttpUrl{"h", 81, "/x"}));
  ASSERT_EQ(o->resolve.size(), 1u);
  EXPECT_EQ(to_string(o->resolve[0].second), "1.2.3.4");
  EXPECT_EQ(to_string(*o->dns), "8.8.8.8");
  a = cli.parse(std::vector<std::string_view>{"https://h/"});
  ASSERT_TRUE(a);
  EXPECT_FALSE(parse_options(*a));
}

}  // namespace
}  // namespace utcp::app::http_get
