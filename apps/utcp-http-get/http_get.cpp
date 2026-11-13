#include "utcp-http-get/http_get.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "common/dns.hpp"
#include "common/kernel_transport.hpp"

namespace utcp::app::http_get {

namespace {

constexpr std::size_t read_chunk = 64 * 1024;

const char* framing_name(BodyFraming::Kind k) {
  switch (k) {
    case BodyFraming::Kind::none: return "none";
    case BodyFraming::Kind::length: return "length";
    case BodyFraming::Kind::chunked: return "chunked";
    case BodyFraming::Kind::until_close: return "until_close";
  }
  return "none";
}

}  // namespace

HttpGet::HttpGet(Transport& t, const Options& o, BodySink sink)
    : t_(t), o_(o), sink_(std::move(sink)) {}

std::expected<void, std::string> HttpGet::start() {
  start_ = t_.now();
  if (o_.timeout > Duration::zero()) {
    deadline_timer_ = t_.add_oneshot(o_.timeout, [this] {
      deadline_timer_on_ = false;
      fail("timed out after " + std::to_string(o_.timeout.count() / 1'000'000) + " ms");
    });
    deadline_timer_on_ = true;
  }
  if (auto ip = parse_ipv4(o_.url.host)) {
    connect_to(*ip);
    return {};
  }
  for (const auto& [host, addr] : o_.resolve) {
    if (iequals(host, o_.url.host)) {
      connect_to(addr);
      return {};
    }
  }
  if (!o_.dns) {
    return std::unexpected("cannot resolve '" + o_.url.host + "': give --resolve host:ip or --dns IP");
  }
  auto u = t_.udp_open(Endpoint{});
  if (!u) {
    return std::unexpected("UDP socket for DNS: " + describe(u.error()));
  }
  udp_ = *u;
  // Any value will do for a stub resolver's single query; the clock's low
  // bits differ between runs.
  const std::uint64_t ns = static_cast<std::uint64_t>(t_.now().ns);
  dns_id_ = static_cast<std::uint16_t>(ns ^ (ns >> 16) ^ (ns >> 32));
  send_query();
  return {};
}

void HttpGet::send_query() {
  if (done_ || phase_ != Phase::resolving) {
    return;
  }
  if (dns_sent_ >= o_.dns_tries) {
    fail("no DNS answer from " + to_string(*o_.dns) + " after " + std::to_string(dns_sent_) +
         " tries");
    return;
  }
  auto q = dns_encode_query(dns_id_, o_.url.host);
  if (!q) {
    fail("DNS query: " + q.error());
    return;
  }
  ++dns_sent_;
  if (auto s = t_.send_to(udp_, Endpoint{*o_.dns, dns_port}, *q); !s && s.error() != Error::would_block) {
    fail("DNS send: " + describe(s.error()));
    return;
  }
  dns_timer_ = t_.add_oneshot(o_.dns_timeout, [this] {
    dns_timer_on_ = false;
    send_query();
  });
  dns_timer_on_ = true;
}

void HttpGet::dns_readable() {
  std::vector<std::byte> buf(4096);
  while (phase_ == Phase::resolving && !done_) {
    auto r = t_.recv_from(udp_, buf);
    if (!r) {
      return;
    }
    if (r->from != Endpoint{*o_.dns, dns_port} || r->truncated) {
      continue;  // not our server's, or too large for a stub answer
    }
    auto msg = dns_parse_response(std::span(buf).first(r->len));
    if (!msg || msg->id != dns_id_) {
      continue;  // RFC 5452 §4: ignore what does not match the query
    }
    auto addrs = dns_a_records(*msg, dns_id_, o_.url.host);
    if (!addrs) {
      fail("DNS: " + addrs.error());
      return;
    }
    if (dns_timer_on_) {
      t_.cancel_timer(dns_timer_);
      dns_timer_on_ = false;
    }
    t_.close(udp_);
    udp_ = no_conn;
    connect_to(addrs->front());
    return;
  }
}

void HttpGet::connect_to(Ipv4Addr addr) {
  result_.addr = addr;
  phase_ = Phase::connecting;
  auto c = t_.connect(Endpoint{addr, o_.url.port}, o_.sock);
  if (!c) {
    fail("connect to " + to_string(Endpoint{addr, o_.url.port}) + ": " + describe(c.error()));
    return;
  }
  conn_ = *c;
}

void HttpGet::on_connected(ConnId id) {
  if (id != conn_ || phase_ != Phase::connecting) {
    return;
  }
  std::string host = o_.url.host;
  if (o_.url.port != 80) {
    host += ':' + std::to_string(o_.url.port);
  }
  // RFC 9112 §3.2: Host in every HTTP/1.1 request; §9.6: Connection: close.
  request_ = "GET " + o_.url.target + " HTTP/1.1\r\nHost: " + host +
             "\r\nUser-Agent: utcp-http-get\r\nAccept: */*\r\nConnection: close\r\n\r\n";
  request_off_ = 0;
  phase_ = Phase::head;
  send_request();
  read_response();
}

void HttpGet::send_request() {
  while (!done_ && request_off_ < request_.size()) {
    auto r = t_.send(conn_, std::as_bytes(std::span(request_)).subspan(request_off_));
    if (!r) {
      if (r.error() != Error::would_block) {
        fail("send: " + describe(r.error()));
      }
      return;
    }
    if (*r == 0) {
      return;
    }
    request_off_ += *r;
  }
}

bool HttpGet::deliver(std::string_view data) {
  if (data.empty()) {
    return true;
  }
  const auto bytes = std::as_bytes(std::span(data));
  hash_.update(bytes);
  result_.body_bytes += data.size();
  if (sink_ && !sink_(bytes)) {
    fail("cannot write the body");
    return false;
  }
  return true;
}

bool HttpGet::parse_head() {
  const auto size = http_head_size(in_, o_.limits, /*request=*/false);
  if (!size) {
    fail("bad response: " + size.error().message);
    return false;
  }
  if (*size == 0) {
    return false;
  }
  auto head = parse_response_head(std::string_view(in_).substr(0, *size), o_.limits);
  in_.erase(0, *size);
  if (!head) {
    fail("bad response: " + head.error().message);
    return false;
  }
  if (head->status / 100 == 1) {
    if (head->status == 101) {
      fail("unexpected 101 Switching Protocols");
      return false;
    }
    return true;  // RFC 9110 §15.2: interim response; the final one follows
  }
  result_.status = head->status;
  result_.reason = head->reason;
  result_.fields = head->fields;
  if (head->status / 100 == 3) {
    const std::string* loc = head->fields.get("location");
    fail("redirect " + std::to_string(head->status) + (loc ? " to " + *loc : std::string()) +
         " (redirects are not followed)");
    return false;
  }
  const auto framing = response_body_framing(*head, /*request_was_head=*/false);
  if (!framing) {
    fail("bad response framing: " + framing.error());
    return false;
  }
  framing_ = *framing;
  result_.framing = framing_name(framing_.kind);
  remaining_ = framing_.length;
  if (framing_.kind == BodyFraming::Kind::chunked) {
    chunked_.emplace();
  }
  phase_ = Phase::body;
  if (framing_.kind == BodyFraming::Kind::none ||
      (framing_.kind == BodyFraming::Kind::length && remaining_ == 0)) {
    complete();
    return false;
  }
  return true;
}

void HttpGet::read_response() {
  std::string buf(read_chunk, '\0');
  while (!done_ && (phase_ == Phase::head || phase_ == Phase::body)) {
    if (phase_ == Phase::head && !in_.empty()) {
      if (parse_head()) {
        continue;
      }
      if (done_) {
        return;
      }
    } else if (phase_ == Phase::body && !in_.empty()) {
      switch (framing_.kind) {
        case BodyFraming::Kind::length: {
          const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(remaining_, in_.size()));
          if (!deliver(std::string_view(in_).substr(0, n))) return;
          remaining_ -= n;
          in_.clear();  // bytes after the body are not ours (Connection: close)
          if (remaining_ == 0) {
            complete();
            return;
          }
          break;
        }
        case BodyFraming::Kind::chunked: {
          std::string out;
          auto r = chunked_->feed(in_, out);
          if (!r) {
            fail("bad chunked body: " + r.error());
            return;
          }
          if (!deliver(out)) return;
          in_.erase(0, *r);
          if (chunked_->done()) {
            result_.trailers = chunked_->trailers();
            complete();
            return;
          }
          break;
        }
        default:
          if (!deliver(in_)) return;
          in_.clear();
          break;
      }
      continue;
    }
    auto r = t_.recv(conn_, std::as_writable_bytes(std::span(buf)));
    if (!r) {
      if (r.error() != Error::would_block) {
        fail("recv: " + describe(r.error()));
      }
      return;
    }
    if (*r == 0) {
      if (phase_ == Phase::body && framing_.kind == BodyFraming::Kind::until_close) {
        complete();
      } else if (phase_ == Phase::head) {
        fail(in_.empty() ? "connection closed without a response"
                         : "connection closed inside the response head");
      } else {
        fail("connection closed before the end of the body");
      }
      return;
    }
    in_.append(buf.data(), *r);
  }
}

void HttpGet::on_readable(ConnId id) {
  if (id == udp_) {
    dns_readable();
  } else if (id == conn_ && (phase_ == Phase::head || phase_ == Phase::body)) {
    read_response();
  }
}

void HttpGet::on_writable(ConnId id) {
  if (id == conn_ && phase_ != Phase::connecting) {
    send_request();
  }
}

void HttpGet::on_closed(ConnId id) {
  if (id == conn_) {
    read_response();
  }
}

void HttpGet::on_error(ConnId id, Error e) {
  if (id == conn_) {
    // A reset after a read-to-close body still ends the body ambiguously;
    // RFC 9112 §6.3 item 8 treats it as incomplete.
    fail((phase_ == Phase::connecting ? "connect: " : "connection failed: ") + describe(e));
  }
}

void HttpGet::release() {
  if (dns_timer_on_) {
    t_.cancel_timer(dns_timer_);
    dns_timer_on_ = false;
  }
  if (deadline_timer_on_) {
    t_.cancel_timer(deadline_timer_);
    deadline_timer_on_ = false;
  }
  if (udp_ != no_conn) {
    t_.close(udp_);
    udp_ = no_conn;
  }
  if (conn_ != no_conn) {
    t_.close(conn_);
    conn_ = no_conn;
  }
  result_.duration = t_.now() - start_;
  result_.sha256 = to_hex(hash_.finish());
  phase_ = Phase::done;
  done_ = true;
  t_.stop();
}

void HttpGet::complete() {
  if (done_) {
    return;
  }
  result_.ok = result_.status / 100 == 2;
  if (!result_.ok) {
    result_.error = "HTTP status " + std::to_string(result_.status);
  }
  release();
}

void HttpGet::fail(const std::string& why) {
  if (done_) {
    return;
  }
  result_.ok = false;
  result_.error = why;
  release();
}

void HttpGet::abort(const std::string& why) { fail(why); }

JsonLine HttpGet::summary() const {
  const Result& r = result_;
  JsonLine line;
  line.add("ev", "summary").add("url", o_.url_text).add("ok", r.ok);
  if (!r.ok) {
    line.add("error", r.error);
  }
  line.add("addr", to_string(Endpoint{r.addr, o_.url.port}))
      .add("status", r.status)
      .add("framing", r.framing.empty() ? std::string("none") : r.framing)
      .add("bytes", r.body_bytes)
      .add("sha256", r.sha256)
      .add("trailers", static_cast<std::uint64_t>(r.trailers.size()))
      .add("duration_us", r.duration.count() / 1000);
  return line;
}

// --- Program.

void add_options(CliParser& p) {
  p.positional("URL", "http://host[:port]/path")
      .option("o", "FILE", "write the body to FILE (- = stdout)")
      .option("output", "FILE", "same as -o")
      .option("resolve", "HOST:IP", "use IP for HOST")
      .option("dns", "IP", "DNS server for the A query (port 53)")
      .option("dns-timeout", "S", "seconds to wait for a DNS answer before retrying", "2")
      .option("timeout", "S", "give up after S seconds (0: never)", "0")
      .option("cc", "ALGO", "congestion control: newreno, cubic, bbr");
}

std::expected<Options, std::string> parse_options(const CliArgs& a) {
  Options o;
  o.url_text = a.positionals().at(0);
  auto url = parse_http_url(o.url_text);
  if (!url) return std::unexpected(url.error());
  o.url = *url;
  if (const auto r = a.get("resolve")) {
    auto pair = parse_pair(*r);
    if (!pair) return std::unexpected("--resolve: " + pair.error());
    auto ip = parse_ipv4(pair->second);
    if (!ip) return std::unexpected("--resolve: " + ip.error());
    o.resolve.emplace_back(std::string(pair->first), *ip);
  }
  if (const auto d = a.get("dns")) {
    auto ip = parse_ipv4(*d);
    if (!ip) return std::unexpected("--dns: " + ip.error());
    o.dns = *ip;
  }
  auto dt = parse_duration(a.get("dns-timeout").value_or("2"), std::chrono::seconds(1));
  if (!dt || *dt <= Duration::zero()) return std::unexpected(std::string("--dns-timeout must be > 0"));
  o.dns_timeout = *dt;
  auto to = parse_duration(a.get("timeout").value_or("0"), std::chrono::seconds(1));
  if (!to) return std::unexpected("--timeout: " + to.error());
  o.timeout = *to;
  if (const auto cc = a.get("cc")) {
    auto v = parse_cc(*cc);
    if (!v) return std::unexpected(v.error());
    o.sock.cc = *v;
  }
  return o;
}

int main_(int argc, const char* const* argv) {
  CliParser cli("utcp-http-get", "Fetch an http:// URL, print the body's SHA-256 and length.");
  add_options(cli);
  add_backend_options(cli);
  // "-o FILE": the parser takes long options only, so -o is rewritten.
  std::vector<std::string_view> words;
  for (int i = 1; i < argc; ++i) {
    const std::string_view w = argv[i];
    words.push_back(w == "-o" ? std::string_view("--o") : w);
  }
  auto args = cli.parse(words);
  if (!args) {
    std::fprintf(stderr, "utcp-http-get: %s\n%s", args.error().c_str(), cli.usage().c_str());
    return 2;
  }
  if (args->help()) {
    std::fputs(cli.usage().c_str(), stdout);
    return 0;
  }
  auto opts = parse_options(*args);
  if (!opts) {
    std::fprintf(stderr, "utcp-http-get: %s\n", opts.error().c_str());
    return 2;
  }
  auto backend = parse_backend_options(*args);
  if (!backend) {
    std::fprintf(stderr, "utcp-http-get: %s\n", backend.error().c_str());
    return 2;
  }
  std::string out_path = args->get("o").value_or(args->get("output").value_or(""));
  std::FILE* out = nullptr;
  if (out_path == "-") {
    out = stdout;
  } else if (!out_path.empty()) {
    out = std::fopen(out_path.c_str(), "wb");
    if (out == nullptr) {
      std::fprintf(stderr, "utcp-http-get: %s: %s\n", out_path.c_str(), std::strerror(errno));
      return 2;
    }
  }
  BodySink sink;
  if (out != nullptr) {
    sink = [out](std::span<const std::byte> b) { return std::fwrite(b.data(), 1, b.size(), out) == b.size(); };
  }
  auto transport = make_transport(*backend);
  if (!transport) {
    std::fprintf(stderr, "utcp-http-get: %s\n", transport.error().c_str());
    return 1;
  }
  HttpGet get(**transport, *opts, sink);
  if (auto s = get.start(); !s) {
    std::fprintf(stderr, "utcp-http-get: %s\n", s.error().c_str());
    return 1;
  }
  if (!get.done()) {
    (*transport)->run(get);
  }
  if (!get.done()) {
    get.abort("interrupted");
  }
  bool write_ok = true;
  if (out != nullptr && out != stdout) {
    write_ok = std::fclose(out) == 0;
  } else if (out == stdout) {
    write_ok = std::fflush(stdout) == 0;
  }
  std::FILE* report = out == stdout ? stderr : stdout;
  std::fprintf(report, "%s\n", get.summary().str().c_str());
  if (!get.result().ok || !write_ok) {
    std::fprintf(stderr, "utcp-http-get: %s\n",
                 write_ok ? get.result().error.c_str() : "cannot write the output file");
    return 1;
  }
  return 0;
}

}  // namespace utcp::app::http_get
