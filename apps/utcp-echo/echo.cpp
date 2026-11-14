#include "utcp-echo/echo.hpp"

#include <algorithm>
#include <cstdio>
#include <optional>

#include "common/kernel_transport.hpp"

namespace utcp::app::echo {

namespace {

constexpr std::size_t io_chunk = 64 * 1024;

std::uint64_t splitmix64(std::uint64_t z) noexcept {
  z += 0x9e3779b97f4a7c15ULL;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

}  // namespace

std::byte request_byte(std::uint64_t seed, std::uint64_t conn, std::uint64_t req,
                       std::size_t off) noexcept {
  const std::uint64_t key = splitmix64(seed ^ splitmix64(conn ^ splitmix64(req)));
  const std::uint64_t word = splitmix64(key + off / 8);
  return static_cast<std::byte>(word >> (8 * (off % 8)));
}

// --- Server.

EchoServer::EchoServer(Transport& t, const ServerOptions& o) : t_(t), o_(o), buf_(io_chunk) {}

std::expected<void, std::string> EchoServer::start() {
  auto s = o_.udp ? t_.udp_open(o_.local) : t_.listen(o_.local, o_.backlog, o_.sock);
  if (!s) {
    return std::unexpected(std::string(o_.udp ? "UDP bind " : "listen on ") + to_string(o_.local) +
                           ": " + describe(s.error()));
  }
  sock_ = *s;
  return {};
}

bool EchoServer::owns(ConnId id) const { return id == sock_ || conns_.contains(id); }

void EchoServer::close_all() {
  for (const auto& [id, c] : conns_) {
    t_.close(id);
  }
  conns_.clear();
  if (sock_ != no_conn) {
    t_.close(sock_);
    sock_ = no_conn;
  }
}

void EchoServer::on_accept(ConnId listener, ConnId conn) {
  if (listener != sock_) {
    return;
  }
  ++stats_.accepted;
  conns_.emplace(conn, Conn{});
  service(conn);  // data may already be queued
}

void EchoServer::drop(ConnId id) {
  t_.close(id);
  conns_.erase(id);
  ++stats_.closed;
}

// Sends what is pending, reads while the pending bytes stay below the limit,
// and closes once the peer's stream ended and everything was echoed.
void EchoServer::service(ConnId id) {
  while (true) {
    const auto it = conns_.find(id);
    if (it == conns_.end()) {
      return;
    }
    Conn& c = it->second;
    // Flush.
    while (c.pending_off < c.pending.size()) {
      auto r = t_.send(id, std::span(c.pending).subspan(c.pending_off));
      if (!r) {
        if (r.error() == Error::would_block) {
          break;
        }
        ++stats_.errors;
        drop(id);
        return;
      }
      c.pending_off += *r;
      stats_.bytes += *r;
    }
    if (c.pending_off == c.pending.size()) {
      c.pending.clear();
      c.pending_off = 0;
    } else if (c.pending_off > c.pending.size() / 2) {
      c.pending.erase(c.pending.begin(), c.pending.begin() + static_cast<std::ptrdiff_t>(c.pending_off));
      c.pending_off = 0;
    }
    if (c.eof) {
      if (c.pending.empty()) {
        drop(id);  // FIN after the echoed data
      }
      return;
    }
    if (c.pending.size() - c.pending_off >= o_.max_pending) {
      return;  // on_writable resumes reading
    }
    auto r = t_.recv(id, buf_);
    if (!r) {
      if (r.error() != Error::would_block) {
        ++stats_.errors;
        drop(id);
      }
      return;
    }
    if (*r == 0) {
      c.eof = true;
      continue;
    }
    c.pending.insert(c.pending.end(), buf_.begin(), buf_.begin() + static_cast<std::ptrdiff_t>(*r));
  }
}

void EchoServer::udp_readable() {
  while (true) {
    auto r = t_.recv_from(sock_, buf_);
    if (!r) {
      return;
    }
    const std::size_t n = std::min(r->len, buf_.size());
    if (t_.send_to(sock_, r->from, std::span(buf_).first(n))) {
      ++stats_.datagrams;
    } else {
      ++stats_.udp_dropped;
    }
  }
}

void EchoServer::on_readable(ConnId id) {
  if (o_.udp && id == sock_) {
    udp_readable();
  } else if (conns_.contains(id)) {
    service(id);
  }
}

void EchoServer::on_writable(ConnId id) {
  if (conns_.contains(id)) {
    service(id);
  }
}

void EchoServer::on_closed(ConnId id) {
  if (conns_.contains(id)) {
    drop(id);
  }
}

void EchoServer::on_error(ConnId id, Error /*e*/) {
  if (conns_.contains(id)) {
    ++stats_.errors;
    drop(id);
  }
}

// --- Client.

EchoClient::EchoClient(Transport& t, const ClientOptions& o) : t_(t), o_(o), buf_(io_chunk) {}

std::expected<void, std::string> EchoClient::start(bool stop_when_done) {
  stop_when_done_ = stop_when_done;
  start_ = t_.now();
  if (o_.rate > 0) {
    last_refill_ = start_;
    tokens_milli_ = 1000;  // the first request may start at once
    rate_timer_ = t_.add_timer(std::chrono::milliseconds(1), [this] { refill(t_.now()); });
    rate_timer_on_ = true;
  }
  open_more();
  if (conns_.empty() && opened_ == 0 && o_.connections > 0) {
    return std::unexpected("connect to " + to_string(o_.remote) + ": " + result_.first_error);
  }
  check_done();
  return {};
}

void EchoClient::open_more() {
  while (!done_ && opened_ < o_.connections && conns_.size() < o_.concurrency) {
    auto c = t_.connect(o_.remote, o_.sock);
    if (!c) {
      if (result_.first_error.empty()) {
        result_.first_error = describe(c.error());
      }
      if (opened_ == 0) {
        return;  // start() reports it
      }
      ++opened_;
      ++result_.errors;
      continue;
    }
    conns_.emplace(*c, Conn{.index = opened_});
    ++opened_;
  }
}

void EchoClient::on_connected(ConnId id) {
  const auto it = conns_.find(id);
  if (it == conns_.end()) {
    return;
  }
  it->second.connected = true;
  begin_request(id);
}

void EchoClient::begin_request(ConnId id) {
  Conn& c = conns_.at(id);
  if (o_.rate > 0) {
    if (tokens_milli_ < 1000) {
      c.waiting = true;
      waiting_.push_back(id);
      return;
    }
    tokens_milli_ -= 1000;
  }
  c.waiting = false;
  c.in_request = true;
  c.sent = c.received = 0;
  c.started = t_.now();
  send_some(id);
}

void EchoClient::refill(Time now) {
  // Thousandths of a token: rate per second times the elapsed nanoseconds.
  // The elapsed time is capped at 1 s (the bucket holds at most
  // `concurrency` tokens anyway) and the rate at 1e9, so nothing overflows.
  const std::int64_t elapsed = std::clamp<std::int64_t>((now - last_refill_).count(), 0, 1'000'000'000);
  last_refill_ = now;
  const std::uint64_t add = o_.rate * static_cast<std::uint64_t>(elapsed) / 1'000'000;
  const std::uint64_t cap = std::max<std::uint64_t>(o_.concurrency, 1) * 1000;
  tokens_milli_ = std::min(cap, tokens_milli_ + add);
  while (tokens_milli_ >= 1000 && !waiting_.empty()) {
    const ConnId id = waiting_.front();
    waiting_.pop_front();
    if (conns_.contains(id) && conns_.at(id).waiting) {
      begin_request(id);
    }
  }
}

void EchoClient::send_some(ConnId id) {
  while (true) {
    const auto it = conns_.find(id);
    if (it == conns_.end()) {
      return;
    }
    Conn& c = it->second;
    if (!c.in_request || c.sent == o_.size) {
      return;
    }
    const std::size_t n = std::min(buf_.size(), o_.size - c.sent);
    for (std::size_t i = 0; i < n; ++i) {
      buf_[i] = request_byte(o_.seed, c.index, c.req, c.sent + i);
    }
    auto r = t_.send(id, std::span(buf_).first(n));
    if (!r) {
      if (r.error() != Error::would_block) {
        finish_conn(id, false, "send: " + describe(r.error()));
      }
      return;
    }
    c.sent += *r;
    if (*r == 0) {
      return;
    }
  }
}

void EchoClient::read_some(ConnId id) {
  while (true) {
    const auto it = conns_.find(id);
    if (it == conns_.end()) {
      return;
    }
    Conn& c = it->second;
    if (!c.connected) {
      return;
    }
    auto r = t_.recv(id, buf_);
    if (!r) {
      if (r.error() != Error::would_block) {
        finish_conn(id, false, "recv: " + describe(r.error()));
      }
      return;
    }
    if (*r == 0) {
      finish_conn(id, false, "the server closed the connection");
      return;
    }
    if (!c.in_request || c.received + *r > c.sent) {
      ++result_.mismatches;
      finish_conn(id, false, "more bytes echoed than sent");
      return;
    }
    for (std::size_t i = 0; i < *r; ++i) {
      if (buf_[i] != request_byte(o_.seed, c.index, c.req, c.received + i)) {
        ++result_.mismatches;
        finish_conn(id, false, "echoed byte differs from the request");
        return;
      }
    }
    c.received += *r;
    result_.bytes += *r;
    if (c.received == o_.size) {
      result_.latency.record(t_.now() - c.started);
      ++result_.requests_ok;
      c.in_request = false;
      ++c.req;
      if (c.req == o_.count) {
        finish_conn(id, true, "");
        return;
      }
      begin_request(id);
    }
  }
}

void EchoClient::on_readable(ConnId id) {
  if (conns_.contains(id)) {
    read_some(id);
  }
}

void EchoClient::on_writable(ConnId id) {
  if (conns_.contains(id)) {
    send_some(id);
  }
}

void EchoClient::on_closed(ConnId id) {
  if (conns_.contains(id)) {
    finish_conn(id, false, "connection closed early");
  }
}

void EchoClient::on_error(ConnId id, Error e) {
  if (conns_.contains(id)) {
    finish_conn(id, false, describe(e));
  }
}

void EchoClient::finish_conn(ConnId id, bool ok, const std::string& why) {
  t_.close(id);
  conns_.erase(id);
  if (ok) {
    ++result_.connections_done;
  } else {
    ++result_.errors;
    if (result_.first_error.empty()) {
      result_.first_error = why;
    }
  }
  open_more();
  check_done();
}

void EchoClient::check_done() {
  if (done_ || opened_ < o_.connections || !conns_.empty()) {
    return;
  }
  done_ = true;
  result_.duration = t_.now() - start_;
  result_.ok = result_.errors == 0 && result_.mismatches == 0 &&
               result_.requests_ok == o_.connections * o_.count;
  if (rate_timer_on_) {
    t_.cancel_timer(rate_timer_);
    rate_timer_on_ = false;
  }
  if (stop_when_done_) {
    t_.stop();
  }
}

void EchoClient::abort(const std::string& why) {
  if (done_) {
    return;
  }
  for (const auto& [id, c] : conns_) {
    t_.close(id);
    ++result_.errors;
  }
  conns_.clear();
  if (result_.first_error.empty()) {
    result_.first_error = why;
  }
  opened_ = o_.connections;
  check_done();
  result_.ok = false;
}

JsonLine EchoClient::summary() const {
  const ClientResult& r = result_;
  JsonLine line;
  line.add("ev", "summary").add("role", "client").add("ok", r.ok);
  if (!r.first_error.empty()) {
    line.add("error", r.first_error);
  }
  const std::int64_t ns = r.duration.count();
  const std::uint64_t rps =
      ns > 0 ? static_cast<std::uint64_t>(static_cast<double>(r.requests_ok) * 1e9 /
                                          static_cast<double>(ns))
             : 0;
  line.add("connections", o_.connections)
      .add("connections_ok", r.connections_done)
      .add("errors", r.errors)
      .add("requests", o_.connections * o_.count)
      .add("requests_ok", r.requests_ok)
      .add("mismatches", r.mismatches)
      .add("size", o_.size)
      .add("bytes", r.bytes)
      .add("duration_us", ns / 1000)
      .add("requests_per_s", rps)
      .add("latency_min_ns", r.latency.min().count())
      .add("latency_mean_ns", r.latency.mean().count())
      .add("latency_p50_ns", r.latency.percentile(0.50).count())
      .add("latency_p99_ns", r.latency.percentile(0.99).count())
      .add("latency_p999_ns", r.latency.percentile(0.999).count())
      .add("latency_max_ns", r.latency.max().count());
  return line;
}

// --- Program.

void add_options(CliParser& p) {
  p.option("listen", "PORT", "server: listen on PORT (or IP:PORT)")
      .flag("udp", "server: UDP echo instead of TCP")
      .option("connect", "IP:PORT", "client: connect to IP:PORT")
      .option("size", "N", "client: bytes per request", "64")
      .option("count", "N", "client: requests per connection", "100")
      .option("connections", "N", "client: connections in total", "1")
      .option("concurrency", "N", "client: connections at a time", "1")
      .option("rate", "R", "client: request starts per second, 0 = unlimited", "0")
      .option("pattern-seed", "N", "client: request pattern seed", "1")
      .flag("nodelay", "disable Nagle's algorithm")
      .option("cc", "ALGO", "congestion control: newreno, cubic, bbr");
}

namespace {

std::expected<Endpoint, std::string> listen_endpoint(const std::string& s) {
  if (s.find(':') != std::string::npos) {
    return parse_endpoint(s);
  }
  auto port = parse_port(s);
  if (!port) {
    return std::unexpected(port.error());
  }
  return Endpoint{Ipv4Addr{}, *port};
}

std::expected<std::uint64_t, std::string> get_u64(const CliArgs& a, const char* name,
                                                  bool size = false) {
  const std::string v = a.get(name).value_or("");
  auto r = size ? parse_size(v) : parse_u64(v);
  if (!r) {
    return std::unexpected(std::string("--") + name + ": " + r.error());
  }
  return *r;
}

}  // namespace

int main_(int argc, const char* const* argv) {
  CliParser cli("utcp-echo", "TCP echo server and client, UDP echo server.");
  add_options(cli);
  add_backend_options(cli);
  auto args = cli.parse(argc, argv);
  if (!args) {
    std::fprintf(stderr, "utcp-echo: %s\n%s", args.error().c_str(), cli.usage().c_str());
    return 2;
  }
  if (args->help()) {
    std::fputs(cli.usage().c_str(), stdout);
    return 0;
  }
  const auto die = [](const std::string& msg) {
    std::fprintf(stderr, "utcp-echo: %s\n", msg.c_str());
    return 2;
  };
  TcpSocketOptions sock;
  if (args->flag("nodelay")) {
    sock.nodelay = true;
  }
  if (const auto cc = args->get("cc")) {
    auto v = parse_cc(*cc);
    if (!v) return die(v.error());
    sock.cc = *v;
  }
  auto backend = parse_backend_options(*args);
  if (!backend) return die(backend.error());
  const auto listen = args->get("listen");
  const auto connect = args->get("connect");
  if (listen.has_value() == connect.has_value()) {
    return die("give exactly one of --listen and --connect");
  }
  auto transport = make_transport(*backend);
  if (!transport) {
    std::fprintf(stderr, "utcp-echo: %s\n", transport.error().c_str());
    return 1;
  }
  Transport& t = **transport;

  if (listen) {
    ServerOptions so;
    auto ep = listen_endpoint(*listen);
    if (!ep) return die("--listen: " + ep.error());
    so.local = *ep;
    so.udp = args->flag("udp");
    so.sock = sock;
    EchoServer server(t, so);
    if (auto s = server.start(); !s) {
      std::fprintf(stderr, "utcp-echo: %s\n", s.error().c_str());
      return 1;
    }
    std::fprintf(stderr, "utcp-echo: %s echo on %s\n", so.udp ? "UDP" : "TCP",
                 to_string(so.local).c_str());
    t.run(server);  // until a signal
    const ServerStats& st = server.stats();
    JsonLine line;
    line.add("ev", "summary").add("role", "server").add("udp", so.udp)
        .add("accepted", st.accepted).add("closed", st.closed).add("errors", st.errors)
        .add("bytes", st.bytes).add("datagrams", st.datagrams).add("udp_dropped", st.udp_dropped);
    server.close_all();
    std::printf("%s\n", line.str().c_str());
    return 0;
  }

  if (args->flag("udp")) return die("--udp is a server mode (use nc -u as the client)");
  ClientOptions co;
  auto ep = parse_endpoint(*connect);
  if (!ep) return die("--connect: " + ep.error());
  co.remote = *ep;
  co.sock = sock;
  auto size = get_u64(*args, "size", true);
  auto count = get_u64(*args, "count");
  auto conns = get_u64(*args, "connections");
  auto conc = get_u64(*args, "concurrency");
  auto rate = get_u64(*args, "rate");
  auto seed = get_u64(*args, "pattern-seed");
  for (const auto* r : {&size, &count, &conns, &conc, &rate, &seed}) {
    if (!*r) return die(r->error());
  }
  if (*size == 0 || *size > (std::uint64_t{1} << 30) || *count == 0 || *conc == 0 ||
      *rate > 1'000'000'000) {
    return die("--size must be 1..1Gi, --count and --concurrency at least 1, --rate at most 1e9");
  }
  co.size = static_cast<std::size_t>(*size);
  co.count = *count;
  co.connections = *conns;
  co.concurrency = *conc;
  co.rate = *rate;
  co.seed = *seed;
  EchoClient client(t, co);
  if (auto s = client.start(); !s) {
    std::fprintf(stderr, "utcp-echo: %s\n", s.error().c_str());
    return 1;
  }
  if (!client.done()) {
    t.run(client);
  }
  if (!client.done()) {
    client.abort("interrupted");
  }
  t.finish_closing(finish_closing_max);
  std::printf("%s\n", client.summary().str().c_str());
  if (!client.result().ok) {
    std::fprintf(stderr, "utcp-echo: failed: %s\n", client.result().first_error.c_str());
    return 1;
  }
  return 0;
}

}  // namespace utcp::app::echo
