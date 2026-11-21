#include "utcp-echo/echo.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <optional>

#include "common/kernel_transport.hpp"
#include "common/utcp_transport.hpp"
#include "core/stack_impl.hpp"
#include "core/tcp/tcb.hpp"

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
  bool write_blocked = false;
  while (true) {
    const auto it = conns_.find(id);
    if (it == conns_.end()) {
      return;
    }
    Conn& c = it->second;
    // Flush.
    while (!write_blocked && c.pending_off < c.pending.size()) {
      auto r = t_.send(id, std::span(c.pending).subspan(c.pending_off));
      if (!r) {
        if (r.error() == Error::would_block) {
          break;
        }
        ++stats_.errors;
        drop(id);
        return;
      }
      if (*r == 0) {
        break;
      }
      c.pending_off += *r;
      stats_.bytes += *r;
    }
    write_blocked = false;
    if (c.pending_off == c.pending.size()) {
      c.pending.clear();
      c.pending_off = 0;
    } else if (c.pending_off > c.pending.size() / 2) {
      stats_.compacted_bytes += c.pending.size() - c.pending_off;
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
    auto received = std::span<const std::byte>(buf_).first(*r);
    if (o_.direct_echo && c.pending.empty()) {
      // send() consumes the accepted prefix synchronously. Only an unsent
      // tail needs to survive reuse of the shared receive scratch buffer.
      auto sent = t_.send(id, received);
      if (sent) {
        stats_.bytes += *sent;
        received = received.subspan(*sent);
        write_blocked = *sent == 0;
      } else if (sent.error() == Error::would_block) {
        write_blocked = true;
      } else {
        ++stats_.errors;
        drop(id);
        return;
      }
    }
    if (received.empty()) {
      continue;
    }
    if (received.size() > c.pending.capacity() - c.pending.size()) {
      stats_.relocated_bytes += c.pending.size();
    }
    c.pending.insert(c.pending.end(), received.begin(), received.end());
    stats_.staged_bytes += received.size();
    ++stats_.stage_appends;
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
  if (o_.open_batch != 0) {
    return {};  // wait for the controller to capture both endpoint baselines
  }
  start_rate();
  open_more();
  if (conns_.empty() && opened_ == 0 && o_.connections > 0) {
    return std::unexpected("connect to " + to_string(o_.remote) + ": " + result_.first_error);
  }
  check_done();
  return {};
}

void EchoClient::start_rate() {
  if (o_.rate > 0) {
    last_refill_ = start_;
    tokens_milli_ = 1000;  // the first request may start at once
    rate_timer_ = t_.add_timer(std::chrono::milliseconds(1), [this] { refill(t_.now()); });
    rate_timer_on_ = true;
  }
}

void EchoClient::advance_load() {
  switch (load_phase_) {
    case LoadPhase::baseline:
      load_phase_ = LoadPhase::opening;
      open_timer_ = t_.add_timer(std::chrono::milliseconds(2), [this] { open_more(); });
      break;
    case LoadPhase::idle:
      load_phase_ = LoadPhase::active;
      start_ = t_.now();
      start_rate();
      // Populate the queue before the first send. A send failure can abort
      // the load and clear the connection map.
      for (auto& [id, c] : conns_) {
        c.waiting = true;
        wait_for_token(id);
      }
      refill(start_);
      break;
    case LoadPhase::drained:
      for (const auto& [id, c] : conns_) {
        t_.close(id);
      }
      conns_.clear();
      established_ = 0;
      check_done();
      break;
    case LoadPhase::opening:
    case LoadPhase::active:
      break;  // only a connection or response can advance these phases
  }
}

void EchoClient::open_more() {
  while (!done_ && opened_ < o_.connections && conns_.size() < o_.concurrency &&
         (o_.open_batch == 0 || conns_.size() - established_ < o_.open_batch)) {
    auto c = t_.connect(o_.remote, o_.sock);
    if (!c) {
      if (o_.open_batch != 0) {
        ++result_.errors;
        abort("connect: " + describe(c.error()));
        return;
      }
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
  if (it == conns_.end() || it->second.connected) {
    return;
  }
  it->second.connected = true;
  ++established_;
  if (o_.open_batch == 0) {
    begin_request(id);
  } else if (established_ == o_.connections) {
    t_.cancel_timer(open_timer_);
    open_timer_ = 0;
    load_phase_ = LoadPhase::idle;
  }
}

void EchoClient::begin_request(ConnId id) {
  Conn& c = conns_.at(id);
  if (o_.rate > 0) {
    if (tokens_milli_ < 1000) {
      c.waiting = true;
      wait_for_token(id);
      return;
    }
    tokens_milli_ -= 1000;
  }
  c.waiting = false;
  c.in_request = true;
  c.sent = c.received = 0;
  c.started = t_.now();
  ++requests_started_;
  send_some(id);
}

void EchoClient::wait_for_token(ConnId id) {
  // Reuse capacity across requests. Move a live suffix only when the
  // consumed prefix is at least as long, so compaction is amortized.
  if (waiting_.size() == waiting_.capacity() && waiting_head_ != 0 &&
      waiting_head_ >= waiting_.size() - waiting_head_) {
    waiting_.erase(waiting_.begin(), waiting_.begin() + static_cast<std::ptrdiff_t>(waiting_head_));
    waiting_head_ = 0;
  }
  waiting_.push_back(id);
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
  while (!done_ && tokens_milli_ >= 1000 && !waiting_.empty()) {
    const ConnId id = waiting_[waiting_head_++];
    if (waiting_head_ == waiting_.size()) {
      waiting_.clear();
      waiting_head_ = 0;
    }
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
        if (o_.open_batch == 0) {
          finish_conn(id, true, "");
          return;
        }
        if (++result_.connections_done == o_.connections) {
          result_.duration = t_.now() - start_;
          load_phase_ = LoadPhase::drained;
          if (rate_timer_on_) {
            t_.cancel_timer(rate_timer_);
            rate_timer_on_ = false;
          }
        }
        continue;  // keep the socket open and detect unsolicited data or FIN
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
  if (o_.open_batch != 0) {
    abort(why);
    return;
  }
  t_.close(id);
  established_ -= conns_.at(id).connected;
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
  if (o_.open_batch == 0 || load_phase_ != LoadPhase::drained) {
    result_.duration = t_.now() - start_;
  }
  result_.ok = result_.errors == 0 && result_.mismatches == 0 &&
               result_.requests_ok == o_.connections * o_.count;
  if (open_timer_ != 0) {
    t_.cancel_timer(open_timer_);
    open_timer_ = 0;
  }
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
  established_ = 0;
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
  if (o_.open_batch != 0) {
    line.add("offered_requests_per_s", o_.rate)
        .add("requests_started", requests_started_)
        .add("latency_samples", r.latency.count())
        .add("workload_start_ns", start_.ns)
        .add("workload_end_ns", (start_ + r.duration).ns);
  }
  return line;
}

JsonLine EchoClient::load_report() const {
  JsonLine line;
  load_report(line);
  return line;
}

void EchoClient::load_report(JsonLine& line) const {
  line.clear();
  constexpr const char* phases[]{"baseline", "opening", "idle", "active", "drained"};
  line.add("role", "client")
      .add("phase", phases[static_cast<std::size_t>(load_phase_)])
      .add("open", conns_.size())
      .add("established", established_)
      .add("connections_ok", result_.connections_done)
      .add("requests_started", requests_started_)
      .add("requests_ok", result_.requests_ok)
      .add("bytes", result_.bytes)
      .add("errors", result_.errors)
      .add("workload_start_ns", start_.ns);
}

// --- Program.

void add_options(CliParser& p) {
  p.option("listen", "PORT", "server: listen on PORT (or IP:PORT)")
      .flag("udp", "server: UDP echo instead of TCP")
      .option("backlog", "N", "server: requested TCP listen backlog", "4096")
      .flag("load-report", "emit periodic TCP connection and buffer counts as JSON lines")
      .flag("direct-echo", "TCP server: send directly from receive scratch when possible")
      .option("load-control", "DIR", "client: hold all connections, advancing on open/active/close files")
      .option("open-batch", "N", "gated client: maximum outstanding handshakes", "32")
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

// The process remains responsive while the controller reads /proc. Only
// benchmark invocations pay for these snapshots.
bool report_load(Transport& t, JsonLine& line) {
  line.add("ev", "load").add("monotonic_ns", t.now().ns);
  if (const auto* u = dynamic_cast<const UtcpTransport*>(&t)) {
    const StackUsage usage = u->stack().debug_usage();
    line.add("tcb_bytes", sizeof(Tcb))
        .add("stream_state_bytes", sizeof(StreamState))
        .add("tcp_stream_states", usage.tcp_stream_states)
        .add("tcp_slots", usage.tcp_slots)
        .add("time_wait_entries", usage.time_wait_entries)
        .add("packet_buffer_bytes", packet_buf_size)
        .add("pool_buffers", usage.pool_buffers)
        .add("pool_buffers_free", usage.pool_buffers_free)
        .add("chunk_bytes", ChunkPool::chunk_size)
        .add("chunks", usage.chunks)
        .add("chunks_free", usage.chunks_free)
        .add("tx_queued", usage.tx_queued)
        .add("conn_timers_armed", usage.conn_timers_armed);
  }
  return line.write_to(stdout) && std::fflush(stdout) == 0;
}

}  // namespace

int main_(int argc, const char* const* argv, const TransportFactory& make) {
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
  const bool load_report = args->flag("load-report");
  const bool direct_echo = args->flag("direct-echo");
  if (direct_echo && (!listen || args->flag("udp"))) {
    return die("--direct-echo requires a TCP listener");
  }
  const auto control_dir = args->get("load-control");
  if ((control_dir && !connect) || (connect && load_report != control_dir.has_value()) ||
      (load_report && args->flag("udp"))) {
    return die("gated TCP clients need both --load-control and --load-report; --load-report is TCP only");
  }
  auto transport = make(*backend);
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
    so.direct_echo = direct_echo;
    so.sock = sock;
    auto backlog = get_u64(*args, "backlog");
    if (!backlog || *backlog == 0 || *backlog > std::numeric_limits<int>::max()) {
      return die("--backlog must be 1..INT_MAX");
    }
    so.backlog = static_cast<std::uint32_t>(*backlog);
    EchoServer server(t, so);
    if (auto s = server.start(); !s) {
      std::fprintf(stderr, "utcp-echo: %s\n", s.error().c_str());
      return 1;
    }
    std::fprintf(stderr, "utcp-echo: %s echo on %s\n", so.udp ? "UDP" : "TCP",
                 to_string(so.local).c_str());
    bool report_ok = true;
    JsonLine line;
    const auto emit = [&] {
      const ServerStats& stats = server.stats();
      line.clear();
      line.add("role", "server").add("open", server.open_connections())
          .add("accepted", stats.accepted).add("closed", stats.closed)
          .add("errors", stats.errors).add("bytes", stats.bytes)
          .add("staged_bytes", stats.staged_bytes).add("stage_appends", stats.stage_appends)
          .add("compacted_bytes", stats.compacted_bytes).add("relocated_bytes", stats.relocated_bytes)
          .add("requested_backlog", so.backlog);
      if (!(report_ok = report_load(t, line))) {
        t.stop();
      }
    };
    if (load_report) {
      emit();
      t.add_timer(std::chrono::milliseconds(500), emit);
    }
    if (report_ok) {
      t.run(server);  // until a signal
    }
    const ServerStats& st = server.stats();
    line.clear();
    line.add("ev", "summary").add("role", "server").add("udp", so.udp)
        .add("accepted", st.accepted).add("closed", st.closed).add("errors", st.errors)
        .add("bytes", st.bytes).add("datagrams", st.datagrams).add("udp_dropped", st.udp_dropped);
    if (load_report) {
      line.add("staged_bytes", st.staged_bytes).add("stage_appends", st.stage_appends)
          .add("compacted_bytes", st.compacted_bytes).add("relocated_bytes", st.relocated_bytes);
    }
    server.close_all();
    std::printf("%s\n", line.str().c_str());
    return report_ok ? 0 : 1;
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
  if (control_dir) {
    auto batch = get_u64(*args, "open-batch");
    if (!batch || *batch == 0 || *batch > 1024 || *conns == 0 || *conns != *conc || *rate == 0 ||
        std::numeric_limits<std::uint64_t>::max() / *size / *count < *conns) {
      return die("gated load needs equal positive --connections and --concurrency, positive --rate,"
                 " --open-batch 1..1024 and a representable expected byte count");
    }
    std::error_code error;
    if (!std::filesystem::is_directory(*control_dir, error)) {
      return die("--load-control needs an existing directory");
    }
    for (const char* name : {"open", "active", "close"}) {
      if (std::filesystem::exists(std::filesystem::path(*control_dir) / name, error) || error) {
        return die("--load-control directory must be accessible and contain no gate files at startup");
      }
    }
    co.open_batch = *batch;
  }
  EchoClient client(t, co);
  if (auto s = client.start(); !s) {
    std::fprintf(stderr, "utcp-echo: %s\n", s.error().c_str());
    return 1;
  }
  JsonLine line;
  const auto emit = [&] {
    client.load_report(line);
    if (!report_load(t, line)) {
      client.abort("cannot write load report");
    }
  };
  std::optional<TimerToken> report_timer, gate_timer;
  if (load_report && !client.done()) {
    emit();
    report_timer = t.add_timer(std::chrono::milliseconds(500), emit);
  }
  if (control_dir) {
    const auto dir = std::filesystem::path(*control_dir);
    const std::array gates{dir / "open", dir / "active", dir / "close"};
    auto last_phase = client.load_phase();
    gate_timer = t.add_timer(std::chrono::milliseconds(50), [&, gates, last_phase]() mutable {
      const auto phase = client.load_phase();
      const auto* gate = phase == LoadPhase::baseline ? &gates[0] :
                         phase == LoadPhase::idle ? &gates[1] :
                         phase == LoadPhase::drained ? &gates[2] : nullptr;
      std::error_code error;
      if (gate && std::filesystem::exists(*gate, error)) {
        client.advance_load();
      } else if (error) {
        client.abort("cannot read load control: " + error.message());
      }
      if (!client.done() && last_phase != client.load_phase()) {
        last_phase = client.load_phase();
        emit();
      }
    });
  }
  if (!client.done()) {
    t.run(client);
  }
  if (!client.done()) {
    client.abort("interrupted");
  }
  if (report_timer) t.cancel_timer(*report_timer);
  if (gate_timer) t.cancel_timer(*gate_timer);
  t.finish_closing(finish_closing_max);
  std::printf("%s\n", client.summary().str().c_str());
  if (!client.result().ok) {
    std::fprintf(stderr, "utcp-echo: failed: %s\n", client.result().first_error.c_str());
    return 1;
  }
  return 0;
}

}  // namespace utcp::app::echo
