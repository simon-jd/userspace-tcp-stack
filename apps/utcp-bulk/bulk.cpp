#include "utcp-bulk/bulk.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "common/kernel_transport.hpp"

namespace utcp::app::bulk {

namespace {

constexpr std::uint64_t golden = 0x9e3779b97f4a7c15ULL;

std::uint64_t splitmix64(std::uint64_t z) noexcept {
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

std::int64_t to_us(Duration d) { return d.count() / 1000; }

}  // namespace

void pattern_fill(std::uint64_t seed, std::uint64_t offset, std::span<std::byte> out) noexcept {
  std::size_t i = 0;
  while (i < out.size()) {
    const std::uint64_t o = offset + i;
    const std::uint64_t word = splitmix64(seed + (o / 8) * golden);
    const unsigned first = static_cast<unsigned>(o % 8);
    if (first == 0 && out.size() - i >= 8) {
      for (unsigned b = 0; b < 8; ++b) {
        out[i + b] = static_cast<std::byte>(word >> (8 * b));
      }
      i += 8;
      continue;
    }
    for (unsigned b = first; b < 8 && i < out.size(); ++b, ++i) {
      out[i] = static_cast<std::byte>(word >> (8 * b));
    }
  }
}

void add_options(CliParser& p) {
  p.option("listen", "PORT", "accept one connection on PORT (or IP:PORT)")
      .option("connect", "IP:PORT", "connect to IP:PORT")
      .flag("send", "send the pattern")
      .flag("recv", "receive (the default)")
      .option("bytes", "N", "sender: bytes to send (K, M, G, Ki, Mi, Gi); receiver: bytes expected")
      .option("duration", "S", "sender: send for S seconds (e.g. 10, 2.5s, 500ms)")
      .option("cc", "ALGO", "congestion control: newreno, cubic, bbr")
      .option("snd-buf", "N", "send buffer (default: autotuning)")
      .option("rcv-buf", "N", "receive buffer (default: autotuning)")
      .flag("nodelay", "disable Nagle's algorithm")
      .option("recv-pause", "MS:BYTES", "stop reading for MS ms after every BYTES read")
      .option("sample-ms", "MS", "statistics sample interval (0: none)", "10")
      .option("jsonl", "FILE", "write samples and the summary as JSON lines (- = stdout)")
      .option("pattern-seed", "N", "seed of the byte pattern", "1")
      .option("chunk", "N", "bytes per send or recv call", "256Ki");
}

std::expected<Options, std::string> parse_options(const CliArgs& a) {
  Options o;
  const auto listen = a.get("listen");
  const auto connect = a.get("connect");
  if (listen.has_value() == connect.has_value()) {
    return std::unexpected(std::string("give exactly one of --listen and --connect"));
  }
  if (listen) {
    o.listen = true;
    if (listen->find(':') != std::string::npos) {
      auto e = parse_endpoint(*listen);
      if (!e) return std::unexpected("--listen: " + e.error());
      o.endpoint = *e;
    } else {
      auto port = parse_port(*listen);
      if (!port) return std::unexpected("--listen: " + port.error());
      o.endpoint = Endpoint{Ipv4Addr{}, *port};
    }
  } else {
    auto e = parse_endpoint(*connect);
    if (!e) return std::unexpected("--connect: " + e.error());
    o.endpoint = *e;
  }
  if (a.flag("send") && a.flag("recv")) {
    return std::unexpected(std::string("give at most one of --send and --recv"));
  }
  o.sender = a.flag("send");
  if (const auto b = a.get("bytes")) {
    auto v = parse_size(*b);
    if (!v) return std::unexpected("--bytes: " + v.error());
    o.bytes = *v;
  }
  if (const auto d = a.get("duration")) {
    auto v = parse_duration(*d, std::chrono::seconds(1));
    if (!v) return std::unexpected("--duration: " + v.error());
    o.duration = *v;
  }
  if (o.sender && o.bytes.has_value() == o.duration.has_value()) {
    return std::unexpected(std::string("the sender needs exactly one of --bytes and --duration"));
  }
  if (!o.sender && o.duration) {
    return std::unexpected(std::string("--duration is for the sender"));
  }
  if (const auto cc = a.get("cc")) {
    auto v = parse_cc(*cc);
    if (!v) return std::unexpected(v.error());
    o.sock.cc = *v;
  }
  for (const char* name : {"snd-buf", "rcv-buf"}) {
    if (const auto s = a.get(name)) {
      auto v = parse_size(*s);
      if (!v || *v == 0 || *v > 0x7fffffff) {
        return std::unexpected(std::string("--") + name + ": a size from 1 to 2Gi-1");
      }
      (std::strcmp(name, "snd-buf") == 0 ? o.sock.snd_buf : o.sock.rcv_buf) =
          static_cast<std::uint32_t>(*v);
    }
  }
  if (a.flag("nodelay")) {
    o.sock.nodelay = true;
  }
  if (const auto p = a.get("recv-pause")) {
    if (o.sender) return std::unexpected(std::string("--recv-pause is for the receiver"));
    auto pair = parse_pair(*p);
    if (!pair) return std::unexpected("--recv-pause: " + pair.error());
    auto ms = parse_duration(pair->first, std::chrono::milliseconds(1));
    auto every = parse_size(pair->second);
    if (!ms || !every || *every == 0) {
      return std::unexpected(std::string("--recv-pause: MS:BYTES with BYTES > 0"));
    }
    o.pause = *ms;
    o.pause_every = *every;
  }
  auto sample = parse_duration(a.get("sample-ms").value_or("10"), std::chrono::milliseconds(1));
  if (!sample) return std::unexpected("--sample-ms: " + sample.error());
  o.sample_interval = *sample;
  auto seed = parse_u64(a.get("pattern-seed").value_or("1"));
  if (!seed) return std::unexpected("--pattern-seed: " + seed.error());
  o.seed = *seed;
  auto chunk = parse_size(a.get("chunk").value_or("256Ki"));
  if (!chunk || *chunk == 0 || *chunk > (std::uint64_t{1} << 30)) {
    return std::unexpected(std::string("--chunk: a size from 1 to 1Gi"));
  }
  o.chunk = static_cast<std::size_t>(*chunk);
  o.backend = a.get("backend").value_or("utcp");
  return o;
}

BulkApp::BulkApp(Transport& t, const Options& o, JsonlWriter* jsonl)
    : t_(t), o_(o), jsonl_(jsonl), buf_(o.chunk) {}

std::expected<void, std::string> BulkApp::start() {
  if (o_.listen) {
    auto l = t_.listen(o_.endpoint, 1, o_.sock);
    if (!l) return std::unexpected("listen on " + to_string(o_.endpoint) + ": " + describe(l.error()));
    listener_ = *l;
    return {};
  }
  auto c = t_.connect(o_.endpoint, o_.sock);
  if (!c) return std::unexpected("connect to " + to_string(o_.endpoint) + ": " + describe(c.error()));
  conn_ = *c;
  return {};
}

void BulkApp::on_accept(ConnId listener, ConnId conn) {
  if (listener != listener_ || conn_ != no_conn) {
    t_.close(conn);  // one connection only
    return;
  }
  t_.close(listener_);
  listener_ = no_conn;
  conn_ = conn;
  begin(conn);
}

void BulkApp::on_connected(ConnId conn) {
  if (conn == conn_) {
    begin(conn);
  }
}

void BulkApp::begin(ConnId /*conn*/) {
  start_ = t_.now();
  if (o_.sample_interval > Duration::zero()) {
    sample_timer_ = t_.add_timer(o_.sample_interval, [this] { take_sample(); });
    sample_timer_on_ = true;
  }
  if (o_.sender) {
    if (o_.duration) {
      t_.add_oneshot(*o_.duration, [this] {
        stop_sending_ = true;
        pump();
      });
    }
    pump();
  } else {
    drain();
  }
}

bool BulkApp::yield(bool sending) {
  // A send or receive loop that never meets would_block (loopback) would keep
  // the event loop from running timers; after a slice it continues from a
  // zero-delay timer instead.
  if (t_.now() - slice_start_ < slice) {
    return false;
  }
  bool& pending = sending ? pump_scheduled_ : drain_scheduled_;
  if (!pending) {
    pending = true;
    t_.add_oneshot(Duration::zero(), [this, sending] {
      if (sending) {
        pump_scheduled_ = false;
        pump();
      } else {
        drain_scheduled_ = false;
        drain();
      }
    });
  }
  return true;
}

void BulkApp::pump() {
  if (done_ || !o_.sender || sending_done_ || conn_ == no_conn) {
    return;
  }
  slice_start_ = t_.now();
  while (true) {
    if (yield(true)) {
      return;
    }
    if (stop_sending_ || (o_.bytes && offset_ >= *o_.bytes)) {
      sending_done_ = true;
      t_.shutdown_write(conn_);
      drain();  // the receiver's FIN may already be in
      return;
    }
    if (buf_len_ == 0) {
      std::size_t n = buf_.size();
      if (o_.bytes) {
        n = static_cast<std::size_t>(std::min<std::uint64_t>(n, *o_.bytes - offset_));
      }
      pattern_fill(o_.seed, offset_, std::span(buf_).first(n));
      buf_off_ = 0;
      buf_len_ = n;
    }
    auto r = t_.send(conn_, std::span(buf_).subspan(buf_off_, buf_len_));
    if (!r) {
      if (r.error() != Error::would_block) {
        fail("send: " + describe(r.error()));
      }
      return;  // on_writable resumes
    }
    hash_.update(std::span(buf_).subspan(buf_off_, *r));
    buf_off_ += *r;
    buf_len_ -= *r;
    offset_ += *r;
    if (*r == 0) {
      return;
    }
  }
}

void BulkApp::drain() {
  if (done_ || conn_ == no_conn) {
    return;
  }
  slice_start_ = t_.now();
  while (!paused_) {
    if (yield(false)) {
      return;
    }
    std::size_t want = buf_.size();
    if (!o_.sender && o_.pause) {
      want = static_cast<std::size_t>(std::min<std::uint64_t>(want, o_.pause_every - since_pause_));
    }
    auto r = t_.recv(conn_, std::span(buf_).first(want));
    if (!r) {
      if (r.error() != Error::would_block) {
        fail("recv: " + describe(r.error()));
      }
      return;
    }
    if (*r == 0) {
      // End of stream.
      if (!o_.sender) {
        result_.duration = t_.now() - start_;
        t_.shutdown_write(conn_);
      } else {
        result_.duration = t_.now() - start_;
      }
      finish();
      return;
    }
    if (o_.sender) {
      continue;  // the receiver sends nothing; discard
    }
    hash_.update(std::span(buf_).first(*r));
    offset_ += *r;
    if (o_.pause) {
      since_pause_ += *r;
      if (since_pause_ >= o_.pause_every) {
        since_pause_ = 0;
        paused_ = true;
        t_.add_oneshot(*o_.pause, [this] {
          paused_ = false;
          drain();
        });
      }
    }
  }
}

void BulkApp::on_readable(ConnId id) {
  if (id == conn_) {
    drain();
  }
}

void BulkApp::on_writable(ConnId id) {
  if (id == conn_) {
    pump();
  }
}

void BulkApp::on_closed(ConnId id) {
  if (id == conn_ && !done_) {
    drain();
  }
}

void BulkApp::on_error(ConnId id, Error e) {
  if (id == conn_ || id == listener_) {
    fail("connection failed: " + describe(e));
  }
}

void BulkApp::take_sample() {
  if (conn_ == no_conn) {
    return;
  }
  const ConnSample s = t_.sample(conn_);
  result_.last = s;
  ++result_.samples;
  if (jsonl_ == nullptr) {
    return;
  }
  JsonLine line;
  line.add("t", t_.now().ns).add("ev", "sample").add("role", role());
  add_fields(line, s);
  // DESIGN §9: inflight = unacked - sacked - lost + retrans (Linux
  // tcp_packets_in_flight), in packets.
  const std::int64_t inflight = std::int64_t{s.unacked} - s.sacked - s.lost + s.retrans;
  line.add("inflight", inflight);
  jsonl_->write(line);
}

void BulkApp::finish() {
  if (done_) {
    return;
  }
  if (o_.sender && offset_ == 0 && o_.bytes && *o_.bytes > 0) {
    fail("the receiver closed before any data was sent");
    return;
  }
  take_sample();
  if (sample_timer_on_) {
    t_.cancel_timer(sample_timer_);
    sample_timer_on_ = false;
  }
  result_.bytes = offset_;
  result_.sha256 = to_hex(hash_.finish());
  result_.ok = true;
  if (!o_.sender && o_.bytes && *o_.bytes != offset_) {
    result_.ok = false;
    result_.error = "received " + std::to_string(offset_) + " bytes, expected " +
                    std::to_string(*o_.bytes);
  }
  done_ = true;
  t_.close(conn_);
  conn_ = no_conn;
  t_.stop();
}

void BulkApp::fail(const std::string& why) {
  if (done_) {
    return;
  }
  if (conn_ != no_conn) {
    take_sample();
  }
  if (sample_timer_on_) {
    t_.cancel_timer(sample_timer_);
    sample_timer_on_ = false;
  }
  result_.ok = false;
  result_.error = why;
  result_.bytes = offset_;
  result_.sha256 = to_hex(hash_.finish());
  if (start_.ns != 0 || conn_ != no_conn) {
    result_.duration = t_.now() - start_;
  }
  done_ = true;
  if (conn_ != no_conn) {
    t_.close(conn_);
    conn_ = no_conn;
  }
  if (listener_ != no_conn) {
    t_.close(listener_);
    listener_ = no_conn;
  }
  t_.stop();
}

void BulkApp::abort(const std::string& why) { fail(why); }

JsonLine BulkApp::summary() const {
  JsonLine line;
  const ConnSample& s = result_.last;
  line.add("ev", "summary").add("role", role()).add("backend", o_.backend).add("ok", result_.ok);
  if (!result_.ok) {
    line.add("error", result_.error);
  }
  line.add("bytes", result_.bytes).add("duration_us", to_us(result_.duration));
  // Goodput in bits per second: application bytes over the duration.
  const std::int64_t ns = result_.duration.count();
  const std::uint64_t goodput =
      ns > 0 ? static_cast<std::uint64_t>(static_cast<double>(result_.bytes) * 8e9 /
                                          static_cast<double>(ns))
             : 0;
  line.add("goodput_bps", goodput).add("sha256", result_.sha256);
  line.add("cc", s.cc_name_view())
      .add("total_retrans", s.total_retrans)
      .add("bytes_retrans", s.bytes_retrans)
      .add("busy_us", to_us(s.busy_time))
      .add("rwnd_limited_us", to_us(s.rwnd_limited))
      .add("sndbuf_limited_us", to_us(s.sndbuf_limited))
      .add("samples", result_.samples);
  if (const LoopStats* ls = t_.loop_stats()) {
    const LatenessHistogram& h = ls->lateness;
    line.add("lateness_count", h.count)
        .add("lateness_p50_ns", h.percentile(0.50).count())
        .add("lateness_p99_ns", h.percentile(0.99).count())
        .add("lateness_p999_ns", h.percentile(0.999).count())
        .add("lateness_max_ns", h.max.count());
  }
  return line;
}

int main_(int argc, const char* const* argv) {
  CliParser cli("utcp-bulk", "Bulk transfer over one TCP connection, SHA-256 of the stream.");
  add_options(cli);
  add_backend_options(cli);
  auto args = cli.parse(argc, argv);
  if (!args) {
    std::fprintf(stderr, "utcp-bulk: %s\n%s", args.error().c_str(), cli.usage().c_str());
    return 2;
  }
  if (args->help()) {
    std::fputs(cli.usage().c_str(), stdout);
    return 0;
  }
  auto opts = parse_options(*args);
  if (!opts) {
    std::fprintf(stderr, "utcp-bulk: %s\n", opts.error().c_str());
    return 2;
  }
  auto backend = parse_backend_options(*args);
  if (!backend) {
    std::fprintf(stderr, "utcp-bulk: %s\n", backend.error().c_str());
    return 2;
  }
  std::optional<JsonlWriter> jsonl;
  if (const auto path = args->get("jsonl")) {
    auto w = JsonlWriter::open(*path);
    if (!w) {
      std::fprintf(stderr, "utcp-bulk: %s\n", w.error().c_str());
      return 2;
    }
    jsonl.emplace(std::move(*w));
  }
  auto transport = make_transport(*backend);
  if (!transport) {
    std::fprintf(stderr, "utcp-bulk: %s\n", transport.error().c_str());
    return 1;
  }
  BulkApp app(**transport, *opts, jsonl ? &*jsonl : nullptr);
  if (auto s = app.start(); !s) {
    std::fprintf(stderr, "utcp-bulk: %s\n", s.error().c_str());
    return 1;
  }
  (*transport)->run(app);
  if (!app.done()) {
    app.abort("interrupted");
  }
  const JsonLine summary = app.summary();
  if (jsonl) {
    jsonl->write(summary);
    jsonl->flush();
  }
  if (args->get("jsonl") != "-") {
    std::printf("%s\n", summary.str().c_str());
    std::fflush(stdout);
  }
  if (!app.result().ok) {
    std::fprintf(stderr, "utcp-bulk: %s\n", app.result().error.c_str());
    return 1;
  }
  return 0;
}

}  // namespace utcp::app::bulk
