#include "utcp-httpd/httpd.hpp"

#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "common/kernel_transport.hpp"

namespace utcp::app::httpd {

namespace {

constexpr std::size_t file_chunk = 64 * 1024;  // DESIGN §9
constexpr std::size_t read_chunk = 16 * 1024;

}  // namespace

HttpServer::HttpServer(Transport& t, const Options& o) : t_(t), o_(o), buf_(read_chunk) {}

HttpServer::~HttpServer() {
  if (root_fd_ >= 0) {
    ::close(root_fd_);
  }
  for (auto& [id, c] : conns_) {
    if (c.file_fd >= 0) {
      ::close(c.file_fd);
    }
  }
}

std::expected<void, std::string> HttpServer::start() {
  if (root_fd_ < 0) {
    root_fd_ = ::open(o_.root.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root_fd_ < 0) {
      return std::unexpected("--root " + o_.root + ": " + std::strerror(errno));
    }
    char real[PATH_MAX];
    if (::realpath(o_.root.c_str(), real) == nullptr) {
      return std::unexpected("--root " + o_.root + ": " + std::strerror(errno));
    }
    root_real_ = real;
  }
  auto l = t_.listen(o_.local, o_.backlog, o_.sock);
  if (!l) {
    return std::unexpected("listen on " + to_string(o_.local) + ": " + describe(l.error()));
  }
  listener_ = *l;
  if (o_.idle_timeout > Duration::zero()) {
    idle_timer_ = t_.add_timer(std::chrono::seconds(1), [this] { sweep_idle(); });
    idle_timer_on_ = true;
  }
  return {};
}

void HttpServer::close_all() {
  std::vector<ConnId> ids;
  for (const auto& kv : conns_) {
    ids.push_back(kv.first);
  }
  for (const ConnId id : ids) {
    drop(id);
  }
  if (listener_ != no_conn) {
    t_.close(listener_);
    listener_ = no_conn;
  }
  if (idle_timer_on_) {
    t_.cancel_timer(idle_timer_);
    idle_timer_on_ = false;
  }
}

void HttpServer::on_accept(ConnId listener, ConnId conn) {
  if (listener != listener_) {
    return;
  }
  ++stats_.accepted;
  Conn c;
  c.last_active = t_.now();
  conns_.emplace(conn, std::move(c));
  service(conn);
}

void HttpServer::on_readable(ConnId id) {
  if (conns_.contains(id)) {
    service(id);
  }
}

void HttpServer::on_writable(ConnId id) {
  if (conns_.contains(id)) {
    service(id);
  }
}

void HttpServer::on_closed(ConnId id) {
  if (conns_.contains(id)) {
    drop(id);
  }
}

void HttpServer::on_error(ConnId id, Error /*e*/) {
  if (conns_.contains(id)) {
    drop(id);
  }
}

void HttpServer::drop(ConnId id) {
  const auto it = conns_.find(id);
  if (it == conns_.end()) {
    return;
  }
  if (it->second.file_fd >= 0) {
    ::close(it->second.file_fd);
  }
  conns_.erase(it);
  t_.close(id);
  ++stats_.closed;
}

void HttpServer::sweep_idle() {
  const Time now = t_.now();
  std::vector<ConnId> idle;
  for (const auto& [id, c] : conns_) {
    const bool busy = c.out_off < c.out.size() || c.file_left > 0;
    if (!busy && now - c.last_active >= o_.idle_timeout) {
      idle.push_back(id);
    }
  }
  for (const ConnId id : idle) {
    ++stats_.idle_closed;
    drop(id);
  }
}

bool HttpServer::flush(ConnId id, Conn& c) {
  while (true) {
    while (c.out_off < c.out.size()) {
      auto r = t_.send(id, std::as_bytes(std::span(c.out)).subspan(c.out_off));
      if (!r) {
        if (r.error() != Error::would_block) {
          drop(id);
        }
        return false;
      }
      if (*r == 0) {
        return false;
      }
      c.out_off += *r;
      c.last_active = t_.now();
    }
    c.out.clear();
    c.out_off = 0;
    if (c.file_left == 0) {
      if (c.file_fd >= 0) {
        ::close(c.file_fd);
        c.file_fd = -1;
      }
      return true;
    }
    // The next chunk of the file body.
    const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(file_chunk, c.file_left));
    c.out.resize(want);
    const ssize_t n = ::pread(c.file_fd, c.out.data(), want, static_cast<off_t>(c.file_off));
    if (n <= 0) {
      // The file shrank or cannot be read: the announced length cannot be
      // kept, so the connection is closed (RFC 9112 §8: incomplete message).
      std::fprintf(stderr, "utcp-httpd: read error on a file being sent; closing\n");
      drop(id);
      return false;
    }
    c.out.resize(static_cast<std::size_t>(n));
    c.file_off += static_cast<std::uint64_t>(n);
    c.file_left -= static_cast<std::uint64_t>(n);
    stats_.body_bytes += static_cast<std::uint64_t>(n);
  }
}

void HttpServer::service(ConnId id) {
  while (true) {
    const auto it = conns_.find(id);
    if (it == conns_.end()) {
      return;
    }
    Conn& c = it->second;
    if (!flush(id, c)) {
      return;
    }
    if (c.closing) {
      // Our FIN is out; read and discard to the peer's end, then release.
      auto r = t_.recv(id, std::as_writable_bytes(std::span(buf_)));
      if (!r) {
        if (r.error() != Error::would_block) {
          drop(id);
        }
        return;
      }
      if (*r == 0) {
        drop(id);
        return;
      }
      continue;
    }
    if (c.close_after) {
      t_.shutdown_write(id);
      c.closing = true;
      c.in.clear();
      continue;
    }
    if (next_request(c)) {
      continue;
    }
    if (c.eof) {
      drop(id);  // no further complete request can arrive
      return;
    }
    auto r = t_.recv(id, std::as_writable_bytes(std::span(buf_)));
    if (!r) {
      if (r.error() != Error::would_block) {
        drop(id);
      }
      return;
    }
    if (*r == 0) {
      c.eof = true;
      continue;
    }
    c.in.append(buf_.data(), *r);
    c.last_active = t_.now();
  }
}

bool HttpServer::next_request(Conn& c) {
  if (c.body_skip > 0) {
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(c.body_skip, c.in.size()));
    c.in.erase(0, n);
    c.body_skip -= n;
    return n > 0;
  }
  if (c.chunked_skip) {
    if (c.in.empty()) {
      return false;
    }
    std::string discard;
    auto r = c.chunked_skip->feed(c.in, discard);
    if (!r) {
      c.chunked_skip.reset();
      c.in.clear();
      respond_error(c, 400, 1, false, false);
      return true;
    }
    c.in.erase(0, *r);
    if (c.chunked_skip->done()) {
      c.chunked_skip.reset();
      return true;
    }
    return *r > 0;
  }
  if (c.in.empty()) {
    return false;
  }
  const auto size = http_head_size(c.in, o_.limits, /*request=*/true);
  if (!size) {
    c.in.clear();
    respond_error(c, size.error().status, 1, false, false);
    return true;
  }
  if (*size == 0) {
    return false;
  }
  const auto req = parse_request_head(std::string_view(c.in).substr(0, *size), o_.limits);
  c.in.erase(0, *size);
  ++stats_.requests;
  if (!req) {
    c.in.clear();
    if (o_.log) {
      std::fprintf(stderr, "utcp-httpd: bad request: %s -> %d\n", req.error().message.c_str(),
                   req.error().status);
    }
    respond_error(c, req.error().status, 1, false, false);
    return true;
  }
  answer(c, *req);
  return true;
}

void HttpServer::answer(Conn& c, const HttpRequestHead& r) {
  const bool head = r.method == "HEAD";
  int status = 200;
  const auto log = [&] {
    if (o_.log) {
      std::fprintf(stderr, "utcp-httpd: %s %s -> %d\n", r.method.c_str(), r.target.c_str(), status);
    }
  };
  const auto framing = request_body_framing(r);
  if (!framing) {
    status = framing.error().status;
    log();
    c.in.clear();
    respond_error(c, status, r.minor, head, false);
    return;
  }
  if (framing->kind == BodyFraming::Kind::length) {
    c.body_skip = framing->length;
  } else if (framing->kind == BodyFraming::Kind::chunked) {
    c.chunked_skip.emplace();
  }
  const bool keep = request_keep_alive(r);
  // RFC 9112 §3.2: an HTTP/1.1 request without exactly one Host is a 400.
  if (r.minor >= 1 && r.fields.count("host") != 1) {
    status = 400;
    log();
    respond_error(c, status, r.minor, head, false);
    return;
  }
  if (r.method != "GET" && r.method != "HEAD") {
    status = 405;
    log();
    respond_error(c, status, r.minor, false, keep, "Allow: GET, HEAD\r\n");
    return;
  }
  const auto path = request_path(r.target);
  if (!path) {
    status = path.error().status;
    log();
    respond_error(c, status, r.minor, head, keep);
    return;
  }
  std::string file = path->substr(1);  // relative to the root
  if (file.empty() || file.ends_with('/')) {
    file += "index.html";
  }
  const int fd = open_beneath(file);
  struct stat st{};
  if (fd < 0 || ::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    const int err = errno;
    status = fd < 0 && err == EACCES ? 403 : 404;
    if (fd >= 0) {
      ::close(fd);
    }
    log();
    respond_error(c, status, r.minor, head, keep);
    return;
  }
  log();
  const auto size = static_cast<std::uint64_t>(st.st_size);
  respond(c, 200, r.minor, head, keep, mime_type(file), size, {});
  if (head || size == 0) {
    ::close(fd);
  } else {
    c.file_fd = fd;
    c.file_off = 0;
    c.file_left = size;
  }
}

int HttpServer::open_beneath(const std::string& rel) const {
  constexpr int flags = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;
  // Symbolic links are followed only while they stay below the root
  // (openat2(2) RESOLVE_BENEATH, Linux 5.6); request_path has already
  // rejected ".." segments that would leave it.
  open_how how{};
  how.flags = flags;
  how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
  const long fd = ::syscall(SYS_openat2, root_fd_, rel.c_str(), &how, sizeof how);
  if (fd >= 0 || (errno != ENOSYS && errno != EPERM)) {
    return static_cast<int>(fd);
  }
  // No openat2 (an old kernel or a seccomp filter): open, then check that the
  // resolved path lies below the root.
  const int f = ::openat(root_fd_, rel.c_str(), flags);
  if (f < 0) {
    return -1;
  }
  char real[PATH_MAX];
  const std::string self = "/proc/self/fd/" + std::to_string(f);
  if (::realpath(self.c_str(), real) == nullptr ||
      !std::string_view(real).starts_with(root_real_ == "/" ? root_real_ : root_real_ + "/")) {
    ::close(f);
    errno = EXDEV;
    return -1;
  }
  return f;
}

void HttpServer::respond(Conn& c, int status, int minor, bool head_only, bool keep_alive,
                         std::string_view content_type, std::uint64_t length,
                         std::string_view body, std::string_view extra) {
  std::string& o = c.out;
  o += "HTTP/1.1 ";
  o += std::to_string(status);
  o += ' ';
  o += status_reason(status);
  o += "\r\nDate: ";
  o += http_date(static_cast<std::int64_t>(std::time(nullptr)));
  o += "\r\nServer: utcp-httpd\r\nContent-Type: ";
  o += content_type;
  o += "\r\nContent-Length: ";
  o += std::to_string(length);
  o += "\r\n";
  o += extra;
  if (!keep_alive) {
    o += "Connection: close\r\n";
  } else if (minor == 0) {
    o += "Connection: keep-alive\r\n";  // RFC 9112 §9.3: an HTTP/1.0 persistent connection
  }
  o += "\r\n";
  if (!head_only) {
    o += body;
  }
  c.close_after = !keep_alive;
  count_status(status);
}

void HttpServer::respond_error(Conn& c, int status, int minor, bool head_only, bool keep_alive,
                               std::string_view extra) {
  const std::string body = std::to_string(status) + " " + std::string(status_reason(status)) + "\n";
  respond(c, status, minor, head_only, keep_alive, "text/plain; charset=utf-8", body.size(), body,
          extra);
}

void HttpServer::count_status(int status) {
  if (status / 100 == 2) {
    ++stats_.status_2xx;
  } else if (status / 100 == 4) {
    ++stats_.status_4xx;
  } else if (status / 100 == 5) {
    ++stats_.status_5xx;
  }
}

JsonLine HttpServer::summary() const {
  JsonLine line;
  line.add("ev", "summary").add("role", "httpd")
      .add("accepted", stats_.accepted).add("closed", stats_.closed)
      .add("requests", stats_.requests).add("status_2xx", stats_.status_2xx)
      .add("status_4xx", stats_.status_4xx).add("status_5xx", stats_.status_5xx)
      .add("body_bytes", stats_.body_bytes).add("idle_closed", stats_.idle_closed);
  return line;
}

// --- Program.

void add_options(CliParser& p) {
  p.option("listen", "PORT", "listen on PORT (or IP:PORT)", "80")
      .option("root", "DIR", "document root", ".")
      .option("idle-timeout", "S", "close idle connections after S seconds (0: never)", "60")
      .option("backlog", "N", "listen backlog", "1024")
      .flag("log", "log each request on stderr")
      .flag("nodelay", "disable Nagle's algorithm")
      .option("cc", "ALGO", "congestion control: newreno, cubic, bbr");
}

std::expected<Options, std::string> parse_options(const CliArgs& a) {
  Options o;
  const std::string listen = a.get("listen").value_or("80");
  if (listen.find(':') != std::string::npos) {
    auto e = parse_endpoint(listen);
    if (!e) return std::unexpected("--listen: " + e.error());
    o.local = *e;
  } else {
    auto p = parse_port(listen);
    if (!p) return std::unexpected("--listen: " + p.error());
    o.local = Endpoint{Ipv4Addr{}, *p};
  }
  o.root = a.get("root").value_or(".");
  while (o.root.size() > 1 && o.root.ends_with('/')) {
    o.root.pop_back();
  }
  struct stat st{};
  if (::stat(o.root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
    return std::unexpected("--root: '" + o.root + "' is not a directory");
  }
  if (o.root == "/") {
    o.root.clear();  // paths start with '/'
  }
  auto idle = parse_duration(a.get("idle-timeout").value_or("60"), std::chrono::seconds(1));
  if (!idle) return std::unexpected("--idle-timeout: " + idle.error());
  o.idle_timeout = *idle;
  auto backlog = parse_u64(a.get("backlog").value_or("1024"));
  if (!backlog || *backlog == 0 || *backlog > 65535) {
    return std::unexpected(std::string("--backlog must be 1..65535"));
  }
  o.backlog = static_cast<std::uint32_t>(*backlog);
  o.log = a.flag("log");
  if (a.flag("nodelay")) {
    o.sock.nodelay = true;
  }
  if (const auto cc = a.get("cc")) {
    auto v = parse_cc(*cc);
    if (!v) return std::unexpected(v.error());
    o.sock.cc = *v;
  }
  return o;
}

int main_(int argc, const char* const* argv) {
  CliParser cli("utcp-httpd", "HTTP/1.1 GET and HEAD for the files under --root.");
  add_options(cli);
  add_backend_options(cli);
  auto args = cli.parse(argc, argv);
  if (!args) {
    std::fprintf(stderr, "utcp-httpd: %s\n%s", args.error().c_str(), cli.usage().c_str());
    return 2;
  }
  if (args->help()) {
    std::fputs(cli.usage().c_str(), stdout);
    return 0;
  }
  auto opts = parse_options(*args);
  if (!opts) {
    std::fprintf(stderr, "utcp-httpd: %s\n", opts.error().c_str());
    return 2;
  }
  auto backend = parse_backend_options(*args);
  if (!backend) {
    std::fprintf(stderr, "utcp-httpd: %s\n", backend.error().c_str());
    return 2;
  }
  auto transport = make_transport(*backend);
  if (!transport) {
    std::fprintf(stderr, "utcp-httpd: %s\n", transport.error().c_str());
    return 1;
  }
  HttpServer server(**transport, *opts);
  if (auto s = server.start(); !s) {
    std::fprintf(stderr, "utcp-httpd: %s\n", s.error().c_str());
    return 1;
  }
  std::fprintf(stderr, "utcp-httpd: serving %s on %s\n", opts->root.empty() ? "/" : opts->root.c_str(),
               to_string(opts->local).c_str());
  (*transport)->run(server);  // until a signal
  server.close_all();
  std::printf("%s\n", server.summary().str().c_str());
  return 0;
}

}  // namespace utcp::app::httpd
