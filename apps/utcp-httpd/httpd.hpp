// utcp-httpd (DESIGN §9): HTTP/1.1 GET and HEAD for the files under --root.
//
// Responses carry Content-Length; connections persist unless the request
// asks for close (RFC 9112 §9.3) or an error made the framing unreliable.
// Pipelined requests are answered one after the other: the next request is
// parsed once the previous response was handed to the transport. File bodies
// are read in 64 KiB chunks as the socket becomes writable.
//
// Status codes: 200; 400 (malformed request, a missing Host in HTTP/1.1, a
// path that escapes the root after decoding and dot-segment removal); 403
// (not readable); 404 (missing, a directory without index.html, not a
// regular file, or reached through a symbolic link that leads out of the
// root: files are opened with openat2 RESOLVE_BENEATH below the root); 405 (other methods, with Allow); 414 (request line longer
// than the limit); 431 (header section too large); 501 (unknown transfer
// coding); 505 (HTTP major version other than 1). After a 400, 414, 431, 501
// or 505 the connection is closed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "common/chunked.hpp"
#include "common/cli.hpp"
#include "common/http.hpp"
#include "common/jsonl.hpp"
#include "common/transport.hpp"

namespace utcp::app::httpd {

struct Options {
  Endpoint local{Ipv4Addr{}, 80};
  std::string root = ".";
  TcpSocketOptions sock{};
  std::uint32_t backlog = 1024;
  Duration idle_timeout = std::chrono::seconds(60);  // 0: none
  HttpLimits limits{};
  bool log = false;  // one line per request on stderr
};

struct Stats {
  std::uint64_t accepted = 0, closed = 0;
  std::uint64_t requests = 0;
  std::uint64_t status_2xx = 0, status_4xx = 0, status_5xx = 0;
  std::uint64_t body_bytes = 0;  // response body bytes handed to the transport
  std::uint64_t idle_closed = 0;
};

class HttpServer final : public Handler {
public:
  HttpServer(Transport& t, const Options& o);
  ~HttpServer() override;
  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;

  // Opens --root and listens.
  [[nodiscard]] std::expected<void, std::string> start();
  [[nodiscard]] bool owns(ConnId id) const { return id == listener_ || conns_.contains(id); }
  [[nodiscard]] const Stats& stats() const { return stats_; }
  [[nodiscard]] std::size_t open_connections() const { return conns_.size(); }
  [[nodiscard]] JsonLine summary() const;
  void close_all();

  void on_accept(ConnId listener, ConnId conn) override;
  void on_readable(ConnId id) override;
  void on_writable(ConnId id) override;
  void on_closed(ConnId id) override;
  void on_error(ConnId id, Error e) override;

private:
  struct Conn {
    std::string in;              // received, not yet parsed
    std::string out;             // response bytes not yet sent
    std::size_t out_off = 0;
    int file_fd = -1;            // body being sent
    std::uint64_t file_off = 0, file_left = 0;
    std::uint64_t body_skip = 0;  // request body bytes still to discard
    std::optional<ChunkedDecoder> chunked_skip;  // chunked request body being discarded
    bool close_after = false;    // close once the current response is out
    bool closing = false;        // our FIN is sent; reading to the peer's end
    bool eof = false;            // the peer ended its stream
    Time last_active{};
  };

  void service(ConnId id);
  // Sends what is queued, reading file chunks as needed. False if the
  // transport cannot take more now or the connection was dropped.
  bool flush(ConnId id, Conn& c);
  // Consumes request bytes from c.in: body to skip or one request (answered
  // into c.out). False if nothing could be consumed.
  bool next_request(Conn& c);
  void answer(Conn& c, const HttpRequestHead& r);
  void respond(Conn& c, int status, int minor, bool head_only, bool keep_alive,
               std::string_view content_type, std::uint64_t length, std::string_view body,
               std::string_view extra = {});
  void respond_error(Conn& c, int status, int minor, bool head_only, bool keep_alive,
                     std::string_view extra = {});
  void drop(ConnId id);
  void sweep_idle();
  void count_status(int status);
  // Opens `rel` (relative to the root) read-only without leaving the root;
  // -1 with errno set on failure (EXDEV: it would leave the root).
  int open_beneath(const std::string& rel) const;

  Transport& t_;
  Options o_;
  ConnId listener_ = no_conn;
  int root_fd_ = -1;              // O_PATH descriptor of --root
  std::string root_real_;         // realpath of --root (the fallback without openat2)
  std::map<ConnId, Conn> conns_;
  std::vector<char> buf_;
  TimerToken idle_timer_ = 0;
  bool idle_timer_on_ = false;
  Stats stats_;
};

void add_options(CliParser& p);
[[nodiscard]] std::expected<Options, std::string> parse_options(const CliArgs& a);
int main_(int argc, const char* const* argv);

}  // namespace utcp::app::httpd
