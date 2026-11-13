// utcp-http-get (DESIGN §9): `utcp-http-get URL [-o FILE] [--resolve host:ip]
// [--dns IP]`. Plain http:// only. Sends one GET with Host and
// `Connection: close`, reads the status line and fields, and the body by
// Content-Length, chunked (trailers kept) or read-to-close (RFC 9112 §6.3).
// Interim 1xx responses are skipped. No redirects: a 3xx is an error. Prints
// the body's SHA-256 and length.
//
// The exit status is 0 only for a complete body with a 2xx status; other
// statuses still read and hash the body but exit 1.
//
// Name resolution: an IPv4 literal; else --resolve host:ip; else one A query
// over the transport's UDP to --dns (port 53), retried on a timeout.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "common/chunked.hpp"
#include "common/cli.hpp"
#include "common/http.hpp"
#include "common/jsonl.hpp"
#include "common/sha256.hpp"
#include "common/transport.hpp"

namespace utcp::app::http_get {

struct Options {
  HttpUrl url{};
  std::string url_text;
  std::vector<std::pair<std::string, Ipv4Addr>> resolve;  // --resolve host:ip
  std::optional<Ipv4Addr> dns;                             // --dns IP
  Duration dns_timeout = std::chrono::seconds(2);
  int dns_tries = 3;
  Duration timeout = std::chrono::seconds(0);  // whole transfer; 0 = none
  TcpSocketOptions sock{};
  HttpLimits limits{};
};

struct Result {
  bool ok = false;
  std::string error;
  Ipv4Addr addr{};
  int status = 0;
  std::string reason;
  std::string framing;  // "length", "chunked", "until_close", "none"
  std::uint64_t body_bytes = 0;
  std::string sha256;
  HttpFields fields;    // the final response's header fields
  HttpFields trailers;  // chunked trailers
  Duration duration{};
};

// Called with each piece of the body; false stops the transfer (write error).
using BodySink = std::function<bool(std::span<const std::byte>)>;

class HttpGet final : public Handler {
public:
  HttpGet(Transport& t, const Options& o, BodySink sink = {});
  // Resolves and connects; the transport is stopped when done.
  [[nodiscard]] std::expected<void, std::string> start();
  [[nodiscard]] bool done() const { return done_; }
  [[nodiscard]] const Result& result() const { return result_; }
  [[nodiscard]] JsonLine summary() const;
  void abort(const std::string& why);

  void on_connected(ConnId id) override;
  void on_readable(ConnId id) override;
  void on_writable(ConnId id) override;
  void on_closed(ConnId id) override;
  void on_error(ConnId id, Error e) override;

private:
  enum class Phase : std::uint8_t { resolving, connecting, head, body, done };

  void send_query();
  void dns_readable();
  void connect_to(Ipv4Addr addr);
  void send_request();
  void read_response();
  // Consumes c.in; false when it needs more bytes or the transfer ended.
  bool parse_head();
  bool deliver(std::string_view data);
  void complete();
  void fail(const std::string& why);
  void release();

  Transport& t_;
  Options o_;
  BodySink sink_;
  Phase phase_ = Phase::resolving;
  ConnId udp_ = no_conn, conn_ = no_conn;
  std::uint16_t dns_id_ = 0;
  int dns_sent_ = 0;
  TimerToken dns_timer_ = 0, deadline_timer_ = 0;
  bool dns_timer_on_ = false, deadline_timer_on_ = false;
  std::string request_;
  std::size_t request_off_ = 0;
  std::string in_;
  BodyFraming framing_{};
  std::uint64_t remaining_ = 0;
  std::optional<ChunkedDecoder> chunked_;
  Sha256 hash_;
  Time start_{};
  bool done_ = false;
  Result result_;
};

void add_options(CliParser& p);
[[nodiscard]] std::expected<Options, std::string> parse_options(const CliArgs& a);
int main_(int argc, const char* const* argv);

}  // namespace utcp::app::http_get
