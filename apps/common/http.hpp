// HTTP/1.1 message heads (RFC 9112, RFC 9110) for utcp-httpd and
// utcp-http-get (DESIGN §9): request and response parsing with limits, body
// framing, persistence, request-target to path, URLs, dates and MIME types.
//
// Parsing works on a complete header section; http_head_size() finds where it
// ends in a buffer that is still filling. Lines may end in CRLF or a bare LF
// (RFC 9112 §2.2); a bare CR elsewhere is an error. Obsolete line folding
// (RFC 9112 §5.2) is rejected in requests (400) and replaced by a space in
// responses, as a user agent must.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace utcp::app {

struct HttpLimits {
  std::size_t max_start_line = 8 * 1024;  // request-line or status-line, without the line end
  std::size_t max_head = 64 * 1024;       // the whole header section, empty line included
  std::size_t max_fields = 100;
};

// Why a head was refused, with the status a server answers (400 Bad Request,
// 414 URI Too Long, 431 Request Header Fields Too Large, 501 Not
// Implemented, 505 HTTP Version Not Supported).
struct HttpError {
  int status = 400;
  std::string message;

  bool operator==(const HttpError&) const = default;
};

// Field lines in received order. Names are compared case-insensitively.
class HttpFields {
public:
  void add(std::string name, std::string value);
  // The value of the first line named `name`, or nullptr.
  [[nodiscard]] const std::string* get(std::string_view name) const;
  [[nodiscard]] std::size_t count(std::string_view name) const;
  // The elements of every `name` line as a comma-separated list (RFC 9110
  // §5.6.1), trimmed, empty elements dropped, in order.
  [[nodiscard]] std::vector<std::string_view> list(std::string_view name) const;
  // `token` is an element of list(name), compared case-insensitively.
  [[nodiscard]] bool has_token(std::string_view name, std::string_view token) const;
  [[nodiscard]] const std::vector<std::pair<std::string, std::string>>& all() const { return f_; }
  [[nodiscard]] std::size_t size() const { return f_.size(); }
  // Appends " " and `more` to the last value (obs-fold replacement).
  void append_to_last(std::string_view more);

private:
  std::vector<std::pair<std::string, std::string>> f_;
};

struct HttpRequestHead {
  std::string method;  // case-sensitive token (RFC 9110 §9.1)
  std::string target;  // request-target as received
  int minor = 1;       // HTTP/1.<minor>
  HttpFields fields;
};

struct HttpResponseHead {
  int minor = 1;
  int status = 0;  // 100..599
  std::string reason;
  HttpFields fields;
};

// The size of the header section at the start of `buf`, through the empty
// line that ends it (requests: after any empty lines before the request-line,
// RFC 9112 §2.2). 0 while incomplete. Errors: a start line longer than
// max_start_line (414 for requests), a section longer than max_head (431).
[[nodiscard]] std::expected<std::size_t, HttpError> http_head_size(std::string_view buf,
                                                                   const HttpLimits& limits,
                                                                   bool request);

// Parse a complete header section as found by http_head_size.
[[nodiscard]] std::expected<HttpRequestHead, HttpError> parse_request_head(
    std::string_view head, const HttpLimits& limits = {});
[[nodiscard]] std::expected<HttpResponseHead, HttpError> parse_response_head(
    std::string_view head, const HttpLimits& limits = {});

// How the message body is delimited (RFC 9112 §6.3).
struct BodyFraming {
  enum class Kind : std::uint8_t { none, length, chunked, until_close };
  Kind kind = Kind::none;
  std::uint64_t length = 0;  // Kind::length

  bool operator==(const BodyFraming&) const = default;
};

// Content-Length (RFC 9110 §8.6): nullopt-like 'absent' is reported as
// std::nullopt inside the expected; several lines or list elements must all be
// equal.
[[nodiscard]] std::expected<std::optional<std::uint64_t>, std::string> content_length(
    const HttpFields& f);
// RFC 9112 §6.3 for requests: Transfer-Encoding with chunked last, else
// Content-Length, else no body. Transfer-Encoding without chunked last is 400,
// another coding 501, Transfer-Encoding with Content-Length 400.
[[nodiscard]] std::expected<BodyFraming, HttpError> request_body_framing(const HttpRequestHead& r);
// RFC 9112 §6.3 for responses: none for HEAD, 1xx, 204 and 304;
// Transfer-Encoding with chunked last; Transfer-Encoding otherwise reads to
// close; then Content-Length; then until close.
[[nodiscard]] std::expected<BodyFraming, std::string> response_body_framing(
    const HttpResponseHead& r, bool request_was_head);

// RFC 9112 §9.3: the connection persists after this message.
[[nodiscard]] bool request_keep_alive(const HttpRequestHead& r);
[[nodiscard]] bool response_keep_alive(const HttpResponseHead& r);

// The path of an origin-form ("/a/b?q") or absolute-form ("http://h/a/b")
// request-target (RFC 9112 §3.2), percent-decoded, with "." and ".." segments
// resolved (RFC 3986 §5.2.4) and empty segments removed. A trailing '/' is
// kept. Errors (400): other forms, bad or NUL percent-encodings, and a ".."
// that would leave the root.
[[nodiscard]] std::expected<std::string, HttpError> request_path(std::string_view target);

// "http://host[:port][/path][?query][#fragment]" (RFC 9110 §4.2.1). Only the
// http scheme; no userinfo; IPv6 literals are not supported.
struct HttpUrl {
  std::string host;            // lower-cased
  std::uint16_t port = 80;
  std::string target = "/";    // path and query, the request-target to send
  bool operator==(const HttpUrl&) const = default;
};
[[nodiscard]] std::expected<HttpUrl, std::string> parse_http_url(std::string_view url);

// IMF-fixdate (RFC 9110 §5.6.7), e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
[[nodiscard]] std::string http_date(std::int64_t unix_seconds);
// Standard reason phrase (RFC 9110 §15), "Unknown" for others.
[[nodiscard]] std::string_view status_reason(int status);
// Content-Type for a file name by its extension; application/octet-stream if unknown.
[[nodiscard]] std::string_view mime_type(std::string_view path);
// RFC 9110 §5.6.2 token.
[[nodiscard]] bool is_token(std::string_view s);
// ASCII case-insensitive equality.
[[nodiscard]] bool iequals(std::string_view a, std::string_view b);

}  // namespace utcp::app
