#include "common/http.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>

namespace utcp::app {

namespace {

char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

bool istarts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && iequals(s.substr(0, prefix.size()), prefix);
}

bool is_ows(char c) { return c == ' ' || c == '\t'; }

std::string_view trim_ows(std::string_view s) {
  while (!s.empty() && is_ows(s.front())) {
    s.remove_prefix(1);
  }
  while (!s.empty() && is_ows(s.back())) {
    s.remove_suffix(1);
  }
  return s;
}

bool is_digit(char c) { return c >= '0' && c <= '9'; }

HttpError err(int status, std::string msg) { return HttpError{status, std::move(msg)}; }

// RFC 9110 §5.5: field-value characters are VCHAR, SP, HTAB and obs-text.
bool valid_field_value(std::string_view v) {
  return std::ranges::all_of(v, [](char ch) {
    const auto c = static_cast<unsigned char>(ch);
    return c == '\t' || (c >= 0x20 && c != 0x7f);
  });
}

// Splits a header section into lines without their line ends. A CR that does
// not end a line is an error (RFC 9112 §2.2).
std::expected<std::vector<std::string_view>, HttpError> split_lines(std::string_view head) {
  std::vector<std::string_view> lines;
  std::size_t pos = 0;
  while (pos < head.size()) {
    const std::size_t nl = head.find('\n', pos);
    std::string_view line = head.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }
    if (line.find('\r') != std::string_view::npos) {
      return std::unexpected(err(400, "bare CR in the header section"));
    }
    lines.push_back(line);
    if (nl == std::string_view::npos) {
      break;
    }
    pos = nl + 1;
  }
  return lines;
}

// "HTTP/" DIGIT "." DIGIT (RFC 9112 §2.3): the minor version. A major version
// other than 1 is 505.
std::expected<int, HttpError> parse_version(std::string_view v) {
  if (v.size() != 8 || !v.starts_with("HTTP/") || !is_digit(v[5]) || v[6] != '.' ||
      !is_digit(v[7])) {
    return std::unexpected(err(400, "bad HTTP version"));
  }
  if (v[5] != '1') {
    return std::unexpected(err(505, "HTTP version not supported"));
  }
  return v[7] - '0';
}

// Field lines from `first` to the empty line.
std::expected<void, HttpError> parse_fields(const std::vector<std::string_view>& lines,
                                            std::size_t first, HttpFields& out,
                                            const HttpLimits& limits, bool allow_fold) {
  for (std::size_t i = first; i < lines.size(); ++i) {
    const std::string_view line = lines[i];
    if (line.empty()) {
      return {};
    }
    if (is_ows(line.front())) {
      // RFC 9112 §5.2: obs-fold.
      if (!allow_fold) {
        return std::unexpected(err(400, "obsolete line folding is not accepted"));
      }
      if (out.size() == 0) {
        return std::unexpected(err(400, "whitespace before the first field line"));
      }
      const std::string_view more = trim_ows(line);
      if (!valid_field_value(more)) {
        return std::unexpected(err(400, "invalid character in a field value"));
      }
      out.append_to_last(more);
      continue;
    }
    const std::size_t colon = line.find(':');
    if (colon == std::string_view::npos) {
      return std::unexpected(err(400, "field line without a colon"));
    }
    const std::string_view name = line.substr(0, colon);
    // RFC 9112 §5.1: no whitespace between the name and the colon.
    if (!is_token(name)) {
      return std::unexpected(err(400, "invalid field name"));
    }
    const std::string_view value = trim_ows(line.substr(colon + 1));
    if (!valid_field_value(value)) {
      return std::unexpected(err(400, "invalid character in a field value"));
    }
    if (out.size() >= limits.max_fields) {
      return std::unexpected(err(431, "too many header fields"));
    }
    out.add(std::string(name), std::string(value));
  }
  return std::unexpected(err(400, "header section does not end with an empty line"));
}

}  // namespace

bool iequals(std::string_view a, std::string_view b) {
  return a.size() == b.size() &&
         std::ranges::equal(a, b, [](char x, char y) { return lower(x) == lower(y); });
}

bool is_token(std::string_view s) {
  if (s.empty()) {
    return false;
  }
  return std::ranges::all_of(s, [](char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || is_digit(c)) {
      return true;
    }
    return std::string_view("!#$%&'*+-.^_`|~").find(c) != std::string_view::npos;
  });
}

// --- HttpFields.

void HttpFields::add(std::string name, std::string value) {
  f_.emplace_back(std::move(name), std::move(value));
}

void HttpFields::append_to_last(std::string_view more) {
  if (f_.empty()) {
    return;
  }
  std::string& v = f_.back().second;
  if (!more.empty()) {
    if (!v.empty()) {
      v += ' ';
    }
    v += more;
  }
}

const std::string* HttpFields::get(std::string_view name) const {
  for (const auto& [n, v] : f_) {
    if (iequals(n, name)) {
      return &v;
    }
  }
  return nullptr;
}

std::size_t HttpFields::count(std::string_view name) const {
  return static_cast<std::size_t>(
      std::ranges::count_if(f_, [name](const auto& kv) { return iequals(kv.first, name); }));
}

std::vector<std::string_view> HttpFields::list(std::string_view name) const {
  std::vector<std::string_view> out;
  for (const auto& [n, v] : f_) {
    if (!iequals(n, name)) {
      continue;
    }
    std::string_view rest = v;
    while (true) {
      const std::size_t comma = rest.find(',');
      const std::string_view elem = trim_ows(rest.substr(0, comma));
      if (!elem.empty()) {
        out.push_back(elem);
      }
      if (comma == std::string_view::npos) {
        break;
      }
      rest.remove_prefix(comma + 1);
    }
  }
  return out;
}

bool HttpFields::has_token(std::string_view name, std::string_view token) const {
  return std::ranges::any_of(list(name), [token](std::string_view e) { return iequals(e, token); });
}

// --- Heads.

std::expected<std::size_t, HttpError> http_head_size(std::string_view buf, const HttpLimits& limits,
                                                     bool request) {
  std::size_t pos = 0;
  if (request) {
    // RFC 9112 §2.2: empty lines before the request-line are ignored.
    while (true) {
      if (pos < buf.size() && buf[pos] == '\n') {
        ++pos;
      } else if (pos + 1 < buf.size() && buf[pos] == '\r' && buf[pos + 1] == '\n') {
        pos += 2;
      } else {
        break;
      }
      if (pos > limits.max_head) {
        return std::unexpected(err(431, "header section too large"));
      }
    }
  }
  std::size_t nl = buf.find('\n', pos);
  if (nl == std::string_view::npos) {
    if (buf.size() - pos > limits.max_start_line + 1) {
      return std::unexpected(err(request ? 414 : 400, request ? "request line too long" : "status line too long"));
    }
    if (buf.size() > limits.max_head) {
      return std::unexpected(err(431, "header section too large"));
    }
    return 0;
  }
  const std::size_t start_len = nl - pos - (nl > pos && buf[nl - 1] == '\r' ? 1 : 0);
  if (start_len > limits.max_start_line) {
    return std::unexpected(err(request ? 414 : 400, request ? "request line too long" : "status line too long"));
  }
  std::size_t p = nl + 1;
  while (true) {
    if (p > limits.max_head) {
      return std::unexpected(err(431, "header section too large"));
    }
    nl = buf.find('\n', p);
    if (nl == std::string_view::npos) {
      if (buf.size() > limits.max_head) {
        return std::unexpected(err(431, "header section too large"));
      }
      return 0;
    }
    const bool empty = nl == p || (nl == p + 1 && buf[p] == '\r');
    if (empty) {
      if (nl + 1 > limits.max_head) {
        return std::unexpected(err(431, "header section too large"));
      }
      return nl + 1;
    }
    p = nl + 1;
  }
}

std::expected<HttpRequestHead, HttpError> parse_request_head(std::string_view head,
                                                             const HttpLimits& limits) {
  auto lines = split_lines(head);
  if (!lines) {
    return std::unexpected(lines.error());
  }
  std::size_t i = 0;
  while (i < lines->size() && (*lines)[i].empty()) {
    ++i;
  }
  if (i == lines->size()) {
    return std::unexpected(err(400, "no request line"));
  }
  // RFC 9112 §3: method SP request-target SP HTTP-version.
  const std::string_view line = (*lines)[i];
  if (line.size() > limits.max_start_line) {
    return std::unexpected(err(414, "request line too long"));
  }
  const std::size_t sp1 = line.find(' ');
  const std::size_t sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
  if (sp2 == std::string_view::npos || line.find(' ', sp2 + 1) != std::string_view::npos) {
    return std::unexpected(err(400, "malformed request line"));
  }
  HttpRequestHead r;
  const std::string_view method = line.substr(0, sp1);
  const std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
  if (!is_token(method)) {
    return std::unexpected(err(400, "invalid method"));
  }
  if (target.empty() || !std::ranges::all_of(target, [](char c) { return c > 0x20 && c < 0x7f; })) {
    return std::unexpected(err(400, "invalid request target"));
  }
  const auto minor = parse_version(line.substr(sp2 + 1));
  if (!minor) {
    return std::unexpected(minor.error());
  }
  r.method = method;
  r.target = target;
  r.minor = *minor;
  if (auto f = parse_fields(*lines, i + 1, r.fields, limits, /*allow_fold=*/false); !f) {
    return std::unexpected(f.error());
  }
  return r;
}

std::expected<HttpResponseHead, HttpError> parse_response_head(std::string_view head,
                                                               const HttpLimits& limits) {
  auto lines = split_lines(head);
  if (!lines) {
    return std::unexpected(lines.error());
  }
  if (lines->empty()) {
    return std::unexpected(err(400, "no status line"));
  }
  // RFC 9112 §4: HTTP-version SP status-code SP [reason-phrase]. A missing
  // SP after the code with an empty reason is accepted.
  const std::string_view line = (*lines)[0];
  if (line.size() > limits.max_start_line) {
    return std::unexpected(err(400, "status line too long"));
  }
  HttpResponseHead r;
  const auto minor = parse_version(line.substr(0, 8));
  if (!minor) {
    return std::unexpected(minor.error());
  }
  r.minor = *minor;
  if (line.size() < 12 || line[8] != ' ' || !is_digit(line[9]) || !is_digit(line[10]) ||
      !is_digit(line[11]) || (line.size() > 12 && line[12] != ' ')) {
    return std::unexpected(err(400, "malformed status line"));
  }
  r.status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
  if (r.status < 100 || r.status > 599) {
    return std::unexpected(err(400, "status code out of range"));
  }
  if (line.size() > 13) {
    const std::string_view reason = line.substr(13);
    if (!valid_field_value(reason)) {
      return std::unexpected(err(400, "invalid character in the reason phrase"));
    }
    r.reason = reason;
  }
  if (auto f = parse_fields(*lines, 1, r.fields, limits, /*allow_fold=*/true); !f) {
    return std::unexpected(f.error());
  }
  return r;
}

// --- Framing and persistence.

std::expected<std::optional<std::uint64_t>, std::string> content_length(const HttpFields& f) {
  std::optional<std::uint64_t> len;
  for (const auto& [name, value] : f.all()) {
    if (!iequals(name, "content-length")) {
      continue;
    }
    std::string_view rest = value;
    while (true) {
      const std::size_t comma = rest.find(',');
      const std::string_view elem = trim_ows(rest.substr(0, comma));
      if (elem.empty() || !std::ranges::all_of(elem, is_digit)) {
        return std::unexpected("invalid Content-Length '" + value + "'");
      }
      std::uint64_t v = 0;
      for (const char c : elem) {
        if (__builtin_mul_overflow(v, std::uint64_t{10}, &v) ||
            __builtin_add_overflow(v, static_cast<std::uint64_t>(c - '0'), &v) ||
            v > (std::uint64_t{1} << 62)) {
          return std::unexpected("Content-Length too large '" + value + "'");
        }
      }
      if (len && *len != v) {
        return std::unexpected("conflicting Content-Length values");
      }
      len = v;
      if (comma == std::string_view::npos) {
        break;
      }
      rest.remove_prefix(comma + 1);
    }
  }
  return len;
}

std::expected<BodyFraming, HttpError> request_body_framing(const HttpRequestHead& r) {
  if (r.fields.count("transfer-encoding") > 0) {
    // RFC 9112 §6.1: Transfer-Encoding in HTTP/1.0, or with Content-Length,
    // makes the framing faulty; the server responds and closes.
    if (r.minor == 0) {
      return std::unexpected(err(400, "Transfer-Encoding in an HTTP/1.0 request"));
    }
    if (r.fields.count("content-length") > 0) {
      return std::unexpected(err(400, "both Transfer-Encoding and Content-Length"));
    }
    const auto codings = r.fields.list("transfer-encoding");
    if (codings.empty() || !iequals(codings.back(), "chunked")) {
      // RFC 9112 §6.3 item 4.
      return std::unexpected(err(400, "chunked is not the final transfer coding"));
    }
    if (codings.size() > 1) {
      return std::unexpected(err(501, "transfer coding not implemented"));
    }
    return BodyFraming{BodyFraming::Kind::chunked, 0};
  }
  const auto cl = content_length(r.fields);
  if (!cl) {
    return std::unexpected(err(400, cl.error()));
  }
  if (*cl && **cl > 0) {
    return BodyFraming{BodyFraming::Kind::length, **cl};
  }
  return BodyFraming{};
}

std::expected<BodyFraming, std::string> response_body_framing(const HttpResponseHead& r,
                                                              bool request_was_head) {
  if (request_was_head || r.status / 100 == 1 || r.status == 204 || r.status == 304) {
    return BodyFraming{};
  }
  if (r.fields.count("transfer-encoding") > 0) {
    const auto codings = r.fields.list("transfer-encoding");
    if (r.minor >= 1 && !codings.empty() && iequals(codings.back(), "chunked")) {
      return BodyFraming{BodyFraming::Kind::chunked, 0};
    }
    return BodyFraming{BodyFraming::Kind::until_close, 0};
  }
  const auto cl = content_length(r.fields);
  if (!cl) {
    return std::unexpected(cl.error());
  }
  if (*cl) {
    return BodyFraming{BodyFraming::Kind::length, **cl};
  }
  return BodyFraming{BodyFraming::Kind::until_close, 0};
}

bool request_keep_alive(const HttpRequestHead& r) {
  if (r.fields.has_token("connection", "close")) {
    return false;
  }
  return r.minor >= 1 || r.fields.has_token("connection", "keep-alive");
}

bool response_keep_alive(const HttpResponseHead& r) {
  if (r.fields.has_token("connection", "close")) {
    return false;
  }
  return r.minor >= 1 || r.fields.has_token("connection", "keep-alive");
}

// --- Paths and URLs.

std::expected<std::string, HttpError> request_path(std::string_view target) {
  std::string_view path;
  if (target.starts_with('/')) {
    path = target;
  } else if (istarts_with(target, "http://")) {
    // RFC 9112 §3.2.2: absolute-form.
    const std::string_view rest = target.substr(7);
    const std::size_t end = rest.find_first_of("/?");
    if (end == 0) {
      return std::unexpected(err(400, "absolute-form target without a host"));
    }
    path = end == std::string_view::npos || rest[end] == '?' ? std::string_view("/") : rest.substr(end);
  } else {
    return std::unexpected(err(400, "unsupported request-target form"));
  }
  path = path.substr(0, path.find('?'));

  std::string decoded;
  decoded.reserve(path.size());
  const auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < path.size(); ++i) {
    if (path[i] != '%') {
      decoded += path[i];
      continue;
    }
    if (i + 2 >= path.size()) {
      return std::unexpected(err(400, "bad percent-encoding"));
    }
    const int hi = hex(path[i + 1]);
    const int lo = hex(path[i + 2]);
    if (hi < 0 || lo < 0) {
      return std::unexpected(err(400, "bad percent-encoding"));
    }
    const char c = static_cast<char>(hi * 16 + lo);
    if (c == '\0') {
      return std::unexpected(err(400, "NUL in the path"));
    }
    decoded += c;
    i += 2;
  }

  // RFC 3986 §5.2.4, but a ".." above the root is an error, not dropped.
  std::vector<std::string_view> segs;
  bool dir = decoded.ends_with('/');
  std::string_view rest = std::string_view(decoded).substr(1);
  while (true) {
    const std::size_t slash = rest.find('/');
    const std::string_view seg = rest.substr(0, slash);
    const bool last = slash == std::string_view::npos;
    if (seg == "..") {
      if (segs.empty()) {
        return std::unexpected(err(400, "path escapes the document root"));
      }
      segs.pop_back();
      dir = dir || last;
    } else if (seg == ".") {
      dir = dir || last;
    } else if (!seg.empty()) {
      segs.push_back(seg);
    }
    if (last) {
      break;
    }
    rest.remove_prefix(slash + 1);
  }
  std::string out = "/";
  for (std::size_t i = 0; i < segs.size(); ++i) {
    out += segs[i];
    if (i + 1 < segs.size() || dir) {
      out += '/';
    }
  }
  return out;
}

std::expected<HttpUrl, std::string> parse_http_url(std::string_view url) {
  if (!istarts_with(url, "http://")) {
    return std::unexpected("only http:// URLs are supported: '" + std::string(url) + "'");
  }
  std::string_view rest = url.substr(7);
  rest = rest.substr(0, rest.find('#'));
  const std::size_t auth_end = rest.find_first_of("/?");
  const std::string_view authority = rest.substr(0, auth_end);
  HttpUrl u;
  if (auth_end != std::string_view::npos) {
    const std::string_view t = rest.substr(auth_end);
    u.target = t.starts_with('?') ? "/" + std::string(t) : std::string(t);
  }
  if (!std::ranges::all_of(u.target, [](char c) { return c > 0x20 && c < 0x7f; })) {
    return std::unexpected("URL path has a space or a non-ASCII byte (percent-encode it)");
  }
  if (authority.find('@') != std::string_view::npos) {
    return std::unexpected("URLs with userinfo are not supported");
  }
  if (authority.starts_with('[')) {
    return std::unexpected("IPv6 literals are not supported");
  }
  std::string_view host = authority;
  if (const std::size_t colon = authority.rfind(':'); colon != std::string_view::npos) {
    host = authority.substr(0, colon);
    const std::string_view port = authority.substr(colon + 1);
    if (!port.empty()) {
      if (port.size() > 5 || !std::ranges::all_of(port, is_digit)) {
        return std::unexpected("bad port in URL");
      }
      int p = 0;
      for (const char c : port) {
        p = p * 10 + (c - '0');
      }
      if (p <= 0 || p > 65535) {
        return std::unexpected("bad port in URL");
      }
      u.port = static_cast<std::uint16_t>(p);
    }
  }
  if (host.empty()) {
    return std::unexpected("URL without a host");
  }
  for (const char c : host) {
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || is_digit(c) || c == '-' || c == '.' ||
          c == '_')) {
      return std::unexpected("unsupported character in host '" + std::string(host) + "'");
    }
    u.host += lower(c);
  }
  return u;
}

// --- Misc.

std::string http_date(std::int64_t unix_seconds) {
  using namespace std::chrono;
  static constexpr std::array<const char*, 7> wd = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static constexpr std::array<const char*, 12> mon = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  const sys_seconds tp{seconds{unix_seconds}};
  const sys_days day = floor<days>(tp);
  const year_month_day ymd{day};
  const hh_mm_ss<seconds> hms{tp - day};
  char buf[40];
  std::snprintf(buf, sizeof buf, "%s, %02u %s %04d %02d:%02d:%02d GMT",
                wd[weekday{day}.c_encoding()], static_cast<unsigned>(ymd.day()),
                mon[static_cast<unsigned>(ymd.month()) - 1], static_cast<int>(ymd.year()),
                static_cast<int>(hms.hours().count()), static_cast<int>(hms.minutes().count()),
                static_cast<int>(hms.seconds().count()));
  return buf;
}

std::string_view status_reason(int status) {
  switch (status) {
    case 100: return "Continue";
    case 200: return "OK";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    default: return "Unknown";
  }
}

std::string_view mime_type(std::string_view path) {
  static constexpr std::pair<std::string_view, std::string_view> table[] = {
      {"html", "text/html; charset=utf-8"}, {"htm", "text/html; charset=utf-8"},
      {"txt", "text/plain; charset=utf-8"}, {"css", "text/css"},
      {"js", "text/javascript"},             {"json", "application/json"},
      {"xml", "application/xml"},            {"png", "image/png"},
      {"jpg", "image/jpeg"},                 {"jpeg", "image/jpeg"},
      {"gif", "image/gif"},                  {"svg", "image/svg+xml"},
      {"ico", "image/x-icon"},               {"pdf", "application/pdf"},
      {"gz", "application/gzip"},            {"tar", "application/x-tar"},
      {"zip", "application/zip"},            {"wasm", "application/wasm"},
  };
  const std::size_t slash = path.rfind('/');
  const std::string_view name = slash == std::string_view::npos ? path : path.substr(slash + 1);
  const std::size_t dot = name.rfind('.');
  if (dot == std::string_view::npos || dot == 0) {
    return "application/octet-stream";
  }
  const std::string_view ext = name.substr(dot + 1);
  for (const auto& [e, type] : table) {
    if (iequals(e, ext)) {
      return type;
    }
  }
  return "application/octet-stream";
}

}  // namespace utcp::app
