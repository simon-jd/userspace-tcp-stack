#include "common/chunked.hpp"

#include <algorithm>
#include <utility>

namespace utcp::app {

namespace {

bool is_ws(char c) { return c == ' ' || c == '\t'; }

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool is_tchar(char c) { return is_token(std::string_view(&c, 1)); }

void skip_ws(std::string_view& s) {
  while (!s.empty() && is_ws(s.front())) {
    s.remove_prefix(1);
  }
}

std::string_view take_token(std::string_view& s) {
  std::size_t n = 0;
  while (n < s.size() && is_tchar(s[n])) {
    ++n;
  }
  const std::string_view t = s.substr(0, n);
  s.remove_prefix(n);
  return t;
}

// RFC 9110 §5.6.4: quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE.
bool take_quoted(std::string_view& s) {
  if (s.empty() || s.front() != '"') {
    return false;
  }
  for (std::size_t i = 1; i < s.size(); ++i) {
    const auto c = static_cast<unsigned char>(s[i]);
    if (c == '"') {
      s.remove_prefix(i + 1);
      return true;
    }
    if (c == '\\') {
      if (++i == s.size()) {
        return false;
      }
      const auto q = static_cast<unsigned char>(s[i]);
      if (q != '\t' && (q < 0x20 || q == 0x7f)) {
        return false;
      }
      continue;
    }
    if (c != '\t' && (c < 0x20 || c == 0x7f)) {
      return false;
    }
  }
  return false;
}

// RFC 9112 §7.1.1: chunk-ext = *( BWS ";" BWS chunk-ext-name
//                                  [ BWS "=" BWS chunk-ext-val ] ).
bool valid_extensions(std::string_view s) {
  while (true) {
    skip_ws(s);
    if (s.empty()) {
      return true;
    }
    if (s.front() != ';') {
      return false;
    }
    s.remove_prefix(1);
    skip_ws(s);
    if (take_token(s).empty()) {
      return false;
    }
    skip_ws(s);
    if (!s.empty() && s.front() == '=') {
      s.remove_prefix(1);
      skip_ws(s);
      if (!s.empty() && s.front() == '"') {
        if (!take_quoted(s)) {
          return false;
        }
      } else if (take_token(s).empty()) {
        return false;
      }
    }
  }
}

bool valid_field_value(std::string_view v) {
  return std::ranges::all_of(v, [](char ch) {
    const auto c = static_cast<unsigned char>(ch);
    return c == '\t' || (c >= 0x20 && c != 0x7f);
  });
}

}  // namespace

std::string ChunkedDecoder::fail(std::string msg) {
  state_ = State::failed;
  error_ = msg;
  return msg;
}

std::expected<void, std::string> ChunkedDecoder::end_size_line() {
  std::string_view s = line_;
  std::size_t digits = 0;
  std::uint64_t size = 0;
  while (digits < s.size() && hex_value(s[digits]) >= 0) {
    // At most 2^60 - 1: no overflow, and far beyond any real chunk.
    if (size >= (std::uint64_t{1} << 56)) {
      return std::unexpected(fail("chunk size too large"));
    }
    size = size * 16 + static_cast<std::uint64_t>(hex_value(s[digits]));
    ++digits;
  }
  if (digits == 0) {
    return std::unexpected(fail("chunk size missing"));
  }
  if (!valid_extensions(s.substr(digits))) {
    return std::unexpected(fail("malformed chunk extension"));
  }
  line_.clear();
  if (size == 0) {
    state_ = State::trailer_line;  // last-chunk
  } else {
    remaining_ = size;
    ++chunks_;
    state_ = State::data;
  }
  return {};
}

std::expected<void, std::string> ChunkedDecoder::end_trailer_line() {
  if (line_.empty()) {
    state_ = State::done;
    return {};
  }
  const std::string_view line = line_;
  // RFC 9112 §5.2 (obs-fold) is not accepted in trailers.
  if (is_ws(line.front())) {
    return std::unexpected(fail("folded trailer line"));
  }
  const std::size_t colon = line.find(':');
  if (colon == std::string_view::npos || !is_token(line.substr(0, colon))) {
    return std::unexpected(fail("malformed trailer field"));
  }
  std::string_view value = line.substr(colon + 1);
  skip_ws(value);
  while (!value.empty() && is_ws(value.back())) {
    value.remove_suffix(1);
  }
  if (!valid_field_value(value)) {
    return std::unexpected(fail("invalid character in a trailer field"));
  }
  if (trailers_.size() >= limits_.max_trailer_fields) {
    return std::unexpected(fail("too many trailer fields"));
  }
  trailers_.add(std::string(line.substr(0, colon)), std::string(value));
  line_.clear();
  return {};
}

std::expected<std::size_t, std::string> ChunkedDecoder::feed(std::string_view in, std::string& out) {
  if (state_ == State::failed) {
    return std::unexpected(error_);
  }
  std::size_t i = 0;
  while (i < in.size() && state_ != State::done) {
    if (state_ == State::data) {
      const std::size_t n =
          static_cast<std::size_t>(std::min<std::uint64_t>(remaining_, in.size() - i));
      out.append(in.substr(i, n));
      i += n;
      remaining_ -= n;
      data_bytes_ += n;
      if (remaining_ == 0) {
        state_ = State::data_end;
      }
      continue;
    }
    // A line: size_line, data_end (must be empty) or trailer_line.
    const char c = in[i++];
    if (state_ == State::trailer_line && ++trailer_bytes_ > limits_.max_trailers) {
      return std::unexpected(fail("trailer section too large"));
    }
    if (line_cr_) {
      if (c != '\n') {
        return std::unexpected(fail("bare CR in chunked framing"));
      }
      line_cr_ = false;
    } else if (c == '\r') {
      line_cr_ = true;
      continue;
    } else if (c != '\n') {
      if (state_ == State::data_end) {
        return std::unexpected(fail("chunk data longer than its size"));
      }
      if (line_.size() >= (state_ == State::size_line ? limits_.max_line : limits_.max_trailers)) {
        return std::unexpected(fail("chunked framing line too long"));
      }
      line_ += c;
      continue;
    }
    // End of line.
    std::expected<void, std::string> r{};
    switch (state_) {
      case State::size_line: r = end_size_line(); break;
      case State::data_end: state_ = State::size_line; break;
      case State::trailer_line: r = end_trailer_line(); break;
      default: break;
    }
    if (!r) {
      return std::unexpected(r.error());
    }
  }
  return i;
}

}  // namespace utcp::app
