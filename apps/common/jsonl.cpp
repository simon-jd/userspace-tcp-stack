#include "common/jsonl.hpp"

#include <array>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstring>
#include <type_traits>
#include <utility>

namespace utcp::app {

std::string json_quote(std::string_view s) {
  static constexpr char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(s.size() + 2);
  out += '"';
  for (const char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          out += "\\u00";
          out += hex[static_cast<unsigned char>(c) >> 4];
          out += hex[static_cast<unsigned char>(c) & 0xf];
        } else {
          out += c;
        }
    }
  }
  out += '"';
  return out;
}

void JsonLine::key_(std::string_view key) {
  buf_ += buf_.empty() ? '{' : ',';
  buf_ += json_quote(key);
  buf_ += ':';
}

JsonLine& JsonLine::add(std::string_view key, std::string_view value) {
  key_(key);
  buf_ += json_quote(value);
  return *this;
}

JsonLine& JsonLine::add(std::string_view key, bool value) {
  key_(key);
  buf_ += value ? "true" : "false";
  return *this;
}

JsonLine& JsonLine::add(std::string_view key, double value) {
  if (!std::isfinite(value)) {
    return add_null(key);
  }
  key_(key);
  std::array<char, 32> tmp{};
  const auto r = std::to_chars(tmp.data(), tmp.data() + tmp.size(), value);
  buf_.append(tmp.data(), r.ptr);
  return *this;
}

JsonLine& JsonLine::add_null(std::string_view key) {
  key_(key);
  buf_ += "null";
  return *this;
}

namespace {

// Microseconds, rounded toward zero.
std::int64_t to_us(Duration d) { return d.count() / 1000; }

template <class T>
void add_value(JsonLine& line, std::string_view key, const T& v) {
  if constexpr (std::is_same_v<T, Duration>) {
    line.add(std::string(key) + "_us", to_us(v));
  } else if constexpr (std::is_same_v<T, Time>) {
    line.add(key, v.ns);
  } else if constexpr (std::is_enum_v<T>) {
    line.add(key, to_string(v));
  } else if constexpr (std::is_same_v<T, std::array<char, 16>>) {
    line.add(key, std::string_view(v.data(), strnlen(v.data(), v.size())));
  } else {
    line.add(key, v);
  }
}

}  // namespace

void add_fields(JsonLine& line, const TcpInfo& info) {
  for_each_field(info, [&line](std::string_view name, const auto& v) { add_value(line, name, v); });
}

void add_fields(JsonLine& line, const TraceEvent& e) {
  for_each_field(e, [&line](std::string_view name, const auto& v) {
    using T = std::remove_cvref_t<decltype(v)>;
    if (name == "conn_id") {
      add_value(line, "conn", v);
    } else if (name == "kind") {
      add_value(line, "ev", v);
    } else if constexpr (std::is_same_v<T, std::int64_t>) {
      if (name.ends_with("_ns")) {
        line.add(std::string(name.substr(0, name.size() - 3)) + "_us", v / 1000);
      } else {
        line.add(name, v);
      }
    } else {
      add_value(line, name, v);
    }
  });
}

std::expected<JsonlWriter, std::string> JsonlWriter::open(const std::string& path) {
  if (path == "-") {
    return JsonlWriter(stdout, false);
  }
  std::FILE* f = std::fopen(path.c_str(), "w");
  if (f == nullptr) {
    return std::unexpected(path + ": " + std::strerror(errno));
  }
  return JsonlWriter(f, true);
}

JsonlWriter::JsonlWriter(JsonlWriter&& other) noexcept
    : f_(std::exchange(other.f_, nullptr)),
      owned_(std::exchange(other.owned_, false)),
      lines_(other.lines_) {}

JsonlWriter& JsonlWriter::operator=(JsonlWriter&& other) noexcept {
  if (this != &other) {
    close_();
    f_ = std::exchange(other.f_, nullptr);
    owned_ = std::exchange(other.owned_, false);
    lines_ = other.lines_;
  }
  return *this;
}

JsonlWriter::~JsonlWriter() { close_(); }

void JsonlWriter::close_() {
  if (f_ != nullptr) {
    if (owned_) {
      std::fclose(f_);
    } else {
      std::fflush(f_);
    }
    f_ = nullptr;
  }
}

bool JsonlWriter::write(const JsonLine& line) {
  if (f_ == nullptr) {
    return false;
  }
  const std::string s = line.str();
  if (std::fwrite(s.data(), 1, s.size(), f_) != s.size() || std::fputc('\n', f_) == EOF) {
    return false;
  }
  ++lines_;
  return true;
}

bool JsonlWriter::flush() { return f_ != nullptr && std::fflush(f_) == 0; }

}  // namespace utcp::app
