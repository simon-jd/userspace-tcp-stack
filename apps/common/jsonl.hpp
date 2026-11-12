// JSON Lines output (DESIGN §9, §10.2): one flat JSON object per line
// (RFC 8259), keys in the order they were added. Output only; nothing here
// parses JSON.
//
// Conventions shared by the simulator and the apps: times and durations are
// integers. TraceEvent lines: "t" is the event time in nanoseconds, "conn" the
// connection id, "ev" the TraceKind name, the *_ns fields become *_us
// (microseconds, rounded toward zero), enums are written as names. TcpInfo
// lines: every field of §10.1 under its own name, Durations as <name>_us.
#pragma once

#include <concepts>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <string>
#include <string_view>

#include "utcp/stats.hpp"
#include "utcp/trace.hpp"

namespace utcp::app {

// `s` as a JSON string, quotes included: '"', '\\' and control characters are
// escaped (RFC 8259 §7); other bytes are copied (UTF-8 is assumed).
[[nodiscard]] std::string json_quote(std::string_view s);

class JsonLine {
public:
  JsonLine& add(std::string_view key, std::string_view value);
  JsonLine& add(std::string_view key, const char* value) { return add(key, std::string_view{value}); }
  JsonLine& add(std::string_view key, const std::string& value) {
    return add(key, std::string_view{value});
  }
  JsonLine& add(std::string_view key, bool value);
  template <std::integral T>
    requires(!std::same_as<T, bool> && !std::same_as<T, char>)
  JsonLine& add(std::string_view key, T value) {
    key_(key);
    buf_ += std::to_string(value);
    return *this;
  }
  // Shortest representation that reads back as the same value; NaN and the
  // infinities are written as null (JSON has no such numbers).
  JsonLine& add(std::string_view key, double value);
  JsonLine& add_null(std::string_view key);

  // The object, without a trailing newline.
  [[nodiscard]] std::string str() const { return buf_.empty() ? "{}" : buf_ + '}'; }
  [[nodiscard]] bool empty() const { return buf_.empty(); }
  void clear() { buf_.clear(); }

private:
  void key_(std::string_view key);
  std::string buf_;  // "{" and the members so far, without the closing brace
};

// Appends every TcpInfo field (in declaration order) to `line`.
void add_fields(JsonLine& line, const TcpInfo& info);
// Appends every TraceEvent field (in declaration order) to `line`, with the
// keys described above.
void add_fields(JsonLine& line, const TraceEvent& e);

// Writes lines to a file or, for the path "-", to stdout.
class JsonlWriter {
public:
  static std::expected<JsonlWriter, std::string> open(const std::string& path);
  JsonlWriter(JsonlWriter&& other) noexcept;
  JsonlWriter& operator=(JsonlWriter&& other) noexcept;
  JsonlWriter(const JsonlWriter&) = delete;
  JsonlWriter& operator=(const JsonlWriter&) = delete;
  ~JsonlWriter();

  // Writes the line and a newline; false after a write error.
  bool write(const JsonLine& line);
  bool flush();
  [[nodiscard]] std::uint64_t lines() const { return lines_; }

private:
  JsonlWriter(std::FILE* f, bool owned) : f_(f), owned_(owned) {}
  void close_();

  std::FILE* f_ = nullptr;
  bool owned_ = false;
  std::uint64_t lines_ = 0;
};

}  // namespace utcp::app
