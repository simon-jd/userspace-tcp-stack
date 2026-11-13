// Chunked transfer coding decoder (RFC 9112 §7.1), streaming: input may be
// split anywhere, down to one byte per call. Used by utcp-http-get for
// response bodies and by utcp-httpd to skip chunked request bodies.
//
//   chunked-body = *chunk last-chunk trailer-section CRLF
//   chunk        = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
//   last-chunk   = 1*("0") [ chunk-ext ] CRLF
//
// Chunk extensions are checked for syntax and ignored (RFC 9112 §7.1.1: a
// recipient MUST ignore unrecognized ones). Trailer fields are collected
// (§7.1.2). Lines may end in CRLF or a bare LF (§2.2).
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include "common/http.hpp"

namespace utcp::app {

struct ChunkedLimits {
  std::size_t max_line = 4096;         // chunk-size line with its extensions, without the line end
  std::size_t max_trailers = 64 * 1024;  // the trailer section
  std::size_t max_trailer_fields = 100;
};

class ChunkedDecoder {
public:
  explicit ChunkedDecoder(const ChunkedLimits& limits = {}) : limits_(limits) {}

  // Consumes bytes of `in` and appends the decoded data to `out`. Returns the
  // number of bytes consumed: all of `in`, or fewer when the body ended
  // inside it (the rest belongs to the next message). After an error the
  // decoder stays failed.
  [[nodiscard]] std::expected<std::size_t, std::string> feed(std::string_view in, std::string& out);

  // The final CRLF after the trailer section was consumed.
  [[nodiscard]] bool done() const { return state_ == State::done; }
  [[nodiscard]] const HttpFields& trailers() const { return trailers_; }
  // Decoded data bytes and chunks so far (the last chunk not counted).
  [[nodiscard]] std::uint64_t data_bytes() const { return data_bytes_; }
  [[nodiscard]] std::uint64_t chunks() const { return chunks_; }

private:
  enum class State : std::uint8_t { size_line, data, data_end, trailer_line, done, failed };

  std::expected<void, std::string> end_size_line();
  std::expected<void, std::string> end_trailer_line();
  std::string fail(std::string msg);

  ChunkedLimits limits_;
  State state_ = State::size_line;
  std::string line_;              // the line being collected
  bool line_cr_ = false;          // the line so far ends in CR
  std::uint64_t remaining_ = 0;   // data bytes left in this chunk
  std::size_t trailer_bytes_ = 0;
  HttpFields trailers_;
  std::uint64_t data_bytes_ = 0;
  std::uint64_t chunks_ = 0;
  std::string error_;
};

}  // namespace utcp::app
