// Command-line parsing for the apps (DESIGN §9).
//
// Options are long only: `--name VALUE`, `--name=VALUE`, flags `--name`.
// `--help` and `-h` are always accepted. `--` ends the options; later words
// are positionals. A repeated option keeps its last value for get(); all()
// returns every value in order (`--set A=1 --set B=2`). Errors are
// messages for the user, e.g. "unknown option --foo".
//
// The value parsers below take the whole string (no leading or trailing
// spaces, no sign) and report overflow.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp::app {

class CliArgs {
public:
  // --help or -h was given (required positionals are then not checked).
  [[nodiscard]] bool help() const { return help_; }
  // The flag or option was given on the command line.
  [[nodiscard]] bool given(std::string_view name) const;
  // Flag value: given or not.
  [[nodiscard]] bool flag(std::string_view name) const { return given(name); }
  // Option value (the last one given), else its default, else nullopt.
  [[nodiscard]] std::optional<std::string> get(std::string_view name) const;
  // Every value given for the option, in command-line order (no default).
  [[nodiscard]] std::vector<std::string> all(std::string_view name) const;
  // Positionals in order.
  [[nodiscard]] const std::vector<std::string>& positionals() const { return positionals_; }

private:
  friend class CliParser;
  bool help_ = false;
  std::map<std::string, std::string, std::less<>> values_;    // given options and flags ("")
  std::map<std::string, std::string, std::less<>> defaults_;  // option defaults
  std::map<std::string, std::vector<std::string>, std::less<>> every_;  // every value given
  std::vector<std::string> positionals_;
};

class CliParser {
public:
  CliParser(std::string program, std::string summary);

  // Declarations; names without the leading "--". Declaring a name twice
  // aborts (a programming error).
  CliParser& flag(std::string name, std::string help);
  CliParser& option(std::string name, std::string metavar, std::string help,
                    std::optional<std::string> default_value = std::nullopt);
  // Positionals are matched in declaration order; optional ones must follow
  // the required ones.
  CliParser& positional(std::string name, std::string help, bool required = true);

  // `args` excludes the program name.
  [[nodiscard]] std::expected<CliArgs, std::string> parse(
      std::span<const std::string_view> args) const;
  [[nodiscard]] std::expected<CliArgs, std::string> parse(int argc, const char* const* argv) const;

  // "usage: prog [options] POS...", the summary, and one line per option.
  [[nodiscard]] std::string usage() const;

private:
  struct Opt {
    std::string name{}, metavar{}, help{};
    std::optional<std::string> default_value{};
    bool is_flag = false;
  };
  struct Pos {
    std::string name{}, help{};
    bool required = true;
  };
  [[nodiscard]] const Opt* find(std::string_view name) const;

  std::string program_, summary_;
  std::vector<Opt> opts_;
  std::vector<Pos> pos_;
};

// Decimal integer.
[[nodiscard]] std::expected<std::uint64_t, std::string> parse_u64(std::string_view s);
// Decimal integer with an optional suffix: K, M, G (powers of 1000) or Ki, Mi,
// Gi (powers of 1024). "64Ki" = 65536.
[[nodiscard]] std::expected<std::uint64_t, std::string> parse_size(std::string_view s);
// A non-negative decimal number with a unit ns, us, ms or s, e.g. "200ms",
// "1.5s". Without a unit, `bare_unit` is used if given ("--sample-ms 10"),
// else it is an error. At most 9 decimals; the value must be a whole number
// of nanoseconds.
[[nodiscard]] std::expected<Duration, std::string> parse_duration(
    std::string_view s, std::optional<Duration> bare_unit = std::nullopt);
// Dotted quad, each part 0-255 without leading zeros (as glibc inet_pton).
[[nodiscard]] std::expected<Ipv4Addr, std::string> parse_ipv4(std::string_view s);
[[nodiscard]] std::expected<std::uint16_t, std::string> parse_port(std::string_view s);
// "IP:PORT".
[[nodiscard]] std::expected<Endpoint, std::string> parse_endpoint(std::string_view s);
// Splits at the first `sep`: "200:1048576" -> {"200", "1048576"}. Both parts
// must be non-empty.
[[nodiscard]] std::expected<std::pair<std::string_view, std::string_view>, std::string>
parse_pair(std::string_view s, char sep = ':');

}  // namespace utcp::app
