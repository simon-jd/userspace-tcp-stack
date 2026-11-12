#include "common/cli.hpp"

#include <algorithm>
#include <limits>

#include "utcp/check.hpp"

namespace utcp::app {

namespace {

std::string single_quoted(std::string_view s) { return "'" + std::string(s) + "'"; }

// Digits only, at least one; nullopt on overflow or another character.
std::optional<std::uint64_t> digits(std::string_view s) {
  if (s.empty()) {
    return std::nullopt;
  }
  std::uint64_t v = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    if (__builtin_mul_overflow(v, std::uint64_t{10}, &v) ||
        __builtin_add_overflow(v, static_cast<std::uint64_t>(c - '0'), &v)) {
      return std::nullopt;
    }
  }
  return v;
}

}  // namespace

// --- CliArgs.

bool CliArgs::given(std::string_view name) const { return values_.contains(name); }

std::optional<std::string> CliArgs::get(std::string_view name) const {
  if (const auto it = values_.find(name); it != values_.end()) {
    return it->second;
  }
  if (const auto it = defaults_.find(name); it != defaults_.end()) {
    return it->second;
  }
  return std::nullopt;
}

// --- CliParser.

CliParser::CliParser(std::string program, std::string summary)
    : program_(std::move(program)), summary_(std::move(summary)) {}

const CliParser::Opt* CliParser::find(std::string_view name) const {
  const auto it = std::ranges::find(opts_, name, &Opt::name);
  return it == opts_.end() ? nullptr : &*it;
}

CliParser& CliParser::flag(std::string name, std::string help) {
  UTCP_CHECK(find(name) == nullptr && name != "help");
  opts_.push_back({.name = std::move(name), .help = std::move(help), .is_flag = true});
  return *this;
}

CliParser& CliParser::option(std::string name, std::string metavar, std::string help,
                             std::optional<std::string> default_value) {
  UTCP_CHECK(find(name) == nullptr && name != "help");
  opts_.push_back({.name = std::move(name),
                   .metavar = std::move(metavar),
                   .help = std::move(help),
                   .default_value = std::move(default_value)});
  return *this;
}

CliParser& CliParser::positional(std::string name, std::string help, bool required) {
  UTCP_CHECK(!required || pos_.empty() || pos_.back().required);
  pos_.push_back({std::move(name), std::move(help), required});
  return *this;
}

std::expected<CliArgs, std::string> CliParser::parse(std::span<const std::string_view> args) const {
  CliArgs out;
  for (const Opt& o : opts_) {
    if (o.default_value) {
      out.defaults_.emplace(o.name, *o.default_value);
    }
  }
  bool options_done = false;
  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string_view a = args[i];
    if (options_done || !a.starts_with("-") || a == "-") {
      out.positionals_.emplace_back(a);
      continue;
    }
    if (a == "--") {
      options_done = true;
      continue;
    }
    if (a == "-h" || a == "--help") {
      out.help_ = true;
      continue;
    }
    if (!a.starts_with("--")) {
      return std::unexpected("unknown option " + std::string(a));
    }
    std::string_view name = a.substr(2);
    std::optional<std::string_view> inline_value;
    if (const auto eq = name.find('='); eq != std::string_view::npos) {
      inline_value = name.substr(eq + 1);
      name = name.substr(0, eq);
    }
    const Opt* o = find(name);
    if (o == nullptr) {
      return std::unexpected("unknown option --" + std::string(name));
    }
    if (o->is_flag) {
      if (inline_value) {
        return std::unexpected("option --" + o->name + " takes no value");
      }
      out.values_[o->name] = "";
      continue;
    }
    if (inline_value) {
      out.values_[o->name] = std::string(*inline_value);
    } else if (i + 1 < args.size()) {
      out.values_[o->name] = std::string(args[++i]);
    } else {
      return std::unexpected("option --" + o->name + " needs a value (" + o->metavar + ")");
    }
  }
  if (out.positionals_.size() > pos_.size()) {
    return std::unexpected("unexpected argument " + single_quoted(out.positionals_[pos_.size()]));
  }
  if (!out.help_) {
    for (std::size_t i = out.positionals_.size(); i < pos_.size(); ++i) {
      if (pos_[i].required) {
        return std::unexpected("missing argument " + pos_[i].name);
      }
    }
  }
  return out;
}

std::expected<CliArgs, std::string> CliParser::parse(int argc, const char* const* argv) const {
  std::vector<std::string_view> args;
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }
  return parse(std::span<const std::string_view>(args));
}

std::string CliParser::usage() const {
  std::string s = "usage: " + program_ + " [options]";
  for (const Pos& p : pos_) {
    s += p.required ? " " + p.name : " [" + p.name + "]";
  }
  s += "\n" + summary_ + "\n";
  std::vector<std::pair<std::string, std::string>> rows;
  for (const Pos& p : pos_) {
    rows.emplace_back(p.name, p.help);
  }
  for (const Opt& o : opts_) {
    std::string left = "--" + o.name + (o.is_flag ? "" : " " + o.metavar);
    std::string right = o.help;
    if (o.default_value) {
      right += " (default " + *o.default_value + ")";
    }
    rows.emplace_back(std::move(left), std::move(right));
  }
  rows.emplace_back("-h, --help", "print this help");
  std::size_t width = 0;
  for (const auto& r : rows) {
    width = std::max(width, r.first.size());
  }
  for (const auto& r : rows) {
    s += "  " + r.first + std::string(width - r.first.size() + 2, ' ') + r.second + "\n";
  }
  return s;
}

// --- Value parsers.

std::expected<std::uint64_t, std::string> parse_u64(std::string_view s) {
  if (const auto v = digits(s)) {
    return *v;
  }
  return std::unexpected("not a number or too large: " + single_quoted(s));
}

std::expected<std::uint64_t, std::string> parse_size(std::string_view s) {
  static constexpr std::pair<std::string_view, std::uint64_t> suffixes[] = {
      {"Ki", std::uint64_t{1} << 10}, {"Mi", std::uint64_t{1} << 20}, {"Gi", std::uint64_t{1} << 30},
      {"K", 1'000},                   {"M", 1'000'000},              {"G", 1'000'000'000}};
  std::uint64_t mult = 1;
  std::string_view num = s;
  for (const auto& [suffix, m] : suffixes) {
    if (s.ends_with(suffix)) {
      mult = m;
      num = s.substr(0, s.size() - suffix.size());
      break;
    }
  }
  const auto v = digits(num);
  std::uint64_t r = 0;
  if (!v || __builtin_mul_overflow(*v, mult, &r)) {
    return std::unexpected("not a size or too large: " + single_quoted(s) + " (e.g. 1500, 64Ki, 10M)");
  }
  return r;
}

std::expected<Duration, std::string> parse_duration(std::string_view s,
                                                    std::optional<Duration> bare_unit) {
  static constexpr std::pair<std::string_view, std::int64_t> units[] = {
      {"ns", 1}, {"us", 1'000}, {"ms", 1'000'000}, {"s", 1'000'000'000}};
  const auto bad = [&s] {
    return std::unexpected("not a duration: " + single_quoted(s) + " (e.g. 200ms, 1.5s)");
  };
  std::int64_t unit_ns = 0;
  std::string_view num = s;
  for (const auto& [name, ns] : units) {
    if (s.ends_with(name)) {
      unit_ns = ns;
      num = s.substr(0, s.size() - name.size());
      break;
    }
  }
  if (unit_ns == 0) {
    if (!bare_unit || bare_unit->count() <= 0) {
      return bad();
    }
    unit_ns = bare_unit->count();
  }
  std::string_view int_part = num;
  std::string_view frac_part;
  if (const auto dot = num.find('.'); dot != std::string_view::npos) {
    int_part = num.substr(0, dot);
    frac_part = num.substr(dot + 1);
    if (frac_part.empty()) {
      return bad();
    }
  }
  const auto whole = digits(int_part);
  const auto frac = frac_part.empty() ? std::optional<std::uint64_t>(0) : digits(frac_part);
  if (!whole || !frac || frac_part.size() > 9) {
    return bad();
  }
  // value = (whole + frac / 10^k) * unit_ns, which must be an integer.
  std::int64_t total = 0;
  if (*whole > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ||
      __builtin_mul_overflow(static_cast<std::int64_t>(*whole), unit_ns, &total)) {
    return bad();
  }
  if (!frac_part.empty()) {
    std::int64_t pow10 = 1;
    for (std::size_t i = 0; i < frac_part.size(); ++i) {
      pow10 *= 10;
    }
    // frac < 10^9 and unit_ns <= 10^9, so the product fits.
    const std::int64_t num_ns = static_cast<std::int64_t>(*frac) * unit_ns;
    if (num_ns % pow10 != 0) {
      return std::unexpected("duration " + single_quoted(s) + " is not a whole number of nanoseconds");
    }
    if (__builtin_add_overflow(total, num_ns / pow10, &total)) {
      return bad();
    }
  }
  return Duration{total};
}

std::expected<Ipv4Addr, std::string> parse_ipv4(std::string_view s) {
  std::uint32_t v = 0;
  std::string_view rest = s;
  for (int i = 0; i < 4; ++i) {
    const auto dot = rest.find('.');
    if ((i < 3) == (dot == std::string_view::npos)) {
      return std::unexpected("not an IPv4 address: " + single_quoted(s));
    }
    const std::string_view part = i < 3 ? rest.substr(0, dot) : rest;
    const auto o = digits(part);
    if (!o || *o > 255 || part.size() > 3 || (part.size() > 1 && part[0] == '0')) {
      return std::unexpected("not an IPv4 address: " + single_quoted(s));
    }
    v = (v << 8) | static_cast<std::uint32_t>(*o);
    if (i < 3) {
      rest = rest.substr(dot + 1);
    }
  }
  return Ipv4Addr{v};
}

std::expected<std::uint16_t, std::string> parse_port(std::string_view s) {
  const auto v = digits(s);
  if (!v || *v > 0xffff) {
    return std::unexpected("not a port (0-65535): " + single_quoted(s));
  }
  return static_cast<std::uint16_t>(*v);
}

std::expected<Endpoint, std::string> parse_endpoint(std::string_view s) {
  const auto colon = s.rfind(':');
  if (colon == std::string_view::npos) {
    return std::unexpected("expected IP:PORT, got " + single_quoted(s));
  }
  const auto addr = parse_ipv4(s.substr(0, colon));
  if (!addr) {
    return std::unexpected(addr.error());
  }
  const auto port = parse_port(s.substr(colon + 1));
  if (!port) {
    return std::unexpected(port.error());
  }
  return Endpoint{*addr, *port};
}

std::expected<std::pair<std::string_view, std::string_view>, std::string> parse_pair(
    std::string_view s, char sep) {
  const auto at = s.find(sep);
  if (at == std::string_view::npos || at == 0 || at + 1 == s.size()) {
    return std::unexpected("expected A" + std::string(1, sep) + "B, got " + single_quoted(s));
  }
  return std::pair{s.substr(0, at), s.substr(at + 1)};
}

}  // namespace utcp::app
