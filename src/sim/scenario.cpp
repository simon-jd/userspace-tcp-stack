#include "utcp/sim/scenario.hpp"

#include <array>
#include <bit>
#include <charconv>
#include <limits>
#include <map>
#include <set>
#include <type_traits>
#include <utility>

#include "utcp/check.hpp"
#include "utcp/sim/datagram.hpp"

namespace utcp::sim {

using namespace std::chrono_literals;

// --- Names.

std::string node_name(std::uint32_t index) {
  if (index < 26) {
    return std::string(1, static_cast<char>('a' + index));
  }
  return "n" + std::to_string(index);
}

std::string_view to_string(NodeKind k) noexcept {
  return k == NodeKind::stack ? "stack" : "synthetic";
}

std::string_view to_string(Plant p) noexcept {
  switch (p) {
    case Plant::none: return "none";
    case Plant::fail: return "fail";
    case Plant::abort: return "abort";
    case Plant::hang: return "hang";
    case Plant::segv: return "segv";
  }
  return "?";
}

std::string_view to_string(CloseMode m) noexcept {
  switch (m) {
    case CloseMode::close: return "close";
    case CloseMode::half_close: return "half_close";
    case CloseMode::abort: return "abort";
    case CloseMode::refused: return "refused";
    case CloseMode::simultaneous: return "simultaneous";
  }
  return "?";
}

std::optional<NodeKind> node_kind_from_string(std::string_view s) noexcept {
  if (s == "stack") {
    return NodeKind::stack;
  }
  if (s == "synthetic") {
    return NodeKind::synthetic;
  }
  return std::nullopt;
}

bool Scenario::has_garbage() const noexcept {
  for (const LinkSpec& l : link) {
    if (l.params.garbage_ppm > 0) {
      return true;
    }
  }
  return false;
}

bool Scenario::has_bitflips() const noexcept {
  for (const LinkSpec& l : link) {
    if (l.params.bitflip_ppm > 0) {
      return true;
    }
  }
  return false;
}

// --- Log-uniform values.

namespace {

// 2^(k/16) in Q16, k = 0..15.
constexpr std::array<std::uint64_t, 16> pow2_sixteenths = {
    65536, 68438, 71468, 74632, 77936, 81386, 84990, 88752,
    92682, 96785, 101070, 105545, 110218, 115098, 120194, 125515};

// lo * 2^(k/16), saturating.
std::uint64_t piece_bound(std::uint64_t lo, std::uint32_t k) noexcept {
  const std::uint32_t octave = k / 16;
  if (octave >= 64 || static_cast<std::uint32_t>(std::countl_zero(lo)) <= octave + 17) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return ((lo << octave) * pow2_sixteenths[k % 16]) >> 16;
}

}  // namespace

std::uint64_t log_uniform(Rng& rng, std::uint64_t lo, std::uint64_t hi) {
  UTCP_CHECK(lo >= 1 && lo <= hi);
  std::uint32_t n = 0;  // whole pieces [b(k), b(k+1)) below hi
  while (n < 64 * 16 && piece_bound(lo, n + 1) <= hi) {
    ++n;
  }
  const std::uint32_t k = rng.below(n + 1);
  const std::uint64_t a = piece_bound(lo, k);
  const std::uint64_t b = k < n ? piece_bound(lo, k + 1) - 1 : hi;
  if (b <= a) {
    return a;
  }
  return a + rng.below64(b - a + 1);
}

// --- Generation (DESIGN §7.2).

namespace {

constexpr std::uint64_t kib = 1024;
constexpr std::uint64_t mib = 1024 * 1024;

Duration ns(std::uint64_t v) { return Duration(static_cast<std::int64_t>(v)); }

std::string label(std::string_view prefix, std::string_view name) {
  std::string s(prefix);
  s += name;
  return s;
}

NodeSpec generate_node(const Seed& master, std::uint32_t index) {
  Rng r = Rng::derive(master, label("gen/node/", node_name(index)));
  NodeSpec n;
  n.profile = r.below(2) == 0 ? ProfileId::rfc : ProfileId::linux_compat;
  n.sack = r.below(10) < 7;
  n.timestamps = r.below(10) < 7;
  n.window_scaling = r.below(10) < 7;
  n.nodelay = r.below(10) < 3;
  if (r.below(2) == 0) {
    n.snd_buf = static_cast<std::uint32_t>(log_uniform(r, 4 * kib, 8 * mib));
  }
  if (r.below(2) == 0) {
    n.rcv_buf = static_cast<std::uint32_t>(log_uniform(r, 4 * kib, 8 * mib));
  }
  if (r.below(10) == 0) {  // sequence numbers wrap early in the connection
    n.test_isn = 0xffff'ffffu - r.below(1u << 20);
  }
  if (r.below(20) == 0) {  // a reneging receiver
    n.renege_ppm = static_cast<std::uint32_t>(log_uniform(r, 1000, 200'000));
  }
  if (r.below(20) == 0) {  // small transmit queue and pool, slow host drain
    n.tx_queue_packets = 8 + r.below(57);
    n.pool_buffers = 16 + r.below(113);
    n.host_drain_max = 1 + r.below(8);
    n.host_delay = ns(log_uniform(r, 1000, 1'000'000));
  }
  return n;
}

LinkSpec clean_segment(std::string name) {
  LinkSpec l;
  l.name = std::move(name);
  l.params.delay = 50us;
  return l;
}

}  // namespace

Scenario generate_scenario(std::uint64_t seed, NodeKind nodes, const GenOptions& opt) {
  Scenario s;
  s.seed = seed;
  s.nodes = nodes;
  const Seed master = Seed::from_u64(seed);
  if (opt.probe_extra_label) {
    Rng probe = Rng::derive(master, "gen/test-probe");
    static_cast<void>(probe.next());
  }

  // Virtual time starts at a seeded offset of at least 1 s; 10 % of seeds
  // start up to 10 minutes before 2^32 ms, so 32-bit millisecond stamps wrap
  // during the run (§3.1).
  Rng rt = Rng::derive(master, "gen/time");
  if (rt.below(10) == 0) {
    constexpr std::int64_t wrap_ns = (std::int64_t{1} << 32) * 1'000'000;
    s.start = Time{wrap_ns - 1 - static_cast<std::int64_t>(rt.below64(600'000'000'000))};
  } else {
    s.start = Time{1'000'000'000 + static_cast<std::int64_t>(rt.below64(1'000'000'000'000))};
  }

  s.node = {generate_node(master, 0), generate_node(master, 1)};

  // Path character, shared by both directions.
  Rng rp = Rng::derive(master, "gen/path");
  const std::uint64_t delay = log_uniform(rp, 100'000, 100'000'000);  // 0.1-100 ms
  // One draw per statement, conditions before values (§13.1).
  std::uint64_t jitter = 0;
  if (rp.below(2) != 0) {
    jitter = rp.below64(delay / 2 + 1);
  }
  const bool reorder = rp.below(10) < 3;
  const std::uint32_t loss_class = rp.below(100);  // < 20 none, < 22 heavy (30 %), else up to 10 %
  const bool burst = loss_class >= 22 && rp.below(10) == 0;
  const bool garbage = rp.below(100) < 5;
  const bool spoof = rp.below(100) < 5;
  const bool dup_on = rp.below(10) < 3;
  const bool flip_on = rp.below(10) < 3;
  std::uint64_t rate = 0;
  if (rp.below(10) >= 3) {
    rate = log_uniform(rp, 1'000'000, 10'000'000'000);
  }
  const std::uint64_t queue_packets = log_uniform(rp, 2, 2000);
  std::uint16_t mtu = 1500;
  if (rp.below(10) >= 7) {
    mtu = static_cast<std::uint16_t>(576 + rp.below(924));
  }

  LinkParams dir_params[2];
  for (std::uint32_t d = 0; d < 2; ++d) {
    Rng rl = Rng::derive(master, d == 0 ? "gen/link/a>b" : "gen/link/b>a");
    LinkParams& p = dir_params[d];
    p.delay = ns(delay);
    p.jitter = ns(jitter);
    p.allow_reorder = reorder;
    p.loss_ppm = loss_class < 20   ? 0
                 : loss_class < 22 ? 300'000
                                   : static_cast<std::uint32_t>(log_uniform(rl, 100, 100'000));
    if (burst) {
      p.burst.p_ppm = static_cast<std::uint32_t>(log_uniform(rl, 1000, 50'000));
      p.burst.r_ppm = static_cast<std::uint32_t>(log_uniform(rl, 100'000, 800'000));
    }
    if (dup_on) {
      p.dup_ppm = static_cast<std::uint32_t>(log_uniform(rl, 100, 50'000));
      p.dup_extra_delay = ns(rl.below64(delay + 1));
    }
    if (flip_on) {
      p.bitflip_ppm = static_cast<std::uint32_t>(log_uniform(rl, 100, 20'000));
    }
    if (garbage) {
      p.garbage_ppm = static_cast<std::uint32_t>(log_uniform(rl, 1000, 20'000));
    }
    if (spoof) {
      p.icmp_spoof_ppm = static_cast<std::uint32_t>(log_uniform(rl, 100, 10'000));
    }
    p.rate_bps = rate;
    p.queue_bytes = rate > 0 ? static_cast<std::uint32_t>(queue_packets * 1500) : 0;
    p.mtu = mtu;
    p.send_frag_needed = mtu < 1500;
  }

  if (mtu == 1500) {
    s.link = {LinkSpec{"a>b", dir_params[0]}, LinkSpec{"b>a", dir_params[1]}};
    s.path = {PathSpec{0, 1, {0}}, PathSpec{1, 0, {1}}};
  } else {
    // A router between the nodes: a -(mtu)- r -(1500)- b. Each direction's
    // impairments sit on the low-MTU segment; the router at its entrance
    // answers too-big datagrams (for a, the segment starts at a itself).
    s.link = {LinkSpec{"a>r", dir_params[0]}, clean_segment("r>b"), clean_segment("b>r"),
              LinkSpec{"r>a", dir_params[1]}};
    s.path = {PathSpec{0, 1, {0, 1}}, PathSpec{1, 0, {2, 3}}};
  }

  // Workload.
  Rng rw = Rng::derive(master, "gen/wl");
  s.app_idle_timeout = 300s + ns(rw.below64(300'000'000'000));
  const std::uint32_t nconn = 1 + rw.below(8);
  for (std::uint32_t i = 0; i < nconn; ++i) {
    Rng rc = Rng::derive(master, label("gen/wl/conn", std::to_string(i)));
    ConnSpec c;
    const std::uint32_t m = rc.below(100);
    c.mode = m < 55   ? CloseMode::close
             : m < 75 ? CloseMode::half_close
             : m < 85 ? CloseMode::abort
             : m < 92 ? CloseMode::refused
                      : CloseMode::simultaneous;
    c.client = rc.below(2);
    c.server_port = static_cast<std::uint16_t>((c.mode == CloseMode::refused ? 6000 : 5000) + i);
    c.client_port = c.mode == CloseMode::simultaneous ? static_cast<std::uint16_t>(40000 + i) : 0;
    c.backlog = 1 + rc.below(4);
    c.start = 1ms + ns(rc.below64(1'000'000'000));
    if (rc.below(10) != 0) {
      c.bytes_c2s = log_uniform(rc, 1, 4 * mib);
    }
    if (rc.below(10) != 0) {
      c.bytes_s2c = log_uniform(rc, 1, 4 * mib);
    }
    c.write_max_c = static_cast<std::uint32_t>(log_uniform(rc, 1, 65536));
    c.write_max_s = static_cast<std::uint32_t>(log_uniform(rc, 1, 65536));
    if (rc.below(5) == 0) {  // readers that pause: zero windows
      c.pause_every_c = log_uniform(rc, kib, mib);
      c.pause_c = ns(log_uniform(rc, 1'000'000, 2'000'000'000));
    }
    if (rc.below(5) == 0) {
      c.pause_every_s = log_uniform(rc, kib, mib);
      c.pause_s = ns(log_uniform(rc, 1'000'000, 2'000'000'000));
    }
    if (c.mode == CloseMode::abort) {
      c.abort_after = ns(log_uniform(rc, 1'000'000, 5'000'000'000));
    }
    s.conn.push_back(c);
  }

  // Backlog limits: in 10 % of seeds every connection with a listener
  // (close, half_close, abort) uses the first one's listener and client
  // node, and the clients start within 10 ms of each other, so more SYNs
  // arrive than the backlog admits (SYNs beyond it are dropped, §3.5, and
  // retransmitted).
  Rng rb = Rng::derive(master, "gen/wl/backlog");
  if (rb.below(10) == 0) {
    std::vector<std::size_t> group;
    for (std::size_t i = 0; i < s.conn.size(); ++i) {
      const CloseMode m = s.conn[i].mode;
      if (m == CloseMode::close || m == CloseMode::half_close || m == CloseMode::abort) {
        group.push_back(i);
      }
    }
    if (group.size() >= 2) {
      const ConnSpec first = s.conn[group[0]];
      const std::uint32_t backlog = 1 + rb.below(static_cast<std::uint32_t>(group.size()) - 1);
      for (const std::size_t i : group) {
        ConnSpec& c = s.conn[i];
        c.client = first.client;
        c.server_port = first.server_port;
        c.client_port = static_cast<std::uint16_t>(41000 + i);
        c.backlog = backlog;
        if (i != group[0]) {
          c.start = first.start + ns(rb.below64(10'000'000));
        }
      }
    }
  }
  return s;
}

Scenario two_node_scenario(std::uint64_t seed, const LinkParams& ab, const LinkParams& ba) {
  Scenario s;
  s.seed = seed;
  s.app_idle_timeout = 300s;
  s.node = {NodeSpec{}, NodeSpec{}};
  s.link = {LinkSpec{"a>b", ab}, LinkSpec{"b>a", ba}};
  s.path = {PathSpec{0, 1, {0}}, PathSpec{1, 0, {1}}};
  return s;
}

// --- key=value serialisation. One visitor walks every field for both the
// writer and the reader, so the two cannot disagree.

namespace {

template <class E>
struct EnumName {
  E value;
  std::string_view name;
};

constexpr std::array<EnumName<NodeKind>, 2> node_kinds{
    {{NodeKind::stack, "stack"}, {NodeKind::synthetic, "synthetic"}}};
constexpr std::array<EnumName<Plant>, 5> plants{{{Plant::none, "none"},
                                                 {Plant::fail, "fail"},
                                                 {Plant::abort, "abort"},
                                                 {Plant::hang, "hang"},
                                                 {Plant::segv, "segv"}}};
constexpr std::array<EnumName<CloseMode>, 5> close_modes{{{CloseMode::close, "close"},
                                                          {CloseMode::half_close, "half_close"},
                                                          {CloseMode::abort, "abort"},
                                                          {CloseMode::refused, "refused"},
                                                          {CloseMode::simultaneous, "simultaneous"}}};
constexpr std::array<EnumName<ProfileId>, 2> profiles{
    {{ProfileId::rfc, "rfc"}, {ProfileId::linux_compat, "linux_compat"}}};
constexpr std::array<EnumName<TestFault>, 2> test_faults{
    {{TestFault::none, "none"}, {TestFault::unscaled_peer_window, "unscaled_peer_window"}}};

std::string idx_prefix(std::string_view list, std::size_t i) {
  std::string s(list);
  s += '.';
  s += std::to_string(i);
  s += '.';
  return s;
}

class KvWriter {
public:
  std::string out;

  template <class T>
    requires std::is_unsigned_v<T>
  void field(std::string_view key, T& v) {
    put(key, std::to_string(v));
  }
  void field(std::string_view key, bool& v) { put(key, v ? "1" : "0"); }
  void field(std::string_view key, Duration& v) { put(key, std::to_string(v.count())); }
  void field(std::string_view key, Time& v) { put(key, std::to_string(v.ns)); }
  void field(std::string_view key, std::string& v) { put(key, v); }
  void field(std::string_view key, Ipv4Addr& v) { put(key, to_string(v)); }
  void field(std::string_view key, std::optional<std::uint32_t>& v) {
    put(key, v ? std::to_string(*v) : "none");
  }
  void field(std::string_view key, std::vector<std::uint32_t>& v) {
    std::string s;
    for (std::size_t i = 0; i < v.size(); ++i) {
      if (i > 0) {
        s += ',';
      }
      s += std::to_string(v[i]);
    }
    put(key, s);
  }
  template <class E, std::size_t N>
  void enumeration(std::string_view key, E& v, const std::array<EnumName<E>, N>& names) {
    for (const auto& n : names) {
      if (n.value == v) {
        put(key, n.name);
        return;
      }
    }
    put(key, "?");
  }
  template <class T, class F>
  void list(std::string_view name, std::vector<T>& v, F&& each) {
    std::size_t n = v.size();
    field(std::string(name) + ".count", n);
    for (std::size_t i = 0; i < v.size(); ++i) {
      each(idx_prefix(name, i), v[i]);
    }
  }

private:
  void put(std::string_view key, std::string_view value) {
    out += key;
    out += '=';
    out += value;
    out += '\n';
  }
};

class KvReader {
public:
  explicit KvReader(std::map<std::string, std::string, std::less<>> kv) : kv_(std::move(kv)) {}

  std::string error;

  template <class T>
    requires std::is_unsigned_v<T>
  void field(std::string_view key, T& v) {
    if (const std::string* s = get(key)) {
      std::uint64_t x = 0;
      if (!parse_u64(*s, x) || x > std::numeric_limits<T>::max()) {
        fail(key, *s);
        return;
      }
      v = static_cast<T>(x);
    }
  }
  void field(std::string_view key, bool& v) {
    if (const std::string* s = get(key)) {
      if (*s == "1" || *s == "true") {
        v = true;
      } else if (*s == "0" || *s == "false") {
        v = false;
      } else {
        fail(key, *s);
      }
    }
  }
  void field(std::string_view key, Duration& v) {
    if (const std::string* s = get(key)) {
      std::int64_t x = 0;
      if (!parse_i64(*s, x) || x < 0) {
        fail(key, *s);
        return;
      }
      v = Duration(x);
    }
  }
  void field(std::string_view key, Time& v) {
    if (const std::string* s = get(key)) {
      std::int64_t x = 0;
      if (!parse_i64(*s, x) || x < 0) {
        fail(key, *s);
        return;
      }
      v = Time{x};
    }
  }
  void field(std::string_view key, std::string& v) {
    if (const std::string* s = get(key)) {
      v = *s;
    }
  }
  void field(std::string_view key, Ipv4Addr& v) {
    if (const std::string* s = get(key)) {
      const auto a = ipv4_from_string(*s);
      if (!a) {
        fail(key, *s);
        return;
      }
      v = *a;
    }
  }
  void field(std::string_view key, std::optional<std::uint32_t>& v) {
    if (const std::string* s = get(key)) {
      if (*s == "none") {
        v.reset();
        return;
      }
      std::uint64_t x = 0;
      if (!parse_u64(*s, x) || x > 0xffff'ffffu) {
        fail(key, *s);
        return;
      }
      v = static_cast<std::uint32_t>(x);
    }
  }
  void field(std::string_view key, std::vector<std::uint32_t>& v) {
    if (const std::string* s = get(key)) {
      v.clear();
      std::string_view rest = *s;
      while (!rest.empty()) {
        const std::size_t comma = rest.find(',');
        const std::string_view item = rest.substr(0, comma);
        std::uint64_t x = 0;
        if (!parse_u64(item, x) || x > 0xffff'ffffu) {
          fail(key, *s);
          return;
        }
        v.push_back(static_cast<std::uint32_t>(x));
        if (comma == std::string_view::npos) {
          break;
        }
        rest.remove_prefix(comma + 1);
        if (rest.empty()) {
          fail(key, *s);
          return;
        }
      }
    }
  }
  template <class E, std::size_t N>
  void enumeration(std::string_view key, E& v, const std::array<EnumName<E>, N>& names) {
    if (const std::string* s = get(key)) {
      for (const auto& n : names) {
        if (n.name == *s) {
          v = n.value;
          return;
        }
      }
      fail(key, *s);
    }
  }
  template <class T, class F>
  void list(std::string_view name, std::vector<T>& v, F&& each) {
    std::size_t n = v.size();
    field(std::string(name) + ".count", n);
    if (n > 4096) {
      fail(std::string(name) + ".count", std::to_string(n));
      return;
    }
    v.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
      each(idx_prefix(name, i), v[i]);
    }
  }

  // Keys present in the input that no field read.
  [[nodiscard]] std::vector<std::string> unused() const {
    std::vector<std::string> out;
    for (const auto& [k, value] : kv_) {
      if (!used_.contains(k)) {
        out.push_back(k);
      }
    }
    return out;
  }

private:
  const std::string* get(std::string_view key) {
    const auto it = kv_.find(key);
    if (it == kv_.end()) {
      return nullptr;
    }
    used_.insert(it->first);
    return &it->second;
  }
  void fail(std::string_view key, std::string_view value) {
    if (error.empty()) {
      error = "bad value for ";
      error += key;
      error += ": '";
      error += value;
      error += "'";
    }
  }
  static bool parse_u64(std::string_view s, std::uint64_t& x) {
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), x);
    return ec == std::errc{} && p == s.data() + s.size() && !s.empty();
  }
  static bool parse_i64(std::string_view s, std::int64_t& x) {
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), x);
    return ec == std::errc{} && p == s.data() + s.size() && !s.empty();
  }

  std::map<std::string, std::string, std::less<>> kv_;
  std::set<std::string, std::less<>> used_;
};

template <class V>
void visit(V& v, Scenario& s) {
  v.field("gen_version", s.gen_version);
  v.field("seed", s.seed);
  v.enumeration("nodes", s.nodes, node_kinds);
  v.enumeration("plant", s.plant, plants);
  v.field("plant_after_events", s.plant_after_events);
  v.field("start_ns", s.start);
  v.field("app_idle_timeout_ns", s.app_idle_timeout);
  v.list("node", s.node, [&](const std::string& p, NodeSpec& n) {
    v.enumeration(p + "profile", n.profile, profiles);
    v.field(p + "sack", n.sack);
    v.field(p + "timestamps", n.timestamps);
    v.field(p + "window_scaling", n.window_scaling);
    v.field(p + "nodelay", n.nodelay);
    v.field(p + "snd_buf", n.snd_buf);
    v.field(p + "rcv_buf", n.rcv_buf);
    v.field(p + "test_isn", n.test_isn);
    v.field(p + "renege_ppm", n.renege_ppm);
    v.enumeration(p + "test_fault", n.test_fault, test_faults);
    v.field(p + "tx_queue_packets", n.tx_queue_packets);
    v.field(p + "pool_buffers", n.pool_buffers);
    v.field(p + "host_drain_max", n.host_drain_max);
    v.field(p + "host_delay_ns", n.host_delay);
  });
  v.list("link", s.link, [&](const std::string& p, LinkSpec& l) {
    v.field(p + "name", l.name);
    LinkParams& q = l.params;
    v.field(p + "delay_ns", q.delay);
    v.field(p + "jitter_ns", q.jitter);
    v.field(p + "allow_reorder", q.allow_reorder);
    v.field(p + "loss_ppm", q.loss_ppm);
    v.field(p + "burst_p_ppm", q.burst.p_ppm);
    v.field(p + "burst_r_ppm", q.burst.r_ppm);
    v.field(p + "burst_loss_bad_ppm", q.burst.loss_bad_ppm);
    v.field(p + "dup_ppm", q.dup_ppm);
    v.field(p + "dup_extra_delay_ns", q.dup_extra_delay);
    v.field(p + "bitflip_ppm", q.bitflip_ppm);
    v.field(p + "garbage_ppm", q.garbage_ppm);
    v.field(p + "rate_bps", q.rate_bps);
    v.field(p + "queue_bytes", q.queue_bytes);
    v.field(p + "mtu", q.mtu);
    v.field(p + "send_frag_needed", q.send_frag_needed);
    v.field(p + "icmp_spoof_ppm", q.icmp_spoof_ppm);
    v.field(p + "router_addr", q.router_addr);
  });
  v.list("path", s.path, [&](const std::string& p, PathSpec& x) {
    v.field(p + "from", x.from);
    v.field(p + "to", x.to);
    v.field(p + "links", x.links);
  });
  v.list("conn", s.conn, [&](const std::string& p, ConnSpec& c) {
    v.enumeration(p + "mode", c.mode, close_modes);
    v.field(p + "client", c.client);
    v.field(p + "server_port", c.server_port);
    v.field(p + "client_port", c.client_port);
    v.field(p + "backlog", c.backlog);
    v.field(p + "start_ns", c.start);
    v.field(p + "bytes_c2s", c.bytes_c2s);
    v.field(p + "bytes_s2c", c.bytes_s2c);
    v.field(p + "write_max_c", c.write_max_c);
    v.field(p + "write_max_s", c.write_max_s);
    v.field(p + "pause_every_c", c.pause_every_c);
    v.field(p + "pause_c_ns", c.pause_c);
    v.field(p + "pause_every_s", c.pause_every_s);
    v.field(p + "pause_s_ns", c.pause_s);
    v.field(p + "abort_after_ns", c.abort_after);
  });
  v.list("udp", s.udp, [&](const std::string& p, UdpSpec& u) {
    v.field(p + "client", u.client);
    v.field(p + "server_port", u.server_port);
    v.field(p + "client_port", u.client_port);
    v.field(p + "server_bound", u.server_bound);
    v.field(p + "count", u.count);
    v.field(p + "size_min", u.size_min);
    v.field(p + "size_max", u.size_max);
    v.field(p + "interval_ns", u.interval);
    v.field(p + "start_ns", u.start);
  });
  v.list("ping", s.ping, [&](const std::string& p, PingSpec& x) {
    v.field(p + "client", x.client);
    v.field(p + "id", x.id);
    v.field(p + "count", x.count);
    v.field(p + "size", x.size);
    v.field(p + "interval_ns", x.interval);
    v.field(p + "start_ns", x.start);
  });
}

std::optional<std::string> validate(const Scenario& s) {
  if (s.node.size() != 2) {
    return "node.count must be 2";
  }
  std::set<std::string> names;
  for (const LinkSpec& l : s.link) {
    if (l.name.empty() || !names.insert(l.name).second) {
      return "link names must be unique and non-empty: '" + l.name + "'";
    }
    if (l.params.rate_bps > max_rate_bps) {
      return "link " + l.name + ": rate_bps above 1e12";
    }
    if (l.params.mtu < 68) {
      return "link " + l.name + ": mtu below 68";
    }
  }
  for (std::uint32_t from = 0; from < s.node.size(); ++from) {
    for (std::uint32_t to = 0; to < s.node.size(); ++to) {
      if (from == to) {
        continue;
      }
      std::size_t found = 0;
      for (const PathSpec& p : s.path) {
        found += p.from == from && p.to == to ? 1u : 0u;
      }
      if (found != 1) {
        return "need exactly one path from node " + std::to_string(from) + " to node " +
               std::to_string(to);
      }
    }
  }
  for (const PathSpec& p : s.path) {
    if (p.from >= s.node.size() || p.to >= s.node.size() || p.from == p.to) {
      return "path with bad node index";
    }
    for (const std::uint32_t l : p.links) {
      if (l >= s.link.size()) {
        return "path with bad link index " + std::to_string(l);
      }
    }
  }
  for (const ConnSpec& c : s.conn) {
    if (c.client >= s.node.size() || c.write_max_c == 0 || c.write_max_s == 0) {
      return "conn with bad client or write_max";
    }
    if (c.mode == CloseMode::simultaneous && c.client_port == 0) {
      return "simultaneous conn needs a client_port";
    }
  }
  // Connections on one server port of one node share a listener (ConnSpec).
  for (std::size_t i = 0; i < s.conn.size(); ++i) {
    for (std::size_t j = i + 1; j < s.conn.size(); ++j) {
      const ConnSpec& x = s.conn[i];
      const ConnSpec& y = s.conn[j];
      if (x.client != y.client || x.server_port != y.server_port) {
        continue;
      }
      const auto shares = [](const ConnSpec& c) {
        return c.mode == CloseMode::close || c.mode == CloseMode::half_close ||
               c.mode == CloseMode::abort;
      };
      if (!shares(x) || !shares(y) || x.client_port == 0 || y.client_port == 0 ||
          x.client_port == y.client_port || x.backlog != y.backlog) {
        return "conns " + std::to_string(i) + " and " + std::to_string(j) +
               " share a server port: both need a listener mode (close, half_close, abort), "
               "distinct client ports and the same backlog";
      }
    }
  }
  for (const UdpSpec& u : s.udp) {
    if (u.client >= s.node.size() || u.size_min > u.size_max || u.size_max > 65507) {
      return "udp flow with bad client or sizes";
    }
  }
  for (const PingSpec& p : s.ping) {
    if (p.client >= s.node.size() || p.size > 65507) {
      return "ping with bad client or size";
    }
  }
  return std::nullopt;
}

}  // namespace

std::string to_kv(const Scenario& s) {
  Scenario copy = s;
  KvWriter w;
  visit(w, copy);
  return std::move(w.out);
}

std::expected<Scenario, std::string> parse_kv(std::string_view text) {
  std::map<std::string, std::string, std::less<>> kv;
  std::size_t line_no = 0;
  while (!text.empty()) {
    const std::size_t nl = text.find('\n');
    std::string_view line = text.substr(0, nl);
    text.remove_prefix(nl == std::string_view::npos ? text.size() : nl + 1);
    ++line_no;
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
      line.remove_suffix(1);
    }
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
      line.remove_prefix(1);
    }
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos || eq == 0) {
      return std::unexpected("line " + std::to_string(line_no) + ": expected key=value");
    }
    if (!kv.emplace(std::string(line.substr(0, eq)), std::string(line.substr(eq + 1))).second) {
      return std::unexpected("line " + std::to_string(line_no) + ": duplicate key " +
                             std::string(line.substr(0, eq)));
    }
  }
  Scenario s;
  s.node.clear();
  KvReader r(std::move(kv));
  visit(r, s);
  if (!r.error.empty()) {
    return std::unexpected(r.error);
  }
  if (const auto unused = r.unused(); !unused.empty()) {
    return std::unexpected("unknown key " + unused.front());
  }
  if (s.gen_version > gen_version) {
    return std::unexpected("gen_version " + std::to_string(s.gen_version) +
                           " is newer than this binary's " + std::to_string(gen_version));
  }
  if (auto err = validate(s)) {
    return std::unexpected(*err);
  }
  return s;
}

}  // namespace utcp::sim
