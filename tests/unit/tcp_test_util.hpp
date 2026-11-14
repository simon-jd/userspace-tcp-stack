// Helpers shared by the TCP engine tests (tcp_*_test.cpp): parsing what the
// stacks send, opening connections over the two-stack harness, reading, and
// one stack driven segment by segment by a scripted peer. Inline functions
// in a named namespace, so every test file may use any subset of them.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "support/packet_builder.hpp"
#include "support/tcp_harness.hpp"
#include "utcp/checksum.hpp"
#include "utcp/config.hpp"
#include "utcp/stack.hpp"

namespace utcp::test::tcpt {

using namespace std::chrono_literals;

inline constexpr std::uint16_t port = 80;

struct Parsed {
  wire::Ipv4Header ip;
  wire::TcpView v;
};

// The TCP segment in a datagram (views into `d`).
inline std::optional<Parsed> parse(std::span<const std::byte> d) {
  const auto ip = wire::parse_ipv4(d);
  if (!ip || ip->h.proto != ip_proto_tcp) {
    return std::nullopt;
  }
  const auto v = wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
  if (!v) {
    return std::nullopt;
  }
  return Parsed{ip->h, *v};
}

inline bool has(const wire::TcpView& v, std::uint16_t f) { return (v.h.flags & f) == f; }
inline bool is_syn(const wire::TcpView& v) {
  return has(v, wire::tcp_syn) && !has(v, wire::tcp_ack);
}
inline bool is_synack(const wire::TcpView& v) { return has(v, wire::tcp_syn | wire::tcp_ack); }
inline bool is_rst(const wire::TcpView& v) { return has(v, wire::tcp_rst); }
inline bool is_fin(const wire::TcpView& v) { return has(v, wire::tcp_fin); }
inline bool is_data(const wire::TcpView& v) { return !v.payload.empty(); }
// No payload, no SYN, FIN or RST.
inline bool is_pure_ack(const wire::TcpView& v) {
  return v.payload.empty() && (v.h.flags & (wire::tcp_syn | wire::tcp_fin | wire::tcp_rst)) == 0;
}

// Log entries from `from` that satisfy `pred`, oldest first.
template <class Pred>
std::vector<const Sent*> find(const TcpHarness& h, Side from, Pred pred) {
  std::vector<const Sent*> out;
  for (const Sent& s : h.log()) {
    if (s.from != from) {
      continue;
    }
    const auto p = parse(s.bytes);
    if (p && pred(p->v)) {
      out.push_back(&s);
    }
  }
  return out;
}

inline StackConfig config(Side s, ProfileId profile = ProfileId::linux_compat) {
  StackConfig c = TcpHarness::default_config(s);
  c.tcp = tcp_config(profile);
  return c;
}

struct Pair {
  Handle listener, client, server;
};

// b listens on `port`, a connects with `opts`; runs `d`, then accepts.
inline std::optional<Pair> open(TcpHarness& h, Duration d = 100ms,
                                const TcpSocketOptions& opts = {}) {
  const auto l = h.b().tcp_listen(Endpoint{{}, port}, 16, opts);
  if (!l) {
    return std::nullopt;
  }
  const auto c = h.a().tcp_connect(Endpoint{h.addr(Side::b), port}, opts);
  if (!c) {
    return std::nullopt;
  }
  h.run_for(d);
  const auto s = h.b().tcp_accept(*l);
  if (!s) {
    return std::nullopt;
  }
  return Pair{*l, *c, *s};
}

inline TcpState state(Stack& s, Handle h) {
  const auto i = s.tcp_info(h);
  return i ? i->state : TcpState::closed;
}

// Reads everything readable.
inline Bytes drain(Stack& s, Handle h) {
  Bytes out;
  std::array<std::byte, 4096> buf{};
  for (;;) {
    const auto r = s.tcp_recv(h, buf);
    if (!r || *r == 0) {
      return out;
    }
    out.insert(out.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*r));
  }
}

// Every pending event bit of `h`, OR-ed (events of other sockets are lost).
inline std::uint16_t events_of(Stack& s, Handle h) {
  std::uint16_t ev = 0;
  while (const auto e = s.poll_event()) {
    if (e->h == h) {
      ev = static_cast<std::uint16_t>(ev | e->events);
    }
  }
  return ev;
}

// One stack driven segment by segment by a scripted peer at 10.0.0.1. The
// stack is 10.0.0.2 (the harness's side b configuration with `profile`).
class Driven {
public:
  explicit Driven(ProfileId profile = ProfileId::linux_compat)
      : Driven(config(Side::b, profile)) {}
  explicit Driven(const StackConfig& cfg) : s_(cfg) { s_.advance(now_); }

  Stack& stack() { return s_; }
  [[nodiscard]] Time now() const { return now_; }
  [[nodiscard]] Endpoint local(std::uint16_t p = port) const {
    return Endpoint{s_.config().local_addr, p};
  }
  static Endpoint peer(std::uint16_t p) { return Endpoint{Ipv4Addr::from_octets(10, 0, 0, 1), p}; }

  void send(const TcpSpec& spec) { s_.receive(now_, tcp_datagram(spec)); }
  // Moves the clock by `d` (firing timers on the way).
  void run_for(Duration d) {
    const Time end = now_ + d;
    while (s_.next_deadline() <= end) {
      now_ = std::max(now_, s_.next_deadline());
      s_.advance(now_);
    }
    now_ = end;
    s_.advance(now_);
  }
  // Datagrams the stack sent since the last call.
  std::vector<Bytes> out() {
    std::vector<Bytes> v;
    while (auto p = s_.pop_transmit()) {
      const auto b = p->buf.bytes();
      v.emplace_back(b.begin(), b.end());
    }
    return v;
  }

private:
  Stack s_;
  Time now_{1'000'000'000};
};

// The options of a scripted peer's SYN.
struct PeerOpts {
  bool ts = false;
  bool sack = true;
  std::optional<std::uint8_t> wscale = 7;
  std::uint16_t mss = 1460;
  std::uint16_t window = 65535;  // of the SYN and later segments (scaled by wscale after it)
};

// A Driven stack listening on `port` and one connection to a scripted peer,
// with the peer's view of both sequence spaces.
class Scripted {
public:
  explicit Scripted(ProfileId profile = ProfileId::linux_compat) : d_(profile) {}
  explicit Scripted(const StackConfig& cfg) : d_(cfg) {}

  Driven& d() { return d_; }
  Stack& stack() { return d_.stack(); }

  std::uint16_t peer_port = 40000;
  PeerOpts po;
  Handle listener, h;
  Seq32 nxt;                    // the peer's next sequence number
  Seq32 their;                  // the peer's RCV.NXT (the stack's sequence space)
  std::uint32_t tsval = 5000;   // the peer's TSval, sent as is
  std::uint32_t their_ts = 0;   // the stack's last TSval
  std::uint16_t window = 65535;  // window field of the peer's segments

  // A segment from the peer: SEQ = nxt, ACK = their, the window, TS.
  [[nodiscard]] TcpSpec spec(std::uint16_t flags) const {
    TcpSpec s(Driven::peer(peer_port), d_.local());
    s.seq = nxt;
    s.ack = their;
    s.flags = flags;
    s.window = window;
    if (po.ts) {
      s.opt.ts = wire::Timestamps{tsval, their_ts};
    }
    return s;
  }
  void send(const TcpSpec& s) { d_.send(s); }
  // Payload `n` bytes at nxt; advances nxt.
  void send_data(std::size_t n, std::uint16_t flags = wire::tcp_ack | wire::tcp_psh) {
    TcpSpec s = spec(flags);
    s.payload = pattern(n);
    nxt = nxt + static_cast<std::uint32_t>(n);
    d_.send(s);
  }
  // The stack's output since the last call, parsed (views into kept bytes);
  // remembers the stack's last TSval.
  std::vector<Parsed> out() {
    kept_.clear();
    for (Bytes& b : d_.out()) {
      kept_.push_back(std::move(b));
    }
    std::vector<Parsed> v;
    for (const Bytes& b : kept_) {
      if (const auto p = parse(b)) {
        if (p->v.opt.ts) {
          their_ts = p->v.opt.ts->val;
        }
        v.push_back(*p);
      }
    }
    return v;
  }

  // Listens (backlog 16), takes the peer's SYN with `po`, ACKs the SYN-ACK
  // with window `ack_window`, and accepts. False on any surprise.
  bool accept(Seq32 isn = Seq32{10'000}, std::uint16_t ack_window = 65535) {
    const auto l = stack().tcp_listen(Endpoint{{}, port}, 16, {});
    if (!l) {
      return false;
    }
    listener = *l;
    nxt = isn;
    window = po.window;
    TcpSpec syn = spec(wire::tcp_syn);
    syn.ack = Seq32{};
    syn.opt.mss = po.mss;
    syn.opt.wscale = po.wscale;
    syn.opt.sack_permitted = po.sack;
    if (po.ts) {
      syn.opt.ts = wire::Timestamps{tsval, 0};
    }
    d_.send(syn);
    const auto sa = out();
    if (sa.size() != 1 || !is_synack(sa[0].v)) {
      return false;
    }
    nxt = isn + 1;
    their = sa[0].v.h.seq + 1;
    ++tsval;
    window = ack_window;
    d_.send(spec(wire::tcp_ack));
    const auto a = stack().tcp_accept(listener);
    if (!a) {
      return false;
    }
    h = *a;
    return out().empty();
  }

private:
  Driven d_;
  std::vector<Bytes> kept_;
};

}  // namespace utcp::test::tcpt
