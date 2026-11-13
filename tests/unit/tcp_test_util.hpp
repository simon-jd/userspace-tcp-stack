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

}  // namespace utcp::test::tcpt
