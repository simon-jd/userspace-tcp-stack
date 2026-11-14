// libFuzzer target for the Stack's whole input path (DESIGN §11 Fuzz,
// m1-tcp-robust test 8). Each input starts a fresh Stack (10.0.0.2) with a
// listener on port 80, one connection it opened to 10.0.0.1:1000 and one
// child it accepted from 10.0.0.1:2000, both established by a scripted peer
// whose options the first input byte chooses. The rest of the input is a
// list of operations:
//
//   raw datagram bytes; an IPv4 header (valid checksum) around fuzz bytes of
//   any protocol with the transport checksum fixed; a TCP segment aimed at a
//   known connection, with SEQ, ACK, TSval and TSecr placed relative to what
//   the stack last sent and received, so the in-window paths are reached in a
//   few bytes; a SYN to the listener or to a closed port; an ICMP error
//   quoting a segment the stack sent; time steps; socket calls (send, recv,
//   shutdown, close, abort, options, a new connect).
//
// After every operation the stack's transmit queue and events are drained
// and Stack::debug_check() runs. At the end every socket is closed and the
// clock jumps from deadline to deadline with no peer answering, until no
// connection timer is armed; then debug_usage() must show a quiescent stack
// (no live slot, TIME_WAIT entry, queued packet, event or echo reply,
// blocked connection or armed connection timer, every buffer and chunk
// free). Any failure aborts through UTCP_CHECK.
//
// A 10-minute campaign runs e.g. -max_len=2048 -jobs=8 -workers=8 on CPUs
// 16-31.
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
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"
#include "utcp/config.hpp"
#include "utcp/stack.hpp"

namespace {

using namespace std::chrono_literals;
using utcp::Duration;
using utcp::Endpoint;
using utcp::Handle;
using utcp::Ipv4Addr;
using utcp::Seq32;
using utcp::Stack;
using utcp::Time;
namespace wire = utcp::wire;
namespace test = utcp::test;

const Ipv4Addr us = Ipv4Addr::from_octets(10, 0, 0, 2);
const Ipv4Addr peer = Ipv4Addr::from_octets(10, 0, 0, 1);
constexpr std::uint16_t listen_port = 80;

class Input {
public:
  Input(const std::uint8_t* data, std::size_t size) : p_(data), end_(data + size) {}
  [[nodiscard]] bool empty() const { return p_ == end_; }
  std::uint8_t u8() { return p_ == end_ ? std::uint8_t{0} : *p_++; }
  std::uint16_t u16() {
    const std::uint8_t hi = u8();
    return static_cast<std::uint16_t>((hi << 8) | u8());
  }
  std::uint32_t u32() {
    const std::uint16_t hi = u16();
    return (std::uint32_t{hi} << 16) | u16();
  }
  std::vector<std::byte> bytes(std::size_t n) {
    n = std::min<std::size_t>(n, static_cast<std::size_t>(end_ - p_));
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) {
      v[i] = static_cast<std::byte>(p_[i]);
    }
    p_ += n;
    return v;
  }

private:
  const std::uint8_t* p_;
  const std::uint8_t* end_;
};

// What the scripted peer knows about one connection, learnt from the
// segments the stack sends.
struct Conn {
  Endpoint local, remote;  // local = the stack's end
  std::optional<Handle> h;  // the application's handle, if any
  Seq32 peer_next{0};       // next sequence number the peer sends (the stack's RCV.NXT)
  Seq32 our_next{0};        // the stack's highest sequence sent + 1
  Seq32 our_una{0};         // the highest ACK the peer sent
  std::uint32_t peer_tsval = 1000;
  std::uint32_t our_tsval = 0;  // last TSval the stack sent
  bool ts = false, sack = false;
  std::uint8_t wscale = 0;
};

struct PeerOptions {
  bool mss = true, ws = true, sack = true, ts = true;
};

class Run {
public:
  explicit Run(std::uint8_t cfg) : stack_(config(cfg)) {
    stack_.advance(now_);
    peer_opt_.ws = (cfg & 0x10) != 0;
    peer_opt_.sack = (cfg & 0x20) != 0;
    peer_opt_.ts = (cfg & 0x40) != 0;
    peer_opt_.mss = (cfg & 0x80) == 0;
    setup();
  }

  void op(Input& in) {
    const std::uint8_t code = in.u8();
    switch (code % 12) {
      case 0: raw(in); break;
      case 1: framed(in); break;
      case 2:
      case 3:
      case 4: segment(in); break;
      case 5: syn(in); break;
      case 6: icmp(in); break;
      case 7: step(in); break;
      case 8:
      case 9: app(in); break;
      case 10: connect(in); break;
      default: to_deadline(); break;
    }
    drain();
  }

  // Closes every socket and lets every timer run out; the stack must then be
  // quiescent (§7.3 QuiescenceChecker, D13).
  void finish() {
    for (Conn& c : conns_) {
      if (c.h) {
        static_cast<void>(stack_.tcp_close(*c.h));
        c.h.reset();
      }
    }
    for (const Handle& l : listeners_) {
      static_cast<void>(stack_.tcp_close(l));
    }
    listeners_.clear();
    drain();
    for (int i = 0;; ++i) {
      const utcp::StackUsage u = stack_.debug_usage();
      if (u.conn_timers_armed == 0 && u.tx_queued == 0 && u.blocked_conns == 0) {
        break;
      }
      UTCP_CHECK(i < 100'000);  // a timer that never stops firing
      const Time d = stack_.next_deadline();
      UTCP_CHECK(!d.is_never());  // armed timers or queued work, but no deadline
      now_ = std::max(now_, d);
      stack_.advance(now_);
      drain();
    }
    const utcp::StackUsage u = stack_.debug_usage();
    UTCP_CHECK(u.tcp_slots == 0);
    UTCP_CHECK(u.udp_slots == 0);
    UTCP_CHECK(u.time_wait_entries == 0);
    UTCP_CHECK(u.tx_queued == 0);
    UTCP_CHECK(u.events_queued == 0);
    UTCP_CHECK(u.echo_replies_queued == 0);
    UTCP_CHECK(u.blocked_conns == 0);
    UTCP_CHECK(u.conn_timers_armed == 0);
    UTCP_CHECK(u.pool_buffers_free == u.pool_buffers);
    UTCP_CHECK(u.chunks_free == u.chunks);
  }

private:
  static utcp::StackConfig config(std::uint8_t cfg) {
    utcp::StackConfig c;
    c.local_addr = us;
    c.seed = utcp::Seed::from_u64(cfg);
    c.tcp = utcp::tcp_config((cfg & 1) != 0 ? utcp::ProfileId::rfc : utcp::ProfileId::linux_compat);
    c.tcp.sack = (cfg & 2) == 0;
    c.tcp.timestamps = (cfg & 4) == 0;
    c.tcp.window_scaling = (cfg & 8) == 0;
    c.pool_buffers = 128;  // small: each input builds a new stack
    c.tx_queue_packets = 64;
    c.assert_time_monotonic = true;
    return c;
  }

  // --- The scripted peer.

  wire::TcpOptions syn_options(const Conn& c) const {
    wire::TcpOptions o;
    if (peer_opt_.mss) {
      o.mss = 1460;
    }
    if (peer_opt_.ws) {
      o.wscale = 7;
    }
    o.sack_permitted = peer_opt_.sack;
    if (peer_opt_.ts) {
      o.ts = wire::Timestamps{c.peer_tsval, c.our_tsval};
    }
    return o;
  }

  void deliver(std::span<const std::byte> d) {
    stack_.receive(now_, d);
    stack_.debug_check();
  }

  void send_tcp(Conn& c, std::uint16_t flags, Seq32 seq, Seq32 ack, std::uint16_t window,
                const wire::TcpOptions& opt, std::vector<std::byte> payload) {
    test::TcpSpec t(c.remote, c.local);
    t.seq = seq;
    t.ack = ack;
    t.flags = flags;
    t.window = window;
    t.opt = opt;
    t.payload = std::move(payload);
    deliver(test::tcp_datagram(t));
  }

  Conn* find(const Endpoint& local, const Endpoint& remote) {
    for (Conn& c : conns_) {
      if (c.local == local && c.remote == remote) {
        return &c;
      }
    }
    return nullptr;
  }

  // Learns sequence numbers and timestamps from a datagram the stack sent.
  void learn(std::span<const std::byte> d) {
    const auto ip = wire::parse_ipv4(d);
    if (!ip || ip->h.proto != utcp::ip_proto_tcp) {
      return;
    }
    const auto seg = wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
    UTCP_CHECK(seg.has_value());  // the stack sends well-formed segments only
    last_sent_.assign(d.begin(), d.end());
    Conn* c = find(Endpoint{ip->h.src, seg->h.sport}, Endpoint{ip->h.dst, seg->h.dport});
    if (c == nullptr) {
      return;
    }
    const std::uint32_t len = static_cast<std::uint32_t>(seg->payload.size()) +
                              ((seg->h.flags & wire::tcp_syn) != 0 ? 1u : 0u) +
                              ((seg->h.flags & wire::tcp_fin) != 0 ? 1u : 0u);
    const Seq32 end = seg->h.seq + len;
    if ((seg->h.flags & wire::tcp_syn) != 0 || end.raw() - c->our_next.raw() < (1u << 31)) {
      c->our_next = end;
    }
    if ((seg->h.flags & wire::tcp_ack) != 0) {
      c->peer_next = seg->h.ack;
    }
    if (seg->opt.ts) {
      c->our_tsval = seg->opt.ts->val;
    }
  }

  void drain() {
    while (auto p = stack_.pop_transmit()) {
      learn(p->buf.bytes());
    }
    while (stack_.poll_event()) {
    }
    while (stack_.poll_echo_reply()) {  // replies to echo requests nobody sent
    }
    stack_.debug_check();
  }

  void setup() {
    const auto l = stack_.tcp_listen(Endpoint{us, listen_port}, 4);
    UTCP_CHECK(l.has_value());
    listeners_.push_back(*l);
    // Active open to 10.0.0.1:1000.
    const auto h = stack_.tcp_connect(Endpoint{peer, 1000});
    UTCP_CHECK(h.has_value());
    // The local port is learnt from the SYN.
    while (auto p = stack_.pop_transmit()) {
      const auto ip = wire::parse_ipv4(p->buf.bytes());
      UTCP_CHECK(ip.has_value());
      const auto seg = wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
      UTCP_CHECK(seg.has_value());
      Conn c;
      c.local = Endpoint{us, seg->h.sport};
      c.remote = Endpoint{peer, 1000};
      c.h = *h;
      c.our_next = seg->h.seq + 1;
      c.peer_next = Seq32(0x10000000);
      if (seg->opt.ts) {
        c.our_tsval = seg->opt.ts->val;
      }
      conns_.push_back(c);
    }
    UTCP_CHECK(conns_.size() == 1);
    {
      Conn& c = conns_[0];
      send_tcp(c, wire::tcp_syn | wire::tcp_ack, c.peer_next, c.our_next, 65535, syn_options(c), {});
      c.peer_next = c.peer_next + 1;
      drain();
    }
    // Passive open from 10.0.0.1:2000.
    Conn p;
    p.local = Endpoint{us, listen_port};
    p.remote = Endpoint{peer, 2000};
    p.peer_next = Seq32(0x20000000);
    conns_.push_back(p);
    {
      Conn& c = conns_[1];
      send_tcp(c, wire::tcp_syn, c.peer_next, Seq32(0), 65535, syn_options(c), {});
      c.peer_next = c.peer_next + 1;
      drain();
      wire::TcpOptions o;
      if (peer_opt_.ts) {
        o.ts = wire::Timestamps{++c.peer_tsval, c.our_tsval};
      }
      send_tcp(c, wire::tcp_ack, c.peer_next, c.our_next, 65535, o, {});
      drain();
      if (const auto child = stack_.tcp_accept(listeners_[0])) {
        c.h = *child;
      }
    }
  }

  // --- Operations.

  void raw(Input& in) { deliver(in.bytes(in.u16() % 1600)); }

  // A valid IPv4 header (options possible) around fuzz bytes; TCP and UDP
  // checksums fixed so the transport parser sees the bytes.
  void framed(Input& in) {
    const std::uint8_t sel = in.u8();
    static constexpr std::array<std::uint8_t, 4> protos{utcp::ip_proto_tcp, utcp::ip_proto_udp,
                                                        utcp::ip_proto_icmp, 47};
    test::IpSpec ip;
    ip.src = (sel & 0x10) != 0 ? Ipv4Addr::from_octets(10, 0, 0, sel) : peer;
    ip.dst = (sel & 0x20) != 0 ? Ipv4Addr::from_octets(255, 255, 255, 255) : us;
    ip.proto = protos[sel & 3];
    ip.df = (sel & 0x40) != 0;
    if ((sel & 0x80) != 0) {
      ip.options = in.bytes(in.u8() % 41);
    }
    const auto payload = in.bytes(in.u16() % 1600);
    auto d = test::ipv4(ip, payload);
    if (ip.proto == utcp::ip_proto_tcp || ip.proto == utcp::ip_proto_udp) {
      const std::size_t hl = 20 + ((ip.options.size() + 3) & ~std::size_t{3});
      const std::size_t min_l4 = ip.proto == utcp::ip_proto_tcp ? 20 : 8;
      if (d.size() >= hl + min_l4) {
        test::fix_checksums(d, true);
      }
    }
    deliver(d);
  }

  // A TCP segment from the peer to a known connection.
  void segment(Input& in) {
    if (conns_.empty()) {
      return;
    }
    Conn& c = conns_[in.u8() % conns_.size()];
    const std::uint8_t sel = in.u8();
    std::uint16_t flags = wire::tcp_ack;
    switch (sel & 7) {
      case 0: break;                                    // ACK / data
      case 1: flags |= wire::tcp_fin; break;
      case 2: flags = wire::tcp_rst; break;
      case 3: flags |= wire::tcp_rst; break;
      case 4: flags = wire::tcp_syn; break;
      case 5: flags |= wire::tcp_syn; break;
      case 6: flags |= wire::tcp_psh; break;
      default: flags = in.u16() & 0x0fff; break;        // anything, AE and reserved bits included
    }
    // Offsets relative to what the peer knows; small ones most of the time.
    const auto rel = [&](std::uint8_t mode) -> std::int64_t {
      switch (mode & 3) {
        case 0: return 0;
        case 1: return static_cast<std::int8_t>(in.u8());
        case 2: return static_cast<std::int16_t>(in.u16());
        default: return static_cast<std::int32_t>(in.u32());
      }
    };
    const Seq32 seq = c.peer_next + static_cast<std::uint32_t>(rel(sel >> 3));
    const Seq32 ack = c.our_next + static_cast<std::uint32_t>(rel(sel >> 5));
    const std::uint16_t window = (sel & 0x80) != 0 ? in.u16() : 65535;
    wire::TcpOptions o;
    const std::uint8_t osel = in.u8();
    if ((osel & 1) != 0 || ((osel & 2) == 0 && peer_opt_.ts)) {
      const std::int64_t dv = (osel & 4) != 0 ? static_cast<std::int16_t>(in.u16()) : 1;
      c.peer_tsval += static_cast<std::uint32_t>(dv);
      const std::uint32_t ecr = (osel & 8) != 0 ? in.u32() : c.our_tsval;
      o.ts = wire::Timestamps{c.peer_tsval, ecr};
    }
    if ((osel & 0x10) != 0) {
      const std::uint8_t n = static_cast<std::uint8_t>(1 + in.u8() % (o.ts ? 3 : 4));
      for (std::uint8_t i = 0; i < n; ++i) {
        const Seq32 b = c.our_una + static_cast<std::uint32_t>(static_cast<std::int16_t>(in.u16()));
        o.sack[i] = {b, b + (in.u16() % 20000u)};
      }
      o.sack_count = n;
    }
    if ((osel & 0x20) != 0) {
      o.mss = in.u16();
    }
    if ((osel & 0x40) != 0) {
      o.wscale = in.u8();
    }
    std::vector<std::byte> payload;
    if ((osel & 0x80) != 0) {
      payload = in.bytes(in.u16() % 3000);
    }
    if ((flags & wire::tcp_ack) != 0 && ack.raw() - c.our_una.raw() < (1u << 31) &&
        c.our_next.raw() - ack.raw() < (1u << 31)) {
      c.our_una = ack;
    }
    send_tcp(c, flags, seq, ack, window, o, std::move(payload));
  }

  // A SYN to the listener (new child) or to a closed port.
  void syn(Input& in) {
    const std::uint8_t sel = in.u8();
    Conn c;
    c.local = Endpoint{us, (sel & 1) != 0 ? listen_port : std::uint16_t{81}};
    c.remote = Endpoint{peer, static_cast<std::uint16_t>(3000 + (sel >> 1))};
    c.peer_next = Seq32(in.u32());
    c.peer_tsval = in.u32();
    if (find(c.local, c.remote) == nullptr && conns_.size() < 16) {
      conns_.push_back(c);
    }
    Conn* known = find(c.local, c.remote);
    Conn& k = known != nullptr ? *known : c;
    send_tcp(k, wire::tcp_syn | ((sel & 0x80) != 0 ? std::uint16_t{0x1c0} : std::uint16_t{0}),
             k.peer_next, Seq32(0), in.u16(), syn_options(k), {});
    k.peer_next = k.peer_next + 1;
  }

  // An ICMP error quoting the last segment the stack sent (sequence numbers
  // in range), possibly edited.
  void icmp(Input& in) {
    if (last_sent_.size() < 28) {
      return;
    }
    const std::uint8_t sel = in.u8();
    static constexpr std::array<std::array<std::uint8_t, 2>, 8> kinds{
        {{3, 4}, {3, 4}, {3, 3}, {3, 0}, {3, 1}, {3, 2}, {11, 0}, {12, 0}}};
    const auto k = kinds[sel & 7];
    std::vector<std::byte> quoted = last_sent_;
    if ((sel & 0x08) != 0) {  // shift the quoted sequence number
      const std::uint32_t d = in.u32();
      for (int i = 0; i < 4; ++i) {
        quoted[24 + i] = static_cast<std::byte>(static_cast<std::uint8_t>(quoted[24 + i]) ^
                                                static_cast<std::uint8_t>(d >> (8 * (3 - i))));
      }
    }
    const std::uint32_t rest = k[1] == 4 ? in.u16() : 0;
    const std::size_t quote = (sel & 0x10) != 0 ? 28 + in.u8() % 64 : quoted.size();
    const Ipv4Addr from = (sel & 0x20) != 0 ? Ipv4Addr::from_octets(10, 0, 0, 254) : peer;
    deliver(test::icmp_error(from, us, k[0], k[1], rest, quoted, std::min(quote, quoted.size())));
  }

  void step(Input& in) {
    const std::uint16_t v = in.u16();
    const Duration d = (v & 0x8000) != 0 ? Duration(std::chrono::seconds(v & 0x7fff)) / 16
                                         : Duration(std::chrono::milliseconds(v & 0x7fff)) / 8;
    now_ = now_ + d;
    stack_.advance(now_);
  }

  void to_deadline() {
    const Time d = stack_.next_deadline();
    if (!d.is_never() && d - now_ < std::chrono::hours(1)) {
      now_ = std::max(now_, d);
      stack_.advance(now_);
    }
  }

  void app(Input& in) {
    std::vector<Handle> hs;
    for (const Conn& c : conns_) {
      if (c.h) {
        hs.push_back(*c.h);
      }
    }
    if (hs.empty()) {
      return;
    }
    const std::uint8_t sel = in.u8();
    const Handle h = hs[sel % hs.size()];
    const auto drop_handle = [&] {
      for (Conn& c : conns_) {
        if (c.h == h) {
          c.h.reset();
        }
      }
    };
    switch ((sel >> 4) % 8) {
      case 0:
      case 1: {
        std::vector<std::byte> data(in.u16() % 20000);
        for (std::size_t i = 0; i < data.size(); ++i) {
          data[i] = static_cast<std::byte>(i * 7);
        }
        static_cast<void>(stack_.tcp_send(h, data));
        break;
      }
      case 2: {
        std::vector<std::byte> out(70000);
        static_cast<void>(stack_.tcp_recv(h, out));
        break;
      }
      case 3: {
        static constexpr std::array<utcp::Shutdown, 3> how{
            utcp::Shutdown::read, utcp::Shutdown::write, utcp::Shutdown::both};
        static_cast<void>(stack_.tcp_shutdown(h, how[in.u8() % 3]));
        break;
      }
      case 4:
        static_cast<void>(stack_.tcp_close(h));
        drop_handle();
        break;
      case 5:
        static_cast<void>(stack_.tcp_abort(h));
        drop_handle();
        break;
      case 6: {
        utcp::TcpSocketOptions o;
        const std::uint8_t v = in.u8();
        o.nodelay = (v & 1) != 0;
        if ((v & 2) != 0) {
          o.rcv_buf = 1u + in.u16() * 64u;
        }
        if ((v & 4) != 0) {
          o.snd_buf = 1u + in.u16() * 64u;
        }
        static_cast<void>(stack_.tcp_set_options(h, o));
        break;
      }
      default:
        static_cast<void>(stack_.take_error(h));
        static_cast<void>(stack_.tcp_info(h));
        static_cast<void>(stack_.tcp_readiness(h));
        break;
    }
  }

  void connect(Input& in) {
    if (conns_.size() >= 16) {
      return;
    }
    const std::uint16_t rport = static_cast<std::uint16_t>(4000 + in.u8());
    const auto h = stack_.tcp_connect(Endpoint{peer, rport});
    if (!h) {
      return;
    }
    while (auto p = stack_.pop_transmit()) {
      const auto ip = wire::parse_ipv4(p->buf.bytes());
      UTCP_CHECK(ip.has_value());
      const auto seg = wire::parse_tcp(ip->payload, ip->h.src, ip->h.dst, true);
      UTCP_CHECK(seg.has_value());
      if ((seg->h.flags & wire::tcp_syn) == 0 || seg->h.dport != rport) {
        learn(p->buf.bytes());
        continue;
      }
      Conn c;
      c.local = Endpoint{us, seg->h.sport};
      c.remote = Endpoint{peer, rport};
      c.h = *h;
      c.our_next = seg->h.seq + 1;
      c.peer_next = Seq32(in.u32());
      if (seg->opt.ts) {
        c.our_tsval = seg->opt.ts->val;
      }
      if (find(c.local, c.remote) == nullptr) {
        conns_.push_back(c);
      }
      last_sent_.assign(p->buf.bytes().begin(), p->buf.bytes().end());
    }
    // The peer may answer at once with a SYN-ACK.
    if ((in.u8() & 1) != 0) {
      for (Conn& k : conns_) {
        if (k.h == *h) {
          send_tcp(k, wire::tcp_syn | wire::tcp_ack, k.peer_next, k.our_next, 65535,
                   syn_options(k), {});
          k.peer_next = k.peer_next + 1;
          break;
        }
      }
    }
  }

  Time now_{1'000'000'000};
  Stack stack_;
  PeerOptions peer_opt_;
  std::vector<Conn> conns_;
  std::vector<Handle> listeners_;
  std::vector<std::byte> last_sent_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  Input in(data, size);
  Run run(in.u8());
  for (int ops = 0; !in.empty() && ops < 400; ++ops) {
    run.op(in);
  }
  run.finish();
  return 0;
}
