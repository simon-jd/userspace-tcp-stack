#include "core/icmp.hpp"

#include <algorithm>
#include <utility>

#include "core/stack_impl.hpp"
#include "core/udp.hpp"
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp {

std::uint16_t pmtu_plateau_below(std::uint16_t total_len) noexcept {
  // RFC 1191 §7, Table 7-1, without the 65535 that nothing is below.
  static constexpr std::array<std::uint16_t, 10> plateaus{32000, 17914, 8166, 4352, 2002,
                                                          1492,  1006,  508,  296,  68};
  for (const std::uint16_t p : plateaus) {
    if (p < total_len) {
      return p;
    }
  }
  return 68;
}

std::uint16_t frag_needed_mtu(std::uint16_t next_hop_mtu, std::uint16_t quoted_total_len,
                              std::uint16_t min_pmtu) noexcept {
  // RFC 1191 §4 next-hop MTU; §7: a router that predates it sends 0, and the
  // host takes the next plateau below the quoted datagram's length.
  const std::uint16_t mtu =
      next_hop_mtu != 0 ? next_hop_mtu : pmtu_plateau_below(quoted_total_len);
  // Linux __ip_rt_update_pmtu: values below ip_rt_min_pmtu are raised to it.
  return std::max(mtu, min_pmtu);
}

bool is_unicast_source(Ipv4Addr a) noexcept {
  const std::uint8_t first = a.octet(0);
  // RFC 1122 §3.2.2 (never to a source that does not define a single host):
  // "this network" 0/8, loopback 127/8, multicast 224/4, class E 240/4 and
  // 255.255.255.255.
  return first != 0 && first != 127 && first < 224;
}

TcpIcmpError tcp_icmp_error(const wire::IcmpHeader& h, const wire::IcmpQuote& q,
                            std::uint16_t current_pmtu, std::uint16_t min_pmtu) noexcept {
  TcpIcmpError e;
  e.type = h.type;
  e.code = h.code;
  e.tuple.local = Endpoint{q.ip.src, wire::load_be16(q.l4, 0)};
  e.tuple.remote = Endpoint{q.ip.dst, wire::load_be16(q.l4, 2)};
  e.seq = Seq32(wire::load_be32(q.l4, 4));  // RFC 5927 §4.1 check is the engine's
  if (h.type == wire::icmp_dest_unreach && h.code == wire::icmp_frag_needed) {
    e.new_pmtu =
        std::min(frag_needed_mtu(h.next_hop_mtu(), q.ip.total_len, min_pmtu), current_pmtu);
  }
  return e;
}

// --- IcmpRateLimiter

IcmpRateLimiter::IcmpRateLimiter(std::uint32_t rate_per_s, std::uint32_t burst) noexcept
    : rate_(rate_per_s), cap_(std::uint64_t{burst} * unit), credit_(cap_) {}

bool IcmpRateLimiter::allow(Time now) noexcept {
  if (now > stamp_) {
    const auto elapsed = static_cast<std::uint64_t>((now - stamp_).count());
    // rate_ tokens per second = rate_ units per nanosecond.
    if (rate_ != 0) {
      if (elapsed >= cap_ / rate_ + 1) {
        credit_ = cap_;
      } else {
        credit_ = std::min(cap_, credit_ + elapsed * rate_);
      }
    }
    stamp_ = now;
  }
  if (credit_ >= unit) {
    credit_ -= unit;
    return true;
  }
  return false;
}

// --- IcmpLayer

IcmpLayer::IcmpLayer(StackCore& core, UdpLayer& udp)
    : core_(core),
      udp_(udp),
      limiter_(core.config().icmp.rate_per_s, core.config().icmp.burst) {}

bool IcmpLayer::transmit(Ipv4Addr dst, const wire::IcmpHeader& h,
                         std::span<const std::byte> body) {
  if (!core_.can_transmit()) {
    return false;
  }
  auto buf = core_.alloc_packet(wire::icmp_header_len, static_cast<std::uint32_t>(body.size()));
  if (!buf) {
    return false;
  }
  std::copy(body.begin(), body.end(), buf->append(body.size()));
  buf->prepend(wire::icmp_header_len);
  wire::write_icmp(buf->bytes(), h);
  // RFC 6864 §4.1: atomic datagram, ID 0 (see the file comment).
  return core_.send_ipv4(dst, ip_proto_icmp, 0, std::move(*buf));
}

void IcmpLayer::on_message(const wire::Ipv4View& ip) {
  StackStats& st = core_.stats();
  ++st.IcmpInMsgs;
  const auto m = wire::parse_icmp(ip.payload, true);
  if (!m) {
    if (m.error() == wire::ParseError::bad_checksum) {
      ++st.IcmpInCsumErrors;  // Linux icmp_rcv: csum_error counts both
    }
    ++st.IcmpInErrors;
    return;
  }
  switch (m->h.type) {
    case wire::icmp_echo_request:
      ++st.IcmpInEchos;
      on_echo_request(ip, *m);
      break;
    case wire::icmp_echo_reply:
      ++st.IcmpInEchoReps;
      on_echo_reply(ip, *m);
      break;
    case wire::icmp_dest_unreach:
      ++st.IcmpInDestUnreachs;
      // Linux icmp_unreach: codes above NR_ICMP_UNREACH reach no protocol.
      if (m->h.code <= icmp_max_unreach_code) {
        on_error(*m);
      }
      break;
    case wire::icmp_time_exceeded:
      ++st.IcmpInTimeExcds;  // a soft error for TCP (§3.7)
      on_error(*m);
      break;
    case icmp_parameter_problem:
      ++st.IcmpInParmProbs;  // a soft error for TCP (RFC 1122 §4.2.3.9)
      on_error(*m);
      break;
    case wire::icmp_source_quench:
      ++st.IcmpInSrcQuenchs;  // RFC 6633 §2: ignored
      break;
    case wire::icmp_redirect:
      ++st.IcmpInRedirects;  // one interface, no routing: ignored (§3.7)
      break;
    default:
      break;  // other types are ignored
  }
}

void IcmpLayer::on_echo_request(const wire::Ipv4View& ip, const wire::IcmpView& m) {
  if (!core_.config().icmp.echo_reply || !is_unicast_source(ip.h.src)) {
    return;
  }
  StackStats& st = core_.stats();
  // RFC 1122 §3.2.2.6: the reply carries the request's identifier, sequence
  // number and data. It is never fragmented, so a reply larger than the path
  // MTU back to the sender (or than a packet buffer) is not sent.
  const std::size_t total = wire::ipv4_header_len + wire::icmp_header_len + m.body.size();
  if (total > core_.pmtu(ip.h.src) ||
      wire::icmp_header_len + m.body.size() > core_.max_l4_size()) {
    ++st.IcmpOutErrors;
    return;
  }
  const wire::IcmpHeader h = wire::icmp_echo_header(wire::icmp_echo_reply, m.h.echo_id(),
                                                    m.h.echo_seq());
  if (!transmit(ip.h.src, h, m.body)) {
    ++st.IpOutDiscards;  // §3.4: a control packet that does not fit is dropped
    return;
  }
  ++st.IcmpOutMsgs;
  ++st.IcmpOutEchoReps;
}

void IcmpLayer::on_echo_reply(const wire::Ipv4View& ip, const wire::IcmpView& m) {
  if (echo_count_ == echo_queue_capacity) {
    ++core_.stats().echo_replies_dropped;
    return;
  }
  EchoReply& r = echo_q_[(echo_head_ + echo_count_) % echo_queue_capacity];
  r = EchoReply{m.h.echo_id(), m.h.echo_seq(), ip.h.src, m.body.size(), core_.now()};
  ++echo_count_;
}

void IcmpLayer::on_error(const wire::IcmpView& m) {
  // §3.7: the quoted IPv4 header plus at least 8 bytes of the transport header.
  const auto q = wire::parse_icmp_quote(m.body);
  if (!q) {
    ++core_.stats().IcmpInErrors;
    return;
  }
  if (q->ip.src != core_.local_addr()) {
    return;  // not about a datagram we sent
  }
  const std::uint16_t min_pmtu = core_.config().tcp.min_pmtu;
  switch (q->ip.proto) {
    case ip_proto_tcp: {
      // §4.7, §4.13: the engine finds the connection, checks the quoted
      // sequence number (RFC 5927 §4.1) and then applies the error.
      const TcpIcmpError e = tcp_icmp_error(m.h, *q, core_.pmtu(q->ip.dst), min_pmtu);
      UTCP_CHECK(tcp_ != nullptr);
      tcp_->on_icmp_error(core_.now(), e);
      break;
    }
    case ip_proto_udp: {
      std::uint16_t frag = 0;
      if (m.h.type == wire::icmp_dest_unreach && m.h.code == wire::icmp_frag_needed) {
        frag = frag_needed_mtu(m.h.next_hop_mtu(), q->ip.total_len, min_pmtu);
      }
      udp_.on_icmp_error(m.h.type, m.h.code, wire::load_be16(q->l4, 0),
                         Endpoint{q->ip.dst, wire::load_be16(q->l4, 2)}, frag);
      break;
    }
    default:
      break;  // errors about our ICMP messages or other protocols: ignored
  }
}

void IcmpLayer::send_unreach(std::uint8_t code, const wire::Ipv4View& ip,
                             std::span<const std::byte> datagram) {
  StackStats& st = core_.stats();
  // RFC 1122 §3.2.2: no error to a source that does not define a single host.
  // (Errors about ICMP errors, fragments and non-unicast destinations cannot
  // arise: we generate errors only for UDP and unknown protocols, fragments
  // are dropped earlier, and the destination is the stack address.)
  if (!is_unicast_source(ip.h.src)) {
    return;
  }
  if (!limiter_.allow(core_.now())) {
    ++st.IcmpOutRateLimitGlobal;
    return;
  }
  // RFC 1812 §4.3.2.3, Linux icmp_send: quote as much as keeps the error
  // within 576 bytes and the path MTU.
  const std::size_t room = std::min<std::size_t>(core_.pmtu(ip.h.src), 576) -
                           wire::ipv4_header_len - wire::icmp_header_len;
  const auto quote = datagram.first(std::min(datagram.size(), room));
  if (!transmit(ip.h.src, wire::icmp_unreach_header(code), quote)) {
    ++st.IpOutDiscards;
    return;
  }
  ++st.IcmpOutMsgs;
  ++st.IcmpOutDestUnreachs;
}

std::expected<void, Error> IcmpLayer::echo(Ipv4Addr dst, std::uint16_t id, std::uint16_t seq,
                                           std::span<const std::byte> payload) {
  if (dst.v == 0) {
    return std::unexpected(Error::invalid_argument);
  }
  const std::size_t total = wire::ipv4_header_len + wire::icmp_header_len + payload.size();
  if (total > core_.pmtu(dst) || wire::icmp_header_len + payload.size() > core_.max_l4_size()) {
    return std::unexpected(Error::message_too_big);
  }
  if (!transmit(dst, wire::icmp_echo_header(wire::icmp_echo_request, id, seq), payload)) {
    return std::unexpected(Error::no_buffers);
  }
  ++core_.stats().IcmpOutMsgs;
  ++core_.stats().IcmpOutEchos;
  return {};
}

std::optional<EchoReply> IcmpLayer::poll_echo_reply() noexcept {
  if (echo_count_ == 0) {
    return std::nullopt;
  }
  const EchoReply r = echo_q_[echo_head_];
  echo_head_ = (echo_head_ + 1) % echo_queue_capacity;
  --echo_count_;
  return r;
}

void IcmpLayer::check_invariants() const {
  UTCP_CHECK(echo_head_ < echo_queue_capacity && echo_count_ <= echo_queue_capacity);
}

}  // namespace utcp
