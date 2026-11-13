#include "core/udp.hpp"

#include <algorithm>
#include <array>
#include <functional>

#include "core/stack_impl.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/udp.hpp"
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp {

UdpLayer::UdpLayer(StackCore& core) : core_(core) {}

UdpLayer::~UdpLayer() = default;

UdpLayer::Socket* UdpLayer::find(Handle h) noexcept {
  if (h.proto != Proto::udp || h.slot >= slots_.size()) {
    return nullptr;
  }
  Socket& s = slots_[h.slot];
  return s.open && s.gen == h.gen ? &s : nullptr;
}

const UdpLayer::Socket* UdpLayer::find(Handle h) const noexcept {
  return const_cast<UdpLayer*>(this)->find(h);
}

std::optional<std::uint32_t> UdpLayer::bound_slot(std::uint16_t port) const noexcept {
  const auto it = std::lower_bound(bound_.begin(), bound_.end(), port,
                                   [](const auto& e, std::uint16_t p) { return e.first < p; });
  if (it != bound_.end() && it->first == port) {
    return it->second;
  }
  return std::nullopt;
}

bool UdpLayer::port_bound(std::uint16_t port) const noexcept {
  return bound_slot(port).has_value();
}

void UdpLayer::bind(std::uint16_t port, std::uint32_t slot) {
  const auto it = std::lower_bound(bound_.begin(), bound_.end(), port,
                                   [](const auto& e, std::uint16_t p) { return e.first < p; });
  UTCP_CHECK(it == bound_.end() || it->first != port);
  bound_.insert(it, {port, slot});
}

void UdpLayer::unbind(std::uint16_t port) {
  const auto it = std::lower_bound(bound_.begin(), bound_.end(), port,
                                   [](const auto& e, std::uint16_t p) { return e.first < p; });
  UTCP_CHECK(it != bound_.end() && it->first == port);
  bound_.erase(it);
}

std::expected<Handle, Error> UdpLayer::open(Endpoint local) {
  if (local.addr.v != 0 && local.addr != core_.local_addr()) {
    return std::unexpected(Error::addr_not_available);
  }
  std::uint16_t port = local.port;
  if (port == 0) {
    // RFC 6056 §3.3.4 Algorithm 4 over the UDP range, rejecting bound ports.
    auto p = core_.udp_ephemeral_port([this](std::uint16_t c) { return port_bound(c); });
    if (!p) {
      return std::unexpected(p.error());
    }
    port = *p;
  } else if (port_bound(port)) {
    return std::unexpected(Error::addr_in_use);
  }
  if (!core_.reserve_slot()) {
    return std::unexpected(Error::no_buffers);
  }
  std::uint32_t slot = 0;
  if (!free_.empty()) {
    std::pop_heap(free_.begin(), free_.end(), std::greater<>{});
    slot = free_.back();
    free_.pop_back();
  } else {
    slot = static_cast<std::uint32_t>(slots_.size());
    slots_.emplace_back();
  }
  Socket& s = slots_[slot];
  ++s.gen;
  s.open = true;
  s.port = port;
  s.rcv.emplace(core_.chunks(), core_.config().udp.rcv_buf, 0);
  s.head = s.tail = 0;
  s.datagrams = 0;
  bind(port, slot);
  ++open_;
  return Handle{slot, s.gen, Proto::udp};
}

std::expected<void, Error> UdpLayer::close(Handle h) {
  Socket* s = find(h);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  unbind(s->port);
  s->rcv.reset();  // returns the chunks
  s->open = false;
  s->port = 0;
  s->head = s->tail = 0;
  s->datagrams = 0;
  core_.drop_events(h);
  free_.push_back(h.slot);
  std::push_heap(free_.begin(), free_.end(), std::greater<>{});
  core_.release_slot();
  --open_;
  return {};
}

std::expected<void, Error> UdpLayer::send_to(Handle h, Endpoint remote,
                                             std::span<const std::byte> data) {
  Socket* s = find(h);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (remote.addr.v == 0 || remote.port == 0) {
    return std::unexpected(Error::invalid_argument);
  }
  // §3.6: no fragmentation; the datagram must fit the path MTU.
  const std::size_t total = wire::ipv4_header_len + wire::udp_header_len + data.size();
  if (data.size() > max_payload || total > core_.pmtu(remote.addr)) {
    return std::unexpected(Error::message_too_big);
  }
  if (!core_.can_transmit()) {
    ++core_.stats().UdpSndbufErrors;
    return std::unexpected(Error::no_buffers);
  }
  const auto len = static_cast<std::uint32_t>(data.size());
  auto buf = core_.alloc_packet(wire::udp_header_len, len);
  if (!buf) {
    ++core_.stats().UdpSndbufErrors;
    return std::unexpected(Error::no_buffers);
  }
  std::copy(data.begin(), data.end(), buf->append(data.size()));
  buf->prepend(wire::udp_header_len);
  const std::span<std::byte> l4 = buf->bytes();
  wire::write_udp_header(l4, wire::UdpHeader{s->port, remote.port,
                                             static_cast<std::uint16_t>(l4.size()), 0});
  // RFC 768: checksum always sent, a computed 0 as 0xFFFF.
  wire::set_l4_checksum(l4, core_.local_addr(), remote.addr, ip_proto_udp);
  // RFC 6864 §4.1: an atomic datagram; ID 0 as Linux ip_select_ident_segs for
  // DF datagrams of unconnected sockets.
  if (!core_.send_ipv4(remote.addr, ip_proto_udp, 0, std::move(*buf))) {
    ++core_.stats().UdpSndbufErrors;
    return std::unexpected(Error::no_buffers);
  }
  ++core_.stats().UdpOutDatagrams;
  return {};
}

std::expected<UdpRecv, Error> UdpLayer::recv_from(Handle h, std::span<std::byte> out) {
  Socket* s = find(h);
  if (s == nullptr) {
    return std::unexpected(Error::bad_handle);
  }
  if (s->datagrams == 0) {
    return std::unexpected(Error::would_block);
  }
  std::array<std::byte, record_header_len> hdr{};
  s->rcv->read_at(s->head, hdr);
  UdpRecv r;
  r.from = Endpoint{Ipv4Addr{wire::load_be32(hdr, 0)}, wire::load_be16(hdr, 4)};
  r.len = wire::load_be16(hdr, 6);
  const std::size_t n = std::min(r.len, out.size());
  r.truncated = n < r.len;
  s->rcv->read_at(s->head + record_header_len, out.first(n));
  const std::uint64_t rec = record_header_len + std::uint64_t{r.len};
  s->rcv->consume(rec);
  s->head += rec;
  --s->datagrams;
  return r;
}

bool UdpLayer::enqueue(Socket& s, Endpoint from, std::span<const std::byte> payload) {
  ByteRing& ring = *s.rcv;
  const std::uint64_t rec = record_header_len + payload.size();
  // §3.6: datagrams are stored length-prefixed; one that does not fit in the
  // free space of the rcv_buf-byte ring is dropped.
  if (s.tail + rec > ring.limit()) {
    return false;
  }
  std::array<std::byte, record_header_len> hdr{};
  wire::store_be32(hdr, 0, from.addr.v);
  wire::store_be16(hdr, 4, from.port);
  wire::store_be16(hdr, 6, static_cast<std::uint16_t>(payload.size()));
  if (ring.write_at(s.tail, hdr) != hdr.size() ||
      ring.write_at(s.tail + record_header_len, payload) != payload.size()) {
    ring.release_from(s.tail);  // chunk pool exhausted: forget the partial record
    return false;
  }
  s.tail += rec;
  ++s.datagrams;
  return true;
}

UdpLayer::Input UdpLayer::on_datagram(const wire::Ipv4View& ip, RxMeta meta) {
  StackStats& st = core_.stats();
  const bool verify = !(meta.csum_verified || meta.csum_partial);
  const auto u = wire::parse_udp(ip.payload, ip.h.src, ip.h.dst, verify);
  if (!u) {
    if (u.error() == wire::ParseError::bad_checksum) {
      ++st.UdpInCsumErrors;
    }
    ++st.UdpInErrors;
    return Input::dropped;
  }
  const auto slot = bound_slot(u->h.dport);
  if (!slot) {
    ++st.UdpNoPorts;
    return Input::no_port;
  }
  Socket& s = slots_[*slot];
  if (!enqueue(s, Endpoint{ip.h.src, u->h.sport}, u->payload)) {
    ++st.UdpRcvbufErrors;
    ++st.UdpInErrors;
    return Input::dropped;
  }
  ++st.UdpInDatagrams;
  core_.raise_event(Handle{*slot, s.gen, Proto::udp}, ev_readable);
  return Input::delivered;
}

void UdpLayer::on_icmp_error(std::uint8_t type, std::uint8_t code, std::uint16_t local_port,
                             Endpoint remote, std::uint16_t frag_mtu) {
  ++core_.stats().udp_icmp_errors;
  // Linux __udp4_lib_err: frag-needed for a datagram of a bound socket updates
  // the route's PMTU (ipv4_sk_update_pmtu); errors are not reported (§3.6).
  if (type == wire::icmp_dest_unreach && code == wire::icmp_frag_needed && frag_mtu != 0 &&
      port_bound(local_port)) {
    core_.pmtu_lower(remote.addr, frag_mtu);
  }
}

std::uint32_t UdpLayer::queued(Handle h) const noexcept {
  const Socket* s = find(h);
  return s != nullptr ? s->datagrams : 0;
}

void UdpLayer::check_invariants() const {
  UTCP_CHECK(std::is_heap(free_.begin(), free_.end(), std::greater<>{}));
  std::vector<std::uint8_t> is_free(slots_.size(), 0);
  for (const std::uint32_t f : free_) {
    UTCP_CHECK(f < slots_.size() && is_free[f] == 0 && !slots_[f].open);
    is_free[f] = 1;
  }
  for (std::size_t i = 1; i < bound_.size(); ++i) {
    UTCP_CHECK(bound_[i - 1].first < bound_[i].first);
  }
  std::uint32_t open = 0;
  for (std::uint32_t i = 0; i < slots_.size(); ++i) {
    const Socket& s = slots_[i];
    if (!s.open) {
      UTCP_CHECK(is_free[i] == 1 && !s.rcv.has_value());
      continue;
    }
    ++open;
    const auto b = bound_slot(s.port);
    UTCP_CHECK(b.has_value() && *b == i);
    UTCP_CHECK(s.rcv.has_value());
    const ByteRing& ring = *s.rcv;
    UTCP_CHECK(ring.begin() == s.head && s.head <= s.tail && s.tail <= ring.limit());
    // Walk the records.
    std::uint64_t at = s.head;
    std::uint32_t n = 0;
    while (at < s.tail) {
      std::array<std::byte, record_header_len> hdr{};
      ring.read_at(at, hdr);
      at += record_header_len + wire::load_be16(hdr, 6);
      ++n;
    }
    UTCP_CHECK(at == s.tail && n == s.datagrams);
  }
  UTCP_CHECK(open == open_ && bound_.size() == open_);
}

}  // namespace utcp
