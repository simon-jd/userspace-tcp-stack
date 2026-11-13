#include "core/ip.hpp"

#include <utility>

#include "core/stack_impl.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp {

void ip_input(StackImpl& s, std::span<const std::byte> datagram, RxMeta meta) {
  StackCore& core = s.core;
  StackStats& st = core.stats();
  ++st.IpInReceives;
  const auto v = wire::parse_ipv4(datagram);
  if (!v) {
    switch (v.error()) {
      case wire::ParseError::truncated: {
        // parse_ipv4 reports both a buffer shorter than the header and a
        // total length beyond the buffer as truncated; Linux ip_rcv_core
        // counts the first as a header error, the second in
        // IPSTATS_MIB_INTRUNCATEDPKTS.
        const bool header_present =
            datagram.size() >= wire::ipv4_header_len &&
            datagram.size() >= std::size_t{wire::load_u8(datagram, 0) & 0x0fu} * 4;
        if (header_present) {
          ++st.IpExtInTruncatedPkts;
        } else {
          ++st.IpInHdrErrors;
        }
        break;
      }
      case wire::ParseError::bad_checksum:
        ++st.IpExtInCsumErrors;
        ++st.IpInHdrErrors;
        break;
      case wire::ParseError::fragment:
        ++st.frag_dropped;  // §1.2: no reassembly
        break;
      default:  // bad_version, bad_ihl, bad_length
        ++st.IpInHdrErrors;
        break;
    }
    return;
  }
  const wire::Ipv4View& ip = *v;
  // §4.4: one endpoint, one address; no forwarding, broadcast or multicast.
  if (ip.h.dst != core.local_addr()) {
    ++st.IpInAddrErrors;
    return;
  }
  // The datagram without link padding, as ICMP errors quote it.
  const std::span<const std::byte> whole = datagram.first(ip.h.total_len);
  switch (ip.h.proto) {
    case ip_proto_icmp:
      ++st.IpInDelivers;
      s.icmp.on_message(ip);
      return;
    case ip_proto_udp:
      ++st.IpInDelivers;
      if (s.udp.on_datagram(ip, meta) == UdpLayer::Input::no_port) {
        s.icmp.send_unreach(wire::icmp_port_unreach, ip, whole);  // RFC 1122 §4.1.3.1
      }
      return;
    case ip_proto_tcp: {
      ++st.IpInDelivers;
      ++st.TcpInSegs;
      // §4.4: the checksum is verified unless the host did (M4 offload).
      const bool verify = !(meta.csum_verified || meta.csum_partial);
      const auto seg = wire::parse_tcp(ip.payload, ip.h.src, ip.h.dst, verify);
      if (!seg) {
        if (seg.error() == wire::ParseError::bad_checksum) {
          ++st.TcpInCsumErrors;
        }
        ++st.TcpInErrs;
        return;
      }
      s.tcp.on_segment(core.now(), ip.h, *seg, meta);
      return;
    }
    default:
      ++st.IpInUnknownProtos;
      s.icmp.send_unreach(wire::icmp_proto_unreach, ip, whole);  // RFC 1122 §3.2.2.1
      return;
  }
}

bool StackCore::send_ipv4(Ipv4Addr dst, std::uint8_t proto, std::uint16_t ip_id, PacketBuf&& l4,
                          std::optional<std::uint32_t> owner_slot) {
  PacketBuf buf = std::move(l4);
  UTCP_CHECK(buf.valid());
  if (txq_.full()) {
    ++stats_.IpOutDiscards;
    return false;  // `buf` returns to the pool
  }
  const std::size_t total = buf.size() + wire::ipv4_header_len;
  // §1.2: DF on every datagram, never larger than the path MTU (the
  // producers check; the interface MTU bounds every path).
  UTCP_DCHECK(total <= cfg_.mtu);
  UTCP_CHECK(total <= 0xffff);
  wire::Ipv4Header h;
  h.tos = 0;
  h.ttl = cfg_.ip_ttl;
  h.proto = proto;
  h.total_len = static_cast<std::uint16_t>(total);
  h.id = ip_id;
  h.df = true;
  h.src = cfg_.local_addr;
  h.dst = dst;
  wire::write_ipv4(std::span<std::byte>(buf.prepend(wire::ipv4_header_len), wire::ipv4_header_len),
                   h);
  txq_.push(TxPacket{std::move(buf), 0, false}, owner_slot);
  ++stats_.IpOutRequests;
  return true;
}

}  // namespace utcp
