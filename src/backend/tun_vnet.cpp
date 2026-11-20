#include "utcp/tun_device.hpp"

#include <bit>
#include <algorithm>

#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "core/wire/udp.hpp"
#include "utcp/checksum.hpp"

namespace utcp {
namespace {

// Linux UAPI virtio_net_hdr (include/uapi/linux/virtio_net.h).
// Serialize explicitly so the unaligned prefix has no C++ struct dependency.
constexpr std::size_t flags_at = 0;
constexpr std::size_t gso_type_at = 1;
constexpr std::size_t hdr_len_at = 2;
constexpr std::size_t gso_size_at = 4;
constexpr std::size_t csum_start_at = 6;
constexpr std::size_t csum_offset_at = 8;
constexpr std::uint8_t needs_csum = 1;
constexpr std::uint8_t data_valid = 2;
constexpr std::uint8_t gso_none = 0;
constexpr std::uint8_t gso_tcpv4 = 1;
constexpr std::size_t max_ipv4 = 65535;
constexpr std::uint16_t tcp_csum_offset = 16;
constexpr std::uint16_t udp_csum_offset = 6;

std::uint16_t load_le16(std::span<const std::byte> bytes, std::size_t at) noexcept {
  return std::byteswap(wire::load_be16(bytes, at));
}

void store_le16(std::span<std::byte> bytes, std::size_t at, std::uint16_t value) noexcept {
  wire::store_be16(bytes, at, std::byteswap(value));
}

std::size_t ipv4_header_size(std::span<const std::byte> ip) noexcept {
  return (wire::load_u8(ip, 0) & 0xfu) * 4u;
}

std::size_t tcp_header_size(std::span<const std::byte> tcp) noexcept {
  return (wire::load_u8(tcp, 12) >> 4) * 4u;
}

}  // namespace

std::optional<TunRxPacket> decode_tun_vnet(std::span<const std::byte> frame,
                                          TunOffload offload) noexcept {
  if (offload == TunOffload::legacy || frame.size() <= tun_vnet_header_size ||
      frame.size() > max_ipv4 + tun_vnet_header_size) {
    return std::nullopt;
  }
  const auto flags = wire::load_u8(frame, flags_at);
  const auto gso_type = wire::load_u8(frame, gso_type_at);
  const auto stride = load_le16(frame, gso_size_at);
  const auto csum_start = load_le16(frame, csum_start_at);
  const auto csum_offset = load_le16(frame, csum_offset_at);
  const bool partial = flags == needs_csum;
  const bool valid = flags == data_valid;
  const bool aggregate = gso_type != gso_none;
  if ((flags != 0 && !partial && !valid) ||
      (aggregate && (offload != TunOffload::tcpv4 || gso_type != gso_tcpv4 ||
                     (!partial && !valid))) ||
      (aggregate != (stride != 0)) || (!partial && (csum_start != 0 || csum_offset != 0))) {
    return std::nullopt;
  }
  const auto ip = frame.subspan(tun_vnet_header_size);
  if (load_le16(frame, hdr_len_at) > ip.size()) {
    return std::nullopt;
  }
  if (!valid && !partial) {
    return TunRxPacket{ip, {}};
  }

  // The IPv4 layer still validates the IP checksum. Grant transport checksum
  // trust only for an exact, unfragmented TCP or UDP frame.
  if (ip.size() < wire::ipv4_header_len) {
    return std::nullopt;
  }
  if ((wire::load_u8(ip, 0) >> 4) != 4) {
    return valid && !aggregate ? std::optional(TunRxPacket{ip, {}}) : std::nullopt;
  }
  const std::size_t ihl = ipv4_header_size(ip);
  if (ihl < wire::ipv4_header_len || ihl >= ip.size() ||
      wire::load_be16(ip, 2) != ip.size() || (wire::load_be16(ip, 6) & 0x3fffu) != 0) {
    return std::nullopt;
  }
  const auto l4 = ip.subspan(ihl);
  const auto proto = wire::load_u8(ip, 9);
  std::uint16_t checksum_offset;
  std::size_t transport_header;
  if (proto == ip_proto_tcp) {
    if (l4.size() < wire::tcp_header_min_len) {
      return std::nullopt;
    }
    transport_header = tcp_header_size(l4);
    if (transport_header < wire::tcp_header_min_len || transport_header > l4.size()) {
      return std::nullopt;
    }
    checksum_offset = tcp_csum_offset;
  } else if (proto == ip_proto_udp && !aggregate) {
    transport_header = wire::udp_header_len;
    if (l4.size() < transport_header || wire::load_be16(l4, 4) != l4.size()) {
      return std::nullopt;
    }
    checksum_offset = udp_csum_offset;
  } else {
    return valid && !aggregate ? std::optional(TunRxPacket{ip, {}}) : std::nullopt;
  }
  if (partial && (csum_start != ihl || csum_offset != checksum_offset)) {
    return std::nullopt;
  }
  if (aggregate) {
    // hdr_len is a linearization hint on reads, not the payload offset.
    // A merged ACK stream may have a final PSH/FIN.
    constexpr auto allowed = wire::tcp_ack | wire::tcp_psh | wire::tcp_fin;
    const auto tcp_flags = wire::load_be16(l4, 12) & wire::tcp_all_flags;
    if (l4.size() - transport_header <= stride || (tcp_flags & ~allowed) != 0 ||
        (tcp_flags & wire::tcp_ack) == 0) {
      return std::nullopt;
    }
  }
  RxMeta meta{valid, partial, stride};
  return TunRxPacket{ip, meta, meta.segments(l4.size() - transport_header)};
}

std::uint32_t prepend_tun_vnet(TxPacket& packet) noexcept {
  const auto ip = std::as_const(packet.buf).bytes();
  auto hdr = std::span(packet.buf.prepend(tun_vnet_header_size), tun_vnet_header_size);
  std::ranges::fill(hdr, std::byte{});
  std::uint32_t segments = 1;
  if (packet.csum_partial) {
    const auto ihl = static_cast<std::uint16_t>(ipv4_header_size(ip));
    wire::store_u8(hdr, flags_at, needs_csum);
    store_le16(hdr, csum_start_at, ihl);
    store_le16(hdr, csum_offset_at, tcp_csum_offset);
    if (packet.gso_size != 0) {
      const auto headers = static_cast<std::uint16_t>(ihl + tcp_header_size(ip.subspan(ihl)));
      wire::store_u8(hdr, gso_type_at, gso_tcpv4);
      store_le16(hdr, gso_size_at, packet.gso_size);
      store_le16(hdr, hdr_len_at, headers);
      segments = 1 + static_cast<std::uint32_t>(ip.size() - headers - 1) / packet.gso_size;
    }
  }
  return segments;
}

}  // namespace utcp
