#include "core/wire/tcp.hpp"

#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace utcp::wire {
namespace {

constexpr std::uint8_t len_mss = 4;
constexpr std::uint8_t len_wscale = 3;
constexpr std::uint8_t len_sack_perm = 2;
constexpr std::uint8_t len_timestamp = 10;
constexpr std::uint8_t len_sack_base = 2;
constexpr std::uint8_t len_sack_block = 8;

// One option of kind `kind` and total length `len` whose body starts at `at`
// (after the kind and length bytes). Known options with the wrong length are
// ignored, as Linux tcp_parse_options does.
void parse_one(std::span<const std::byte> b, std::size_t at, std::uint8_t kind, std::uint8_t len,
               TcpOptions& opt) noexcept {
  switch (kind) {
    case tcpopt_mss:
      if (len == len_mss) {
        opt.mss = load_be16(b, at);
      }
      break;
    case tcpopt_wscale:
      if (len == len_wscale) {
        opt.wscale = load_u8(b, at);
      }
      break;
    case tcpopt_sack_perm:
      if (len == len_sack_perm) {
        opt.sack_permitted = true;
      }
      break;
    case tcpopt_timestamp:
      if (len == len_timestamp) {
        opt.ts = Timestamps{load_be32(b, at), load_be32(b, at + 4)};
      }
      break;
    case tcpopt_sack:
      if (len >= len_sack_base + len_sack_block && (len - len_sack_base) % len_sack_block == 0) {
        const std::size_t n = static_cast<std::size_t>(len - len_sack_base) / len_sack_block;  // <= 4 in 40 bytes
        opt.sack_count = static_cast<std::uint8_t>(n);
        for (std::size_t i = 0; i < n; ++i) {
          opt.sack[i] = {Seq32(load_be32(b, at + i * len_sack_block)),
                         Seq32(load_be32(b, at + i * len_sack_block + 4))};
        }
      }
      break;
    default:
      break;  // unknown or unsupported (MD5, TFO, MPTCP, AccECN, ...): ignored, §1.2
  }
}

// Options occupy bytes [tcp_header_min_len, hlen) of `b`.
TcpOptions parse_options(std::span<const std::byte> b, std::size_t hlen) noexcept {
  TcpOptions opt;
  std::size_t i = tcp_header_min_len;
  while (i < hlen) {
    const std::uint8_t kind = load_u8(b, i);
    if (kind == tcpopt_eol) {
      break;
    }
    if (kind == tcpopt_nop) {
      ++i;
      continue;
    }
    // RFC 9293 §3.2 MUST-7: a malformed length must not crash; as Linux, stop
    // and treat the remaining options as absent (§4.4).
    if (hlen - i < 2) {
      opt.malformed = true;
      break;
    }
    const std::uint8_t len = load_u8(b, i + 1);
    if (len < 2 || len > hlen - i) {
      opt.malformed = true;
      break;
    }
    parse_one(b, i + 2, kind, len, opt);
    i += len;
  }
  return opt;
}

std::size_t options_len(const TcpOptions& opt, bool syn) noexcept {
  std::size_t n = 0;
  if (syn) {
    n += opt.mss ? 4u : 0u;
    n += opt.ts ? 12u : 0u;  // SACK_PERM, TS or NOP, NOP, TS
    n += (opt.sack_permitted && !opt.ts) ? 4u : 0u;  // NOP, NOP, SACK_PERM
    n += opt.wscale ? 4u : 0u;                       // NOP, WS
  } else {
    UTCP_CHECK(opt.sack_count <= (opt.ts ? max_sack_blocks_with_ts : max_sack_blocks));
    n += opt.ts ? 12u : 0u;  // NOP, NOP, TS
    n += opt.sack_count > 0 ? 4u + std::size_t{len_sack_block} * opt.sack_count : 0u;
  }
  return n;
}

}  // namespace

std::expected<TcpView, ParseError> parse_tcp(std::span<const std::byte> seg, Ipv4Addr src,
                                             Ipv4Addr dst, bool verify_csum) noexcept {
  if (seg.size() < tcp_header_min_len) {
    return std::unexpected(ParseError::truncated);
  }
  const auto doff = static_cast<std::uint8_t>(load_u8(seg, 12) >> 4);
  const std::size_t hlen = std::size_t{doff} * 4;
  if (doff < 5 || hlen > seg.size()) {
    return std::unexpected(ParseError::bad_data_offset);
  }
  UTCP_CHECK(seg.size() <= 0xffff);  // an IPv4 payload
  if (verify_csum && !ipv4_transport_checksum_valid(src.v, dst.v, ip_proto_tcp, seg)) {
    return std::unexpected(ParseError::bad_checksum);
  }
  TcpView v;
  v.data_offset = doff;
  v.h.sport = load_be16(seg, 0);
  v.h.dport = load_be16(seg, 2);
  v.h.seq = Seq32(load_be32(seg, 4));
  v.h.ack = Seq32(load_be32(seg, 8));
  v.h.flags = static_cast<std::uint16_t>(load_be16(seg, 12) & tcp_all_flags);
  v.h.window = load_be16(seg, 14);
  v.h.urg = load_be16(seg, 18);
  v.opt = parse_options(seg, hlen);
  v.payload = seg.subspan(hlen);
  return v;
}

std::size_t tcp_header_len(const TcpOptions& opt, bool syn) noexcept {
  return tcp_header_min_len + options_len(opt, syn);
}

void write_tcp_header(std::span<std::byte> out, const TcpHeader& h, const TcpOptions& opt,
                      bool syn) noexcept {
  const std::size_t hlen = tcp_header_len(opt, syn);
  UTCP_CHECK(out.size() >= hlen);
  const std::span<std::byte> o = out.first(hlen);
  store_be16(o, 0, h.sport);
  store_be16(o, 2, h.dport);
  store_be32(o, 4, h.seq.raw());
  store_be32(o, 8, h.ack.raw());
  // Data offset in the top 4 bits, then the 12 flag bits.
  store_be16(o, 12,
             static_cast<std::uint16_t>(((hlen / 4) << 12) | (h.flags & tcp_all_flags)));
  store_be16(o, 14, h.window);
  store_be16(o, 16, 0);
  store_be16(o, 18, h.urg);

  // The option layout of Linux tcp_options_write (§4.5).
  std::size_t at = tcp_header_min_len;
  auto put4 = [&](std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    store_u8(o, at, a);
    store_u8(o, at + 1, b);
    store_u8(o, at + 2, c);
    store_u8(o, at + 3, d);
    at += 4;
  };
  auto put32 = [&](std::uint32_t v) {
    store_be32(o, at, v);
    at += 4;
  };
  if (syn && opt.mss) {
    put4(tcpopt_mss, len_mss, static_cast<std::uint8_t>(*opt.mss >> 8),
         static_cast<std::uint8_t>(*opt.mss & 0xffu));
  }
  if (opt.ts) {
    if (syn && opt.sack_permitted) {
      put4(tcpopt_sack_perm, len_sack_perm, tcpopt_timestamp, len_timestamp);
    } else {
      put4(tcpopt_nop, tcpopt_nop, tcpopt_timestamp, len_timestamp);
    }
    put32(opt.ts->val);
    put32(opt.ts->ecr);
  }
  if (syn && opt.sack_permitted && !opt.ts) {
    put4(tcpopt_nop, tcpopt_nop, tcpopt_sack_perm, len_sack_perm);
  }
  if (syn && opt.wscale) {
    put4(tcpopt_nop, tcpopt_wscale, len_wscale, *opt.wscale);
  }
  if (!syn && opt.sack_count > 0) {
    put4(tcpopt_nop, tcpopt_nop, tcpopt_sack,
         static_cast<std::uint8_t>(len_sack_base + len_sack_block * opt.sack_count));
    for (std::size_t i = 0; i < opt.sack_count; ++i) {
      put32(opt.sack[i].first.raw());
      put32(opt.sack[i].second.raw());
    }
  }
  UTCP_CHECK(at == hlen);
}

}  // namespace utcp::wire
