// libFuzzer target for TCP option parsing (DESIGN §4.4, §11 Fuzz). The input
// is the option area of a segment (at most 40 bytes, padded with EOL to a
// multiple of 4). parse_tcp's options are compared with a second, separate
// transcription of Linux tcp_parse_options (net/ipv4/tcp_input.c) kept here,
// then written with write_tcp_header (SYN and non-SYN layouts) and parsed
// back. A mismatch aborts through UTCP_CHECK.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "utcp/check.hpp"
#include "utcp/checksum.hpp"

namespace {

namespace w = utcp::wire;
using utcp::Ipv4Addr;
using utcp::Seq32;

const Ipv4Addr src_addr = Ipv4Addr::from_octets(10, 0, 0, 1);
const Ipv4Addr dst_addr = Ipv4Addr::from_octets(10, 0, 0, 2);

std::uint32_t be32(const std::uint8_t* p) {
  return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) |
         std::uint32_t{p[3]};
}

// tcp_parse_options, with every option accepted whatever the segment flags
// and sysctls (those checks are the engine's, §4.5) and with `malformed` for
// the two "return" paths on a bad length.
w::TcpOptions reference_parse(const std::uint8_t* ptr, int length) {
  w::TcpOptions o;
  while (length > 0) {
    const int opcode = *ptr++;
    if (opcode == 0) {  // TCPOPT_EOL
      return o;
    }
    if (opcode == 1) {  // TCPOPT_NOP
      length--;
      continue;
    }
    if (length < 2) {
      o.malformed = true;
      return o;
    }
    const int opsize = *ptr++;
    if (opsize < 2 || opsize > length) {  // "silly options", "don't parse partial options"
      o.malformed = true;
      return o;
    }
    switch (opcode) {
      case 2:  // TCPOPT_MSS, TCPOLEN_MSS 4
        if (opsize == 4) {
          o.mss = static_cast<std::uint16_t>((ptr[0] << 8) | ptr[1]);
        }
        break;
      case 3:  // TCPOPT_WINDOW, TCPOLEN_WINDOW 3
        if (opsize == 3) {
          o.wscale = ptr[0];
        }
        break;
      case 4:  // TCPOPT_SACK_PERM, TCPOLEN_SACK_PERM 2
        if (opsize == 2) {
          o.sack_permitted = true;
        }
        break;
      case 8:  // TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP 10
        if (opsize == 10) {
          o.ts = w::Timestamps{be32(ptr), be32(ptr + 4)};
        }
        break;
      case 5:  // TCPOPT_SACK: TCPOLEN_SACK_BASE 2 + n * TCPOLEN_SACK_PERBLOCK 8
        if (opsize >= 10 && (opsize - 2) % 8 == 0) {
          o.sack = {};
          o.sack_count = static_cast<std::uint8_t>((opsize - 2) / 8);
          for (int i = 0; i < o.sack_count; ++i) {
            o.sack[static_cast<std::size_t>(i)] = {Seq32(be32(ptr + 8 * i)),
                                                   Seq32(be32(ptr + 8 * i + 4))};
          }
        }
        break;
      default:
        break;
    }
    ptr += opsize - 2;
    length -= opsize;
  }
  return o;
}

std::vector<std::byte> segment(const w::TcpHeader& h, std::span<const std::uint8_t> options) {
  std::vector<std::byte> s(w::tcp_header_min_len + options.size());
  w::write_tcp_header(s, h, w::TcpOptions{}, false);
  // Byte 12 holds the data offset and the top four flag bits (AE, reserved).
  w::store_u8(s, 12, static_cast<std::uint8_t>(((s.size() / 4) << 4) | ((h.flags >> 8) & 0x0fu)));
  std::ranges::transform(options, s.begin() + w::tcp_header_min_len,
                         [](std::uint8_t b) { return std::byte{b}; });
  w::set_l4_checksum(s, src_addr, dst_addr, utcp::ip_proto_tcp);
  return s;
}

void write_and_reparse(const w::TcpHeader& h, const w::TcpOptions& parsed, bool syn) {
  w::TcpOptions want;
  want.ts = parsed.ts;
  if (syn) {
    want.mss = parsed.mss;
    want.wscale = parsed.wscale;
    want.sack_permitted = parsed.sack_permitted;
  } else {
    want.sack_count = parsed.sack_count;
    std::copy_n(parsed.sack.begin(), parsed.sack_count, want.sack.begin());
  }
  w::TcpHeader hh = h;
  hh.flags = static_cast<std::uint16_t>(syn ? (h.flags | w::tcp_syn) : (h.flags & ~w::tcp_syn));
  std::vector<std::byte> buf(w::tcp_header_len(want, syn));
  UTCP_CHECK(buf.size() <= w::tcp_header_max_len && buf.size() % 4 == 0);
  w::write_tcp_header(buf, hh, want, syn);
  w::set_l4_checksum(buf, src_addr, dst_addr, utcp::ip_proto_tcp);
  const auto r = w::parse_tcp(buf, src_addr, dst_addr, true);
  UTCP_CHECK(r.has_value());
  UTCP_CHECK(r->h == hh);
  UTCP_CHECK(r->opt == want);
  UTCP_CHECK(r->opt == reference_parse(reinterpret_cast<const std::uint8_t*>(buf.data()) + 20,
                                       static_cast<int>(buf.size()) - 20));
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 2) {
    return 0;
  }
  // Byte 0 and 1: flags (12 bits); the rest: the option area.
  w::TcpHeader h;
  h.sport = 1;
  h.dport = 2;
  h.seq = Seq32(0x01020304);
  h.ack = Seq32(0x05060708);
  h.window = 1000;
  h.flags = static_cast<std::uint16_t>(((data[0] << 8) | data[1]) & w::tcp_all_flags);
  std::vector<std::uint8_t> options(data + 2, data + std::min<std::size_t>(size, 42));
  while (options.size() % 4 != 0) {
    options.push_back(0);  // EOL padding
  }

  const auto seg = segment(h, options);
  const auto v = w::parse_tcp(seg, src_addr, dst_addr, true);
  UTCP_CHECK(v.has_value());
  UTCP_CHECK(v->h == h);
  UTCP_CHECK(v->payload.empty());
  const w::TcpOptions ref = reference_parse(options.data(), static_cast<int>(options.size()));
  UTCP_CHECK(v->opt == ref);

  // 40 option bytes cannot hold TS and four SACK blocks, so the non-SYN
  // writer's precondition always holds for parsed options.
  UTCP_CHECK(v->opt.sack_count <= (v->opt.ts ? w::max_sack_blocks_with_ts : w::max_sack_blocks));
  write_and_reparse(h, v->opt, true);
  write_and_reparse(h, v->opt, false);
  return 0;
}
