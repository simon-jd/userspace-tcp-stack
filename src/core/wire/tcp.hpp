// TCP header and options (RFC 9293 §3.1; options RFC 9293 §3.2, RFC 7323,
// RFC 2018; DESIGN §3.10, §4.5). The checksum is set with set_l4_checksum
// (core/wire/ipv4.hpp).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <utility>

#include "core/wire/ipv4.hpp"
#include "utcp/seq.hpp"
#include "utcp/types.hpp"

namespace utcp::wire {

inline constexpr std::size_t tcp_header_min_len = 20;
inline constexpr std::size_t tcp_header_max_len = 60;

// TcpHeader::flags. Bits 0-7 are byte 13 of the header (FIN..CWR), bit 8 is
// AE (AccECN; the former NS bit of RFC 3540) and bits 9-11 are the reserved
// bits of byte 12.
// The parser reports all twelve; write_tcp_header writes all twelve, so the
// engine sends AE and the reserved bits as zero by leaving them clear.
inline constexpr std::uint16_t tcp_fin = 0x001;
inline constexpr std::uint16_t tcp_syn = 0x002;
inline constexpr std::uint16_t tcp_rst = 0x004;
inline constexpr std::uint16_t tcp_psh = 0x008;
inline constexpr std::uint16_t tcp_ack = 0x010;
inline constexpr std::uint16_t tcp_urg = 0x020;
inline constexpr std::uint16_t tcp_ece = 0x040;
inline constexpr std::uint16_t tcp_cwr = 0x080;
inline constexpr std::uint16_t tcp_ae = 0x100;
inline constexpr std::uint16_t tcp_reserved_flags = 0xe00;
inline constexpr std::uint16_t tcp_all_flags = 0xfff;

// Option kinds (IANA "TCP Option Kind Numbers").
inline constexpr std::uint8_t tcpopt_eol = 0;
inline constexpr std::uint8_t tcpopt_nop = 1;
inline constexpr std::uint8_t tcpopt_mss = 2;
inline constexpr std::uint8_t tcpopt_wscale = 3;
inline constexpr std::uint8_t tcpopt_sack_perm = 4;
inline constexpr std::uint8_t tcpopt_sack = 5;
inline constexpr std::uint8_t tcpopt_timestamp = 8;

inline constexpr std::size_t max_sack_blocks = 4;        // 2 + 4 * 8 = 34 bytes fit in 40
inline constexpr std::size_t max_sack_blocks_with_ts = 3;  // with the 12 bytes of NOP, NOP, TS

struct Timestamps {
  std::uint32_t val = 0, ecr = 0;

  constexpr bool operator==(const Timestamps&) const = default;
};

// Options of one segment. Parsed values are reported as they are on the
// wire: an MSS of 0 or a window scale above 14 is the engine's to interpret
// (§4.5), and MSS, window scale and SACK-permitted are reported on any
// segment, not only on a SYN.
struct TcpOptions {
  std::optional<std::uint16_t> mss;
  std::optional<std::uint8_t> wscale;
  bool sack_permitted = false;
  std::optional<Timestamps> ts;
  std::array<std::pair<Seq32, Seq32>, max_sack_blocks> sack{};  // [begin, end) per block
  std::uint8_t sack_count = 0;
  // Option parsing stopped at a malformed option (length 0 or 1, or running
  // past the header); options before it are kept, the rest are absent (§4.4,
  // as Linux tcp_parse_options).
  bool malformed = false;

  constexpr bool operator==(const TcpOptions&) const = default;
};

struct TcpHeader {
  std::uint16_t sport = 0, dport = 0;
  Seq32 seq, ack;
  std::uint16_t window = 0;  // the raw field; scaling is the engine's
  std::uint16_t urg = 0;
  std::uint16_t flags = 0;   // tcp_* bits above

  constexpr bool operator==(const TcpHeader&) const = default;
};

struct TcpView {
  TcpHeader h;
  TcpOptions opt;
  std::uint8_t data_offset = 5;        // header length in 32-bit words
  std::span<const std::byte> payload;  // bytes after the header
};

// Parses one segment (the IPv4 payload). truncated if shorter than 20 bytes;
// bad_data_offset if the data offset is below 5 or beyond the segment;
// bad_checksum if verify_csum and the checksum over the pseudo-header of
// (src, dst) fails. Options follow Linux tcp_parse_options: EOL ends the list;
// NOP is skipped; a length below 2 or past the header sets `malformed` and
// stops; a known option with the wrong length (MSS != 4, WS != 3, SACK-permitted
// != 2, TS != 10, SACK not 2 + 8n with n >= 1) is skipped and parsing goes on;
// unknown options are skipped; a later copy of an option replaces an earlier
// one. More than four SACK blocks cannot occur (40 option bytes).
// Precondition (checked): segment.size() <= 65535 (it is an IPv4 payload).
[[nodiscard]] std::expected<TcpView, ParseError> parse_tcp(std::span<const std::byte> segment,
                                                           Ipv4Addr src, Ipv4Addr dst,
                                                           bool verify_csum) noexcept;

// Header length in bytes for `opt` in the layout of §4.5 (Linux
// tcp_options_write). With syn: MSS, window scale, SACK-permitted and TS as
// present, e.g. MSS, SACK_PERM, TS, NOP, WS (20 bytes) or without TS MSS, NOP,
// NOP, SACK_PERM, NOP, WS (12 bytes); SACK blocks are not written. Without
// syn: NOP, NOP, TS if present, then NOP, NOP, SACK(n) if sack_count > 0; MSS,
// window scale and SACK-permitted are not written. `malformed` is ignored.
// Precondition (checked): sack_count <= 3 with TS, <= 4 without.
[[nodiscard]] std::size_t tcp_header_len(const TcpOptions& opt, bool syn) noexcept;

// Writes the header and options (layout as tcp_header_len) into the first
// tcp_header_len(opt, syn) bytes of `out`, data offset set, checksum zero.
// Precondition (checked): out.size() >= tcp_header_len(opt, syn).
void write_tcp_header(std::span<std::byte> out, const TcpHeader& h, const TcpOptions& opt,
                      bool syn) noexcept;

}  // namespace utcp::wire
