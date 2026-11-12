#include "utcp/pcap.hpp"

#include <algorithm>

#include "utcp/check.hpp"

namespace utcp {
namespace {

// pcap header fields are little-endian (the file is read by the magic's byte
// order; writing one fixed order keeps the bytes host-independent).
void put_le16(std::span<std::byte> b, std::size_t at, std::uint16_t v) noexcept {
  b[at] = static_cast<std::byte>(v & 0xffu);
  b[at + 1] = static_cast<std::byte>(v >> 8);
}

void put_le32(std::span<std::byte> b, std::size_t at, std::uint32_t v) noexcept {
  put_le16(b, at, static_cast<std::uint16_t>(v & 0xffffu));
  put_le16(b, at + 2, static_cast<std::uint16_t>(v >> 16));
}

}  // namespace

void write_pcap_file_header(std::span<std::byte, pcap_file_header_size> out, std::uint32_t snaplen,
                            std::uint32_t linktype) noexcept {
  put_le32(out, 0, pcap_magic_ns);
  put_le16(out, 4, pcap_version_major);
  put_le16(out, 6, pcap_version_minor);
  put_le32(out, 8, 0);   // thiszone
  put_le32(out, 12, 0);  // sigfigs
  put_le32(out, 16, snaplen);
  put_le32(out, 20, linktype);
}

void write_pcap_record_header(std::span<std::byte, pcap_record_header_size> out, Time ts,
                              std::uint32_t orig_len, std::uint32_t snaplen) noexcept {
  UTCP_CHECK(ts.ns >= 0);
  constexpr std::int64_t ns_per_s = 1'000'000'000;
  // ts_sec is 32 bits: valid until 2106 for Unix time.
  put_le32(out, 0, static_cast<std::uint32_t>(ts.ns / ns_per_s));
  put_le32(out, 4, static_cast<std::uint32_t>(ts.ns % ns_per_s));
  put_le32(out, 8, std::min(orig_len, snaplen));
  put_le32(out, 12, orig_len);
}

}  // namespace utcp
