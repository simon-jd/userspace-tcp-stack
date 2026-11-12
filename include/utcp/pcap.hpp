// pcap file and record headers, as bytes (DESIGN §7.4, §10.2).
//
// Serialisation only; file I/O lives in the simulator (src/sim/pcap_writer.cpp)
// and the backend. Files are LINKTYPE_RAW (each record is one IPv4 datagram)
// with the nanosecond magic 0xa1b23c4d. Header fields are written
// little-endian, so the bytes do not depend on the host.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "utcp/time.hpp"

namespace utcp {

inline constexpr std::uint32_t pcap_magic_ns = 0xa1b2'3c4d;
inline constexpr std::uint16_t pcap_version_major = 2;
inline constexpr std::uint16_t pcap_version_minor = 4;
inline constexpr std::uint32_t pcap_linktype_raw = 101;
inline constexpr std::size_t pcap_file_header_size = 24;
inline constexpr std::size_t pcap_record_header_size = 16;

// The 24-byte file header: magic, version 2.4, thiszone 0, sigfigs 0,
// snaplen, linktype.
void write_pcap_file_header(std::span<std::byte, pcap_file_header_size> out,
                            std::uint32_t snaplen,
                            std::uint32_t linktype = pcap_linktype_raw) noexcept;

// The 16-byte record header: seconds and nanoseconds of `ts`, captured length
// min(orig_len, snaplen), original length. `ts` is nanoseconds since the Unix
// epoch (the backend uses CLOCK_REALTIME, the simulator its virtual time);
// precondition ts.ns >= 0.
void write_pcap_record_header(std::span<std::byte, pcap_record_header_size> out, Time ts,
                              std::uint32_t orig_len, std::uint32_t snaplen) noexcept;

}  // namespace utcp
