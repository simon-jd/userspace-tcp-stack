// pcap output of the simulator (DESIGN §7.4): LINKTYPE_RAW (101), the
// nanosecond magic 0xa1b23c4d, record times = virtual time. The header bytes
// come from the core (utcp/pcap.hpp); this file does the I/O.
#pragma once

#include <cstdint>
#include <cstdio>
#include <expected>
#include <span>
#include <string>

#include "utcp/time.hpp"

namespace utcp::sim {

class PcapWriter {
public:
  // Creates or truncates `path` and writes the file header.
  [[nodiscard]] static std::expected<PcapWriter, std::string> open(const std::string& path,
                                                                   std::uint32_t snaplen);
  PcapWriter(PcapWriter&& other) noexcept;
  PcapWriter& operator=(PcapWriter&& other) noexcept;
  PcapWriter(const PcapWriter&) = delete;
  PcapWriter& operator=(const PcapWriter&) = delete;
  ~PcapWriter();

  // One record of the datagram at time t (t.ns >= 0), cut at the snaplen,
  // flushed at once (a run that aborts leaves whole records).
  // False after a write error.
  bool write(Time t, std::span<const std::byte> datagram);
  [[nodiscard]] std::uint64_t records() const noexcept { return records_; }

private:
  PcapWriter(std::FILE* f, std::uint32_t snaplen) noexcept : f_(f), snaplen_(snaplen) {}
  void close_() noexcept;

  std::FILE* f_ = nullptr;
  std::uint32_t snaplen_ = 0;
  std::uint64_t records_ = 0;
  bool failed_ = false;
};

}  // namespace utcp::sim
