#include "utcp/sim/pcap_writer.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <utility>

#include "utcp/pcap.hpp"

namespace utcp::sim {

std::expected<PcapWriter, std::string> PcapWriter::open(const std::string& path,
                                                        std::uint32_t snaplen) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  if (f == nullptr) {
    return std::unexpected(path + ": " + std::strerror(errno));
  }
  std::array<std::byte, pcap_file_header_size> hdr{};
  write_pcap_file_header(hdr, snaplen);
  if (std::fwrite(hdr.data(), 1, hdr.size(), f) != hdr.size()) {
    const int err = errno;
    std::fclose(f);
    return std::unexpected(path + ": " + std::strerror(err));
  }
  return PcapWriter(f, snaplen);
}

PcapWriter::PcapWriter(PcapWriter&& other) noexcept
    : f_(std::exchange(other.f_, nullptr)),
      snaplen_(other.snaplen_),
      records_(other.records_),
      failed_(other.failed_) {}

PcapWriter& PcapWriter::operator=(PcapWriter&& other) noexcept {
  if (this != &other) {
    close_();
    f_ = std::exchange(other.f_, nullptr);
    snaplen_ = other.snaplen_;
    records_ = other.records_;
    failed_ = other.failed_;
  }
  return *this;
}

PcapWriter::~PcapWriter() { close_(); }

void PcapWriter::close_() noexcept {
  if (f_ != nullptr) {
    std::fclose(f_);
    f_ = nullptr;
  }
}

bool PcapWriter::write(Time t, std::span<const std::byte> datagram) {
  if (f_ == nullptr || failed_) {
    return false;
  }
  std::array<std::byte, pcap_record_header_size> hdr{};
  const auto len = static_cast<std::uint32_t>(datagram.size());
  write_pcap_record_header(hdr, t, len, snaplen_);
  const std::size_t cap = std::min<std::size_t>(datagram.size(), snaplen_);
  if (std::fwrite(hdr.data(), 1, hdr.size(), f_) != hdr.size() ||
      std::fwrite(datagram.data(), 1, cap, f_) != cap) {
    failed_ = true;
    return false;
  }
  ++records_;
  return true;
}

}  // namespace utcp::sim
