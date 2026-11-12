#include "utcp/pcap.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

std::vector<std::byte> bytes(std::initializer_list<int> v) {
  std::vector<std::byte> out;
  for (const int b : v) {
    out.push_back(static_cast<std::byte>(b));
  }
  return out;
}

TEST(Pcap, FileHeader) {
  std::array<std::byte, utcp::pcap_file_header_size> h{};
  utcp::write_pcap_file_header(h, 65535);
  // Little-endian nanosecond magic, version 2.4, zone 0, sigfigs 0, snaplen,
  // LINKTYPE_RAW (101).
  EXPECT_EQ(std::vector<std::byte>(h.begin(), h.end()),
            bytes({0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0xff, 0xff, 0, 0, 101, 0, 0, 0}));
  utcp::write_pcap_file_header(h, 96, 1);
  EXPECT_EQ(h[16], std::byte{96});
  EXPECT_EQ(h[20], std::byte{1});
}

TEST(Pcap, RecordHeader) {
  std::array<std::byte, utcp::pcap_record_header_size> r{};
  // 1.5 s: seconds 1, nanoseconds 500000000 = 0x1dcd6500.
  utcp::write_pcap_record_header(r, utcp::Time{1'500'000'000}, 1500, 65535);
  EXPECT_EQ(std::vector<std::byte>(r.begin(), r.end()),
            bytes({1, 0, 0, 0, 0x00, 0x65, 0xcd, 0x1d, 0xdc, 0x05, 0, 0, 0xdc, 0x05, 0, 0}));
  // Captured length is cut to the snaplen; the original length stays.
  utcp::write_pcap_record_header(r, utcp::Time{0}, 1500, 96);
  EXPECT_EQ(std::vector<std::byte>(r.begin() + 8, r.end()),
            bytes({96, 0, 0, 0, 0xdc, 0x05, 0, 0}));
  // A Unix time in 2026: 1793000000 s = 0x6adf0240, plus 999999999 ns = 0x3b9ac9ff.
  utcp::write_pcap_record_header(r, utcp::Time{1'793'000'000'999'999'999}, 40, 40);
  EXPECT_EQ(std::vector<std::byte>(r.begin(), r.begin() + 8),
            bytes({0x40, 0x02, 0xdf, 0x6a, 0xff, 0xc9, 0x9a, 0x3b}));
}

}  // namespace
