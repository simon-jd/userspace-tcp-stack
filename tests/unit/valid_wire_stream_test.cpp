#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "core/tcp/recv_buffer.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "core/wire/udp.hpp"
#include "support/naive_reassembler.hpp"
#include "support/packet_builder.hpp"
#include "utcp/checksum.hpp"
#include "utcp/random.hpp"
#include "utcp/seq.hpp"
#include "utcp/types.hpp"

namespace {

namespace w = utcp::wire;
namespace t = utcp::test;

using utcp::Endpoint;
using utcp::Ipv4Addr;
using utcp::Range;
using utcp::Rng;
using utcp::Seed;
using utcp::Seq32;

constexpr std::uint32_t wire_cases_per_scale = 128;
constexpr std::uint32_t streams_per_scale = 16;
constexpr std::uint32_t windows_per_stream = 2;

class ValidWireStream : public testing::TestWithParam<std::uint64_t> {
protected:
  void SetUp() override {
    // The default CTest workload is short. A larger scale preserves its prefix.
    const char* env = std::getenv("UTCP_VALID_PROPERTY_SCALE");
    if (env == nullptr) {
      return;
    }
    const std::string_view value(env);
    const auto end = value.data() + value.size();
    const auto [ptr, ec] = std::from_chars(value.data(), end, scale_);
    ASSERT_TRUE(ec == std::errc{} && ptr == end && scale_ >= 1 && scale_ <= 1024)
        << "UTCP_VALID_PROPERTY_SCALE must be an integer in [1, 1024]";
  }

  std::uint32_t scale_ = 1;
};

void count(const char* key, std::uint64_t value) {
  testing::Test::RecordProperty(key, std::to_string(value));
}

std::uint16_t source_port(Rng& rng) {
  return static_cast<std::uint16_t>(49152 + rng.below(16384));
}

t::IpSpec ip_spec(Rng& rng) {
  constexpr std::array<std::uint8_t, 4> dscp{0, 0x20, 0x28, 0xb8};
  t::IpSpec ip;
  ip.src = Ipv4Addr::from_octets(192, 0, 2, static_cast<std::uint8_t>(1 + rng.below(254)));
  ip.dst = Ipv4Addr::from_octets(198, 51, 100, static_cast<std::uint8_t>(1 + rng.below(254)));
  ip.ttl = static_cast<std::uint8_t>(1 + rng.below(255));
  ip.tos = dscp[rng.below(dscp.size())];
  ip.id = static_cast<std::uint16_t>(rng.below(65536));
  ip.df = rng.below(2) == 0;
  return ip;
}

w::Ipv4Header expected_ip(const t::IpSpec& ip, std::size_t payload_size) {
  w::Ipv4Header expected;
  expected.src = ip.src;
  expected.dst = ip.dst;
  expected.proto = ip.proto;
  expected.ttl = ip.ttl;
  expected.tos = ip.tos;
  expected.id = ip.id;
  expected.df = ip.df;
  expected.total_len = static_cast<std::uint16_t>(w::ipv4_header_len + payload_size);
  return expected;
}

t::Bytes write_ip_datagram(const t::IpSpec& spec, std::span<const std::byte> transport) {
  t::Bytes datagram(w::ipv4_header_len + transport.size());
  w::write_ipv4(datagram, expected_ip(spec, transport.size()));
  std::ranges::copy(transport, std::span(datagram).subspan(w::ipv4_header_len).begin());
  return datagram;
}

void check_ip(const w::Ipv4View& parsed, const t::IpSpec& spec,
              std::span<const std::byte> transport) {
  ASSERT_EQ(parsed.h, expected_ip(spec, transport.size()));
  ASSERT_EQ(parsed.ihl, 5);
  ASSERT_TRUE(std::ranges::equal(parsed.payload, transport));
}

t::Bytes payload_bytes(Rng& rng, std::size_t size) {
  t::Bytes bytes(size);
  for (auto& byte : bytes) {
    byte = static_cast<std::byte>(rng.next());
  }
  return bytes;
}

t::Bytes wire_payload(Rng& rng, std::uint32_t max_size, std::uint32_t trial) {
  // Exercise zero, short odd/even, on-MTU and interior payload sizes.
  constexpr std::array<std::uint32_t, 4> short_sizes{0, 1, 2, 3};
  const auto profile = trial % 13;
  auto size = rng.below(max_size + 1);
  if (profile < short_sizes.size()) {
    size = short_sizes[profile];
  } else if (profile == short_sizes.size()) {
    size = max_size;
  }
  return payload_bytes(rng, size);
}

void check_tcp(Rng& rng, std::uint32_t trial) {
  auto ip = ip_spec(rng);
  ip.proto = utcp::ip_proto_tcp;
  auto tcp = t::TcpSpec(Endpoint{ip.src, source_port(rng)}, Endpoint{ip.dst, 443});
  tcp.seq = Seq32(static_cast<std::uint32_t>(rng.next()));
  tcp.window = static_cast<std::uint16_t>(rng.below(65536));

  const auto profile = trial % 4;
  const bool syn = profile < 2;
  if (profile != 0) {
    tcp.flags |= w::tcp_ack;
    tcp.ack = Seq32(static_cast<std::uint32_t>(rng.next()));
  }
  const auto syn_options = (trial / 4) % 16;
  // ACKs use every legal block count with and without a timestamp.
  const auto ack_options = (trial / 4) % 9;
  const bool timestamps = syn ? (syn_options & 8) != 0 : ack_options >= 5;
  if (timestamps) {
    const auto echo = profile == 0 ? 0u : static_cast<std::uint32_t>(rng.next());
    tcp.opt.ts = w::Timestamps{static_cast<std::uint32_t>(rng.next()), echo};
  }
  if (syn) {
    tcp.flags |= w::tcp_syn;
    if ((syn_options & 1) != 0) {
      tcp.opt.mss = static_cast<std::uint16_t>(536 + rng.below(925));
    }
    if ((syn_options & 2) != 0) {
      tcp.opt.wscale = static_cast<std::uint8_t>(rng.below(15));
    }
    tcp.opt.sack_permitted = (syn_options & 4) != 0;
  } else {
    tcp.opt.sack_count = static_cast<std::uint8_t>(timestamps ? ack_options - 5 : ack_options);
    // Strictly above ACK, separated and ordered in TCP sequence space.
    auto edge = tcp.ack;
    for (std::uint8_t i = 0; i < tcp.opt.sack_count; ++i) {
      const auto begin = edge + (1 + rng.below(100));
      edge = begin + (1 + rng.below(1200));
      tcp.opt.sack[i] = {begin, edge};
    }
  }

  const auto header_size = w::tcp_header_len(tcp.opt, syn);
  if (profile == 3) {
    constexpr std::uint32_t max_total = 1500 - w::ipv4_header_len;
    tcp.payload = wire_payload(rng, max_total - static_cast<std::uint32_t>(header_size), trial);
    if (!tcp.payload.empty()) {
      tcp.flags |= w::tcp_psh;
    }
  }
  const auto segment = t::tcp(tcp);
  const auto datagram = write_ip_datagram(ip, segment);
  const auto ipv4 = w::parse_ipv4(datagram);
  ASSERT_TRUE(ipv4.has_value());
  ASSERT_NO_FATAL_FAILURE(check_ip(*ipv4, ip, segment));

  const auto parsed = w::parse_tcp(ipv4->payload, ipv4->h.src, ipv4->h.dst, true);
  ASSERT_TRUE(parsed.has_value());
  const w::TcpHeader expected{tcp.src.port, tcp.dst.port, tcp.seq, tcp.ack, tcp.window, 0, tcp.flags};
  ASSERT_EQ(parsed->h, expected);
  ASSERT_EQ(parsed->opt, tcp.opt);
  ASSERT_EQ(parsed->data_offset * 4u, header_size);
  ASSERT_TRUE(std::ranges::equal(parsed->payload, tcp.payload));
}

void check_udp_and_icmp(Rng& rng, std::uint32_t trial) {
  auto ip = ip_spec(rng);
  ip.proto = utcp::ip_proto_udp;
  const auto checksum = trial % 4 == 0 ? t::UdpChecksum::none : t::UdpChecksum::compute;
  const auto udp = t::UdpSpec(Endpoint{ip.src, source_port(rng)}, Endpoint{ip.dst, 7},
                             wire_payload(rng, 1472, trial), checksum);
  const auto transport = t::udp(udp);
  const auto datagram = write_ip_datagram(ip, transport);
  const auto ipv4 = w::parse_ipv4(datagram);
  ASSERT_TRUE(ipv4.has_value());
  ASSERT_NO_FATAL_FAILURE(check_ip(*ipv4, ip, transport));

  const auto parsed = w::parse_udp(ipv4->payload, ipv4->h.src, ipv4->h.dst, true);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->h.sport, udp.src.port);
  ASSERT_EQ(parsed->h.dport, udp.dst.port);
  ASSERT_EQ(parsed->h.len, w::udp_header_len + udp.payload.size());
  ASSERT_EQ(parsed->h.csum == 0, checksum == t::UdpChecksum::none);
  ASSERT_TRUE(std::ranges::equal(parsed->payload, udp.payload));

  auto reply_ip = ip;
  reply_ip.proto = utcp::ip_proto_icmp;
  std::swap(reply_ip.src, reply_ip.dst);
  const bool error = trial % 4 == 3;
  const auto type = error ? w::icmp_dest_unreach
                          : (trial % 4 == 0 ? w::icmp_echo_request : w::icmp_echo_reply);
  const auto echo_id = static_cast<std::uint16_t>(rng.next());
  const auto echo_seq = static_cast<std::uint16_t>(rng.next());
  const auto expected = error ? w::icmp_unreach_header(w::icmp_port_unreach)
                              : w::icmp_echo_header(type, echo_id, echo_seq);
  constexpr auto min_quote = w::ipv4_header_len + w::udp_header_len;
  const auto max_quote = std::min(datagram.size(), w::icmp_max_quote);
  const auto quote_size = min_quote + rng.below(static_cast<std::uint32_t>(max_quote - min_quote + 1));
  const auto body = error ? std::span<const std::byte>(datagram).first(quote_size)
                          : std::span<const std::byte>(udp.payload);
  const auto message = t::icmp(expected.type, expected.code, expected.rest, body);
  const auto outer = write_ip_datagram(reply_ip, message);
  const auto icmp_ip = w::parse_ipv4(outer);
  ASSERT_TRUE(icmp_ip.has_value());
  ASSERT_NO_FATAL_FAILURE(check_ip(*icmp_ip, reply_ip, message));

  const auto icmp = w::parse_icmp(icmp_ip->payload, true);
  ASSERT_TRUE(icmp.has_value());
  ASSERT_EQ(icmp->h.type, expected.type);
  ASSERT_EQ(icmp->h.code, expected.code);
  ASSERT_EQ(icmp->h.rest, expected.rest);
  ASSERT_TRUE(std::ranges::equal(icmp->body, body));
  if (error) {
    const auto quote = w::parse_icmp_quote(icmp->body);
    ASSERT_TRUE(quote.has_value());
    ASSERT_EQ(quote->ihl, 5);
    ASSERT_EQ(quote->ip, expected_ip(ip, transport.size()));
    const auto quoted_transport =
        std::span<const std::byte>(transport).first(quote_size - w::ipv4_header_len);
    ASSERT_TRUE(std::ranges::equal(quote->l4, quoted_transport));
  }
}

void check_datagrams(std::uint64_t seed_value, std::uint32_t scale) {
  const auto seed = Seed::from_u64(seed_value);
  auto tcp = Rng::derive(seed, "valid-wire/tcp");
  auto udp_icmp = Rng::derive(seed, "valid-wire/udp-icmp");
  const auto cases = scale * wire_cases_per_scale;
  for (std::uint32_t trial = 0; trial < cases; ++trial) {
    SCOPED_TRACE(trial);
    ASSERT_NO_FATAL_FAILURE(check_tcp(tcp, trial));
    ASSERT_NO_FATAL_FAILURE(check_udp_and_icmp(udp_icmp, trial));
  }
  count("seed", seed_value);
  count("ipv4_datagrams", cases * 3u);
  count("tcp_segments", cases);
  count("tcp_syn", cases / 4);
  count("tcp_syn_ack", cases / 4);
  count("udp_datagrams", cases);
  count("udp_without_checksum", cases / 4);
  count("icmp_messages", cases);
  count("icmp_echo_request", cases / 4);
  count("icmp_echo_reply", cases / 2);
  count("icmp_port_unreachable", cases / 4);
}

TEST_P(ValidWireStream, ValidDatagrams) {
  ASSERT_NO_FATAL_FAILURE(check_datagrams(GetParam(), scale_));
}

struct StreamCounts {
  std::uint64_t inserts = 0;
  std::uint64_t repeats = 0;
  std::uint64_t reordered = 0;
  std::uint64_t hole_fills = 0;
  std::uint64_t ordered_windows = 0;
  std::uint64_t reordered_windows = 0;
  std::uint64_t drained_windows = 0;
  std::uint64_t reached_fin = 0;
  std::uint64_t reads = 0;
  std::uint64_t bytes_read = 0;
};

void check_state(const utcp::RecvBuffer& recv, const t::NaiveReassembler& ref) {
  recv.check_invariants();
  ASSERT_EQ(recv.read_offset(), ref.read_offset());
  ASSERT_EQ(recv.right_edge(), ref.right_edge());
  ASSERT_EQ(recv.contiguous_end(), ref.contiguous_end());
  ASSERT_EQ(recv.readable(), ref.readable());
  ASSERT_EQ(recv.fin_offset(), ref.fin_offset());
  ASSERT_EQ(recv.fin_reached(), ref.fin_reached());
  ASSERT_TRUE(std::ranges::equal(recv.ooo_ranges(), ref.ooo_ranges()));
}

enum class StreamProfile { historical, soak };

void check_stream(Rng& rng, utcp::ChunkPool& pool, StreamCounts& counts, StreamProfile profile) {
  const bool soak = profile == StreamProfile::soak;
  // Preserve the 4 KiB build's seeded application input at every storage geometry.
  constexpr std::uint32_t workload_unit = 4096;
  const auto capacity = soak ? workload_unit + 1 + rng.below(workload_unit - 1)
                             : workload_unit + rng.below(workload_unit);
  utcp::RecvBuffer recv(capacity, pool);
  t::NaiveReassembler ref(capacity);
  for (std::uint32_t window = 0; window < windows_per_stream; ++window) {
    const auto base = recv.read_offset();
    const bool ordered = soak && window == 0;
    const bool final_window = soak && window + 1 == windows_per_stream;
    const auto window_size =
        soak ? capacity - rng.below(capacity - workload_unit) : capacity - rng.below(capacity / 3 + 1);
    const auto data = payload_bytes(rng, window_size);
    std::vector<Range> segments;
    for (std::size_t off = 0; off < data.size();) {
      const auto length = std::min<std::size_t>(data.size() - off, 128 + rng.below(641));
      segments.push_back(Range{off, off + length});
      off += length;
    }
    ASSERT_GE(segments.size(), 2u);
    if (soak) {
      ASSERT_GT(data.size(), workload_unit);
    }
    if (!ordered) {
      // Release the tail first, then shuffle the remaining segments.
      std::swap(segments.front(), segments.back());
      for (auto n = segments.size() - 1; n > 1; --n) {
        std::swap(segments[n], segments[1 + rng.below(static_cast<std::uint32_t>(n))]);
      }
    }
    const auto limit = recv.right_edge();
    const auto insert = [&](Range segment, bool repeated) {
      const auto payload =
          std::span<const std::byte>(data).subspan(segment.begin, segment.end - segment.begin);
      const auto actual = recv.insert(base + segment.begin, payload, limit);
      const auto expected = ref.insert(base + segment.begin, payload, limit);
      ASSERT_EQ(actual.contiguous_end, expected.contiguous_end);
      ASSERT_EQ(actual.advanced, expected.advanced);
      ASSERT_EQ(actual.out_of_order, expected.out_of_order);
      ASSERT_EQ(actual.filled_hole, expected.filled_hole);
      ASSERT_EQ(actual.ooo_held, expected.ooo_held);
      ASSERT_EQ(actual.duplicate, expected.duplicate);
      ASSERT_EQ(actual.duplicate.has_value(), repeated);
      ASSERT_EQ(actual.stored, expected.stored);
      if (ordered) {
        ASSERT_EQ(actual.contiguous_end, base + segment.end);
        ASSERT_TRUE(actual.advanced);
        ASSERT_FALSE(actual.out_of_order);
        ASSERT_FALSE(actual.ooo_held);
      }
      ASSERT_EQ(actual.dropped, 0u);
      ASSERT_EQ(actual.pruned, 0u);
      ASSERT_FALSE(actual.range_limit);
      ASSERT_NO_FATAL_FAILURE(check_state(recv, ref));
      ++counts.inserts;
      counts.repeats += repeated;
      counts.reordered += actual.out_of_order && !repeated;
      counts.hole_fills += actual.filled_hole;
    };

    constexpr std::size_t max_read = 3072;
    std::array<std::byte, max_read> actual{};
    std::array<std::byte, max_read> expected{};
    const auto read = [&] {
      const auto off = recv.read_offset() - base;
      const auto requested = 1 + rng.below(max_read);
      const auto available = recv.readable();
      const auto got = recv.read(std::span(actual).first(requested));
      ASSERT_EQ(got, ref.read(std::span(expected).first(requested)));
      ASSERT_EQ(got, std::min<std::uint64_t>(requested, available));
      const auto bytes = std::span(actual).first(got);
      ASSERT_TRUE(std::ranges::equal(bytes, std::span(expected).first(got)));
      ASSERT_LE(off + got, data.size());
      ASSERT_TRUE(std::ranges::equal(bytes, std::span(data).subspan(off, got)));
      ASSERT_NO_FATAL_FAILURE(check_state(recv, ref));
      ++counts.reads;
      counts.bytes_read += got;
    };

    ASSERT_NO_FATAL_FAILURE(insert(segments.front(), false));
    if (!ordered) {
      ASSERT_EQ(recv.ooo_ranges().size(), 1u);
      ASSERT_EQ(recv.readable(), 0u);
      ASSERT_NO_FATAL_FAILURE(insert(segments.front(), true));
    }
    if (final_window) {
      // The last segment (delivered first) is immediately followed by FIN.
      const auto fin = base + data.size();
      recv.set_fin(fin);
      ref.set_fin(fin);
      ASSERT_EQ(recv.fin_offset(), fin);
      ASSERT_FALSE(recv.fin_reached());
      ASSERT_NO_FATAL_FAILURE(check_state(recv, ref));
    }
    for (const auto& segment : std::span(segments).subspan(1)) {
      ASSERT_NO_FATAL_FAILURE(insert(segment, false));
      ASSERT_NO_FATAL_FAILURE(read());
    }
    ASSERT_EQ(recv.contiguous_end(), base + data.size());
    while (recv.readable() != 0) {
      ASSERT_NO_FATAL_FAILURE(read());
    }
    ASSERT_EQ(recv.read_offset(), base + data.size());
    ASSERT_TRUE(recv.ooo_ranges().empty());
    if (soak) {
      ASSERT_EQ(recv.readable(), 0u);
      ASSERT_EQ(recv.read(actual), 0u);
      ASSERT_EQ(ref.read(expected), 0u);
      ++counts.drained_windows;
      counts.ordered_windows += ordered;
      counts.reordered_windows += !ordered;
    }
    if (final_window) {
      ASSERT_TRUE(recv.fin_reached());
      ASSERT_EQ(recv.fin_offset(), recv.read_offset());
      ASSERT_NO_FATAL_FAILURE(check_state(recv, ref));
      ++counts.reached_fin;
    }
  }
}

void check_streams(std::uint64_t seed_value, std::uint32_t scale, StreamProfile profile) {
  auto rng = Rng::derive(Seed::from_u64(seed_value), "valid-stream/delivery");
  utcp::ChunkPool pool(8);  // even an unaligned 8191-byte window spans at most five 2 KiB chunks
  const auto streams = scale * streams_per_scale;
  StreamCounts counts;
  for (std::uint32_t trial = 0; trial < streams; ++trial) {
    SCOPED_TRACE(trial);
    ASSERT_NO_FATAL_FAILURE(check_stream(rng, pool, counts, profile));
    ASSERT_EQ(pool.in_use(), 0u);
  }
  ASSERT_EQ(pool.failures(), 0u);
  if (profile == StreamProfile::soak) {
    ASSERT_EQ(counts.repeats, streams);
    ASSERT_EQ(counts.ordered_windows, streams);
    ASSERT_EQ(counts.reordered_windows, streams);
    ASSERT_EQ(counts.drained_windows, streams * windows_per_stream);
    ASSERT_EQ(counts.reached_fin, streams);
    count("ordered_windows", counts.ordered_windows);
    count("reordered_windows", counts.reordered_windows);
    count("drained_windows", counts.drained_windows);
    count("fin_reached", counts.reached_fin);
  } else {
    ASSERT_EQ(counts.repeats, streams * windows_per_stream);
  }
  ASSERT_GE(counts.reordered, counts.repeats);
  ASSERT_GE(counts.hole_fills, counts.repeats);
  count("seed", seed_value);
  count("streams", streams);
  count("delivery_windows", streams * windows_per_stream);
  count("inserts", counts.inserts);
  count("repeat_inserts", counts.repeats);
  count("reordered_inserts", counts.reordered);
  count("hole_fills", counts.hole_fills);
  count("reads", counts.reads);
  count("bytes_read", counts.bytes_read);
}

TEST_P(ValidWireStream, CompleteStreams) {
  ASSERT_NO_FATAL_FAILURE(check_streams(GetParam(), scale_, StreamProfile::historical));
}

void read_setting(const char* name, std::uint32_t lo, std::uint32_t hi, std::uint32_t& out) {
  const char* env = std::getenv(name);
  ASSERT_NE(env, nullptr) << name;
  const std::string_view value(env);
  const auto end = value.data() + value.size();
  const auto [ptr, ec] = std::from_chars(value.data(), end, out);
  ASSERT_TRUE(ec == std::errc{} && ptr == end && out >= lo && out <= hi) << name;
}

enum class SoakLane { wire, stream };

void run_soak(SoakLane lane) {
  using Clock = std::chrono::steady_clock;
  using Ns = std::chrono::nanoseconds;
  static_assert(Clock::is_steady);
  constexpr std::uint32_t max_index = 0x7fffffff;
  std::uint32_t seconds{}, run{}, scale{}, batch{};
  ASSERT_NO_FATAL_FAILURE(read_setting("UTCP_VALID_SOAK_SECONDS", 1, 86400, seconds));
  ASSERT_NO_FATAL_FAILURE(read_setting("UTCP_VALID_SOAK_RUN", 1, max_index, run));
  ASSERT_NO_FATAL_FAILURE(read_setting("UTCP_VALID_SOAK_SCALE", 1, 1024, scale));
  ASSERT_NO_FATAL_FAILURE(read_setting("UTCP_VALID_SOAK_FIRST_BATCH", 0, max_index, batch));
  const bool stream = lane == SoakLane::stream;
  const auto prefix = (std::uint64_t{1} << 63) | (std::uint64_t{run} << 32) |
                      (static_cast<std::uint64_t>(stream) << 31);
  Ns active{};
  while (active < std::chrono::seconds(seconds)) {
    ASSERT_LE(batch, max_index);
    const auto seed = prefix | batch;
    SCOPED_TRACE(seed);
    const auto begin = Clock::now();
    if (stream) {
      ASSERT_NO_FATAL_FAILURE(check_streams(seed, scale, StreamProfile::soak));
    } else {
      ASSERT_NO_FATAL_FAILURE(check_datagrams(seed, scale));
    }
    const auto end = Clock::now();
    const auto begin_ns = std::chrono::duration_cast<Ns>(begin.time_since_epoch());
    const auto end_ns = std::chrono::duration_cast<Ns>(end.time_since_epoch());
    ASSERT_GT(end_ns, begin_ns);
    active += end_ns - begin_ns;
    // Export counters only after all reference and byte checks for this batch pass.
    const auto* result = testing::UnitTest::GetInstance()->current_test_info()->result();
    std::cout << "UTCP_VALID_BATCH " << batch << ' ' << begin_ns.count() << ' ' << end_ns.count();
    for (int i = 0; i < result->test_property_count(); ++i) {
      const auto& p = result->GetTestProperty(i);
      std::cout << ' ' << p.key() << '=' << p.value();
    }
    std::cout << std::endl;
    ++batch;
  }
}

TEST(ValidWireStreamSoak, DISABLED_Wire) { ASSERT_NO_FATAL_FAILURE(run_soak(SoakLane::wire)); }
TEST(ValidWireStreamSoak, DISABLED_Stream) { ASSERT_NO_FATAL_FAILURE(run_soak(SoakLane::stream)); }

INSTANTIATE_TEST_SUITE_P(Seeds, ValidWireStream, testing::Values(101u, 202u, 303u, 404u),
                         testing::PrintToStringParamName());

}  // namespace
