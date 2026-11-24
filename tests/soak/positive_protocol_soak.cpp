#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "core/tcp/recv_buffer.hpp"
#include "core/wire/icmp.hpp"
#include "core/wire/ipv4.hpp"
#include "core/wire/tcp.hpp"
#include "core/wire/udp.hpp"
#include "support/naive_reassembler.hpp"
#include "support/packet_builder.hpp"
#include "support/tcp_harness.hpp"
#include "utcp/checksum.hpp"
#include "utcp/random.hpp"
#include "utcp/stack.hpp"

namespace {

namespace t = utcp::test;
namespace w = utcp::wire;
using Clock = std::chrono::steady_clock;
using utcp::Endpoint;
using utcp::Ipv4Addr;
using utcp::Rng;
using utcp::Seed;
using utcp::Seq32;
using t::Side;

// FNV-1a over a canonical sequence of checked bytes and counters. Replaying
// --cases with the printed seed and completed count reproduces the digest.
struct Digest {
  std::uint64_t value = 14695981039346656037ull;
  void byte(std::uint8_t b) {
    value ^= b;
    value *= 1099511628211ull;
  }
  void number(std::uint64_t n) {
    for (int i = 0; i < 8; ++i) {
      byte(static_cast<std::uint8_t>(n));
      n >>= 8;
    }
  }
  void bytes(std::span<const std::byte> data) {
    number(data.size());
    for (auto b : data) byte(std::to_integer<std::uint8_t>(b));
  }
  std::string hex() const {
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
  }
};

void need(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

t::Bytes random_bytes(Rng& rng, std::size_t n) {
  t::Bytes out(n);
  for (auto& b : out) b = static_cast<std::byte>(rng.next());
  return out;
}

Ipv4Addr source(Rng& rng) {
  return Ipv4Addr::from_octets(192, 0, 2, static_cast<std::uint8_t>(1 + rng.below(254)));
}
Ipv4Addr destination(Rng& rng) {
  return Ipv4Addr::from_octets(198, 51, 100, static_cast<std::uint8_t>(1 + rng.below(254)));
}

void ipv4_case(Rng& rng, Digest& digest, std::uint64_t ordinal) {
  t::IpSpec spec;
  spec.src = source(rng);
  spec.dst = destination(rng);
  spec.proto = std::array<std::uint8_t, 3>{utcp::ip_proto_tcp, utcp::ip_proto_udp,
                                           utcp::ip_proto_icmp}[ordinal % 3];
  spec.ttl = static_cast<std::uint8_t>(1 + rng.below(255));
  spec.tos = std::array<std::uint8_t, 4>{0, 0x20, 0x28, 0xb8}[ordinal % 4];
  spec.id = static_cast<std::uint16_t>(rng.next());
  spec.df = ordinal % 2 == 0;
  const auto payload = random_bytes(rng, ordinal % 11 == 0 ? 0 : 1 + rng.below(1000));
  t::Bytes transport;
  if (spec.proto == utcp::ip_proto_tcp) {
    t::TcpSpec tcp(Endpoint{spec.src, 5000}, Endpoint{spec.dst, 443});
    tcp.seq = Seq32(static_cast<std::uint32_t>(rng.next()));
    tcp.ack = Seq32(static_cast<std::uint32_t>(rng.next()));
    tcp.flags = w::tcp_ack;
    tcp.payload = payload;
    transport = t::tcp(tcp);
  } else if (spec.proto == utcp::ip_proto_udp) {
    transport = t::udp(t::UdpSpec{Endpoint{spec.src, 5000}, Endpoint{spec.dst, 6000},
                                  payload});
  } else {
    transport = t::icmp(w::icmp_echo_request, 0, static_cast<std::uint32_t>(rng.next()), payload);
  }
  const auto datagram = t::ipv4(spec, transport);
  const auto parsed = w::parse_ipv4(datagram);
  need(parsed.has_value(), "generated IPv4 datagram rejected");
  need(parsed->ihl == 5 && parsed->h.src == spec.src && parsed->h.dst == spec.dst &&
           parsed->h.proto == spec.proto && parsed->h.ttl == spec.ttl &&
           parsed->h.tos == spec.tos && parsed->h.id == spec.id && parsed->h.df == spec.df &&
           parsed->h.total_len == datagram.size(), "IPv4 header mismatch");
  need(std::ranges::equal(parsed->payload, transport), "IPv4 payload mismatch");
  if (spec.proto == utcp::ip_proto_tcp) {
    need(w::parse_tcp(parsed->payload, spec.src, spec.dst, true).has_value(),
         "IPv4 TCP payload invalid");
  } else if (spec.proto == utcp::ip_proto_udp) {
    need(w::parse_udp(parsed->payload, spec.src, spec.dst, true).has_value(),
         "IPv4 UDP payload invalid");
  } else {
    need(w::parse_icmp(parsed->payload, true).has_value(), "IPv4 ICMP payload invalid");
  }
  digest.bytes(datagram);
}

void options_case(Rng& rng, Digest& digest, std::uint64_t ordinal) {
  const Endpoint src{source(rng), static_cast<std::uint16_t>(49152 + rng.below(16384))};
  const Endpoint dst{destination(rng), 443};
  t::TcpSpec spec(src, dst);
  spec.seq = Seq32(static_cast<std::uint32_t>(rng.next()));
  spec.ack = Seq32(static_cast<std::uint32_t>(rng.next()));
  spec.window = static_cast<std::uint16_t>(rng.next());
  const bool syn = ordinal % 2 == 0;
  spec.flags = syn ? w::tcp_syn : w::tcp_ack;
  if (ordinal % 3 != 0) {
    spec.opt.ts = w::Timestamps{static_cast<std::uint32_t>(rng.next()),
                                syn ? 0u : static_cast<std::uint32_t>(rng.next())};
  }
  if (syn) {
    spec.opt.mss = static_cast<std::uint16_t>(536 + rng.below(925));
    if (ordinal % 4 != 0) spec.opt.wscale = static_cast<std::uint8_t>(rng.below(15));
    spec.opt.sack_permitted = ordinal % 3 != 0;
  } else {
    spec.opt.sack_count = static_cast<std::uint8_t>(ordinal % (spec.opt.ts ? 4 : 5));
    auto edge = spec.ack;
    for (std::uint8_t i = 0; i < spec.opt.sack_count; ++i) {
      const auto begin = edge + (1 + rng.below(100));
      edge = begin + (1 + rng.below(1200));
      spec.opt.sack[i] = {begin, edge};
    }
  }
  const auto segment = t::tcp(spec);
  const auto parsed = w::parse_tcp(segment, src.addr, dst.addr, true);
  need(parsed.has_value(), "generated TCP segment rejected");
  need(parsed->h.sport == src.port && parsed->h.dport == dst.port &&
           parsed->h.seq == spec.seq && parsed->h.ack == spec.ack &&
           parsed->h.window == spec.window && parsed->h.flags == spec.flags,
       "TCP fixed header mismatch");
  need(parsed->opt == spec.opt && parsed->data_offset * 4u == w::tcp_header_len(spec.opt, syn) &&
           parsed->payload.empty(), "TCP options mismatch");
  digest.bytes(segment);
}

void check_stream_state(const utcp::RecvBuffer& recv, const t::NaiveReassembler& ref) {
  recv.check_invariants();
  need(recv.read_offset() == ref.read_offset() &&
           recv.contiguous_end() == ref.contiguous_end() &&
           recv.readable() == ref.readable() && recv.right_edge() == ref.right_edge() &&
           recv.fin_offset() == ref.fin_offset() && recv.fin_reached() == ref.fin_reached() &&
           std::ranges::equal(recv.ooo_ranges(), ref.ooo_ranges()),
       "receive buffer differs from reference");
}

void stream_case(Rng& rng, Digest& digest, std::uint64_t ordinal) {
  const std::uint32_t capacity = 4097 + rng.below(4095);
  const auto data = random_bytes(rng, 4097 + rng.below(capacity - 4096));
  utcp::ChunkPool pool(8);
  {
    utcp::RecvBuffer recv(capacity, pool);
    t::NaiveReassembler ref(capacity);
    std::array<std::size_t, 5> offsets{0, data.size() / 4, data.size() / 2,
                                       data.size() * 3 / 4, data.size()};
    // Every segment is a valid part of the same stream. Send the tail first.
    for (auto index : std::array<std::size_t, 4>{3, 1, 2, 0}) {
      const auto part = std::span(data).subspan(offsets[index], offsets[index + 1] - offsets[index]);
      const auto actual = recv.insert(offsets[index], part, recv.right_edge());
      const auto expected = ref.insert(offsets[index], part, ref.right_edge());
      need(actual.contiguous_end == expected.contiguous_end &&
               actual.stored == expected.stored && actual.duplicate == expected.duplicate &&
               actual.dropped == 0 && actual.pruned == 0 && !actual.range_limit,
           "receive insert result mismatch");
      check_stream_state(recv, ref);
      if (index == 3) {
        recv.set_fin(data.size());
        ref.set_fin(data.size());
        need(!recv.fin_reached(), "FIN reached before missing data");
        check_stream_state(recv, ref);
      }
    }
    need(recv.contiguous_end() == data.size() && recv.fin_reached(),
         "reassembly did not reach complete data and FIN");
    std::array<std::byte, 1024> got{}, expected{};
    std::size_t read = 0;
    while (recv.readable() != 0) {
      const auto request = 1 + rng.below(got.size());
      const auto n = recv.read(std::span(got).first(request));
      need(n == ref.read(std::span(expected).first(request)) && n != 0 &&
               std::ranges::equal(std::span(got).first(n), std::span(expected).first(n)) &&
               std::ranges::equal(std::span(got).first(n), std::span(data).subspan(read, n)),
           "reassembled content mismatch");
      read += n;
      check_stream_state(recv, ref);
    }
    need(read == data.size() && recv.read_offset() == data.size() &&
             recv.fin_offset() == std::optional<std::uint64_t>(data.size()) &&
             recv.fin_reached() && recv.ooo_ranges().empty(), "stream end mismatch");
    digest.number(ordinal);
    digest.bytes(data);
    digest.number(*recv.fin_offset());
  }
  need(pool.in_use() == 0 && pool.failures() == 0, "receive chunk pool leak or exhaustion");
}

t::Bytes tcp_receive_to_eof(t::TcpHarness& h, utcp::Stack& receiver, utcp::Handle handle) {
  t::Bytes out;
  std::array<std::byte, 1024> buf{};
  for (int step = 0; step < 1000; ++step) {
    const auto result = receiver.tcp_recv(handle, buf);
    if (result) {
      if (*result == 0) return out;
      out.insert(out.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*result));
    } else {
      need(result.error() == utcp::Error::would_block, "TCP receive failed");
      h.run_for(std::chrono::milliseconds(1));
    }
  }
  throw std::runtime_error("TCP did not reach FIN");
}

void peers_case(Rng& rng, Digest& digest, std::uint64_t ordinal) {
  using namespace std::chrono_literals;
  t::TcpHarness h;
  const auto listener = h.b().tcp_listen(Endpoint{{}, 8080}, 16, {});
  need(listener.has_value(), "TCP listen failed");
  const auto client = h.a().tcp_connect(Endpoint{h.addr(Side::b), 8080}, {});
  need(client.has_value(), "TCP connect failed");
  h.run_for(100ms);
  const auto server = h.b().tcp_accept(*listener);
  need(server.has_value(), "TCP accept failed");
  const auto ab = random_bytes(rng, 1 + rng.below(1024));
  const auto ba = random_bytes(rng, 1 + rng.below(1024));
  const auto sent_ab = h.a().tcp_send(*client, ab);
  const auto sent_ba = h.b().tcp_send(*server, ba);
  need(sent_ab.has_value() && sent_ba.has_value() && *sent_ab == ab.size() &&
           *sent_ba == ba.size(), "TCP send incomplete");
  need(h.a().tcp_shutdown(*client, utcp::Shutdown::write).has_value() &&
           h.b().tcp_shutdown(*server, utcp::Shutdown::write).has_value(),
       "TCP write shutdown failed");
  h.run_for(100ms);
  const auto received_ab = tcp_receive_to_eof(h, h.b(), *server);
  const auto received_ba = tcp_receive_to_eof(h, h.a(), *client);
  need(received_ab == ab && received_ba == ba, "TCP peer content mismatch");
  need(h.a().tcp_close(*client).has_value() && h.b().tcp_close(*server).has_value() &&
           h.b().tcp_close(*listener).has_value(), "TCP close failed");

  const Endpoint ea{h.addr(Side::a), 5000}, eb{h.addr(Side::b), 6000};
  const auto ua = h.a().udp_open(Endpoint{{}, ea.port});
  const auto ub = h.b().udp_open(Endpoint{{}, eb.port});
  need(ua.has_value() && ub.has_value(), "UDP open failed");
  const auto udpa = random_bytes(rng, 1 + rng.below(1000));
  const auto udpb = random_bytes(rng, 1 + rng.below(1000));
  need(h.a().udp_send_to(*ua, eb, udpa).has_value() &&
           h.b().udp_send_to(*ub, ea, udpb).has_value(), "UDP send failed");
  h.settle();
  t::Bytes gota(udpb.size()), gotb(udpa.size());
  const auto ra = h.a().udp_recv_from(*ua, gota);
  const auto rb = h.b().udp_recv_from(*ub, gotb);
  need(ra.has_value() && rb.has_value() && ra->len == udpb.size() &&
           rb->len == udpa.size() && ra->from == eb && rb->from == ea &&
           !ra->truncated && !rb->truncated && gota == udpb && gotb == udpa,
       "UDP peer content mismatch");
  need(h.a().udp_close(*ua).has_value() && h.b().udp_close(*ub).has_value(),
       "UDP close failed");

  const auto echo_payload = random_bytes(rng, 1 + rng.below(256));
  const auto echo_id = static_cast<std::uint16_t>(ordinal);
  need(h.a().icmp_echo(h.addr(Side::b), echo_id, 1, echo_payload).has_value() &&
           h.b().icmp_echo(h.addr(Side::a), echo_id, 2, echo_payload).has_value(),
       "ICMP echo send failed");
  h.run_for(10ms);
  const auto echo_a = h.a().poll_echo_reply();
  const auto echo_b = h.b().poll_echo_reply();
  need(echo_a.has_value() && echo_b.has_value() && echo_a->id == echo_id &&
           echo_b->id == echo_id && echo_a->seq == 1 && echo_b->seq == 2 &&
           echo_a->len == echo_payload.size() && echo_b->len == echo_payload.size() &&
           echo_a->from == h.addr(Side::b) && echo_b->from == h.addr(Side::a) &&
           !h.a().poll_echo_reply() && !h.b().poll_echo_reply(),
       "ICMP echo reply mismatch");
  std::size_t requests = 0, replies = 0;
  for (const auto& sent : h.log()) {
    const auto ip = w::parse_ipv4(sent.bytes);
    need(ip.has_value(), "normal peer sent invalid IPv4");
    if (ip->h.proto != utcp::ip_proto_icmp) continue;
    const auto icmp = w::parse_icmp(ip->payload, true);
    need(icmp.has_value() && std::ranges::equal(icmp->body, echo_payload),
         "ICMP peer payload mismatch");
    if (icmp->h.type == w::icmp_echo_request) ++requests;
    else if (icmp->h.type == w::icmp_echo_reply) {
      ++replies;
      digest.bytes(icmp->body);
    } else throw std::runtime_error("unexpected ICMP type in normal exchange");
  }
  need(requests == 2 && replies == 2, "ICMP exchange count mismatch");
  h.a().debug_check();
  h.b().debug_check();
  digest.number(ordinal);
  digest.bytes(ab);
  digest.bytes(received_ab);
  digest.bytes(ba);
  digest.bytes(received_ba);
  digest.bytes(udpa);
  digest.bytes(gotb);
  digest.bytes(udpb);
  digest.bytes(gota);
  digest.bytes(echo_payload);
  digest.number(echo_id);
}

std::uint64_t parse_number(std::string_view text) {
  std::uint64_t value = 0;
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  need(error == std::errc{} && end == text.data() + text.size(), "invalid numeric argument");
  return value;
}

struct Args {
  std::string lane;
  std::uint64_t seed = 0;
  std::uint64_t seconds = 0;
  std::uint64_t cases = 0;
};

Args args(int argc, char** argv) {
  Args out;
  for (int i = 1; i < argc; i += 2) {
    need(i + 1 < argc, "expected a value after each option");
    const std::string_view key(argv[i]), value(argv[i + 1]);
    if (key == "--lane") out.lane = value;
    else if (key == "--seed") out.seed = parse_number(value);
    else if (key == "--seconds") out.seconds = parse_number(value);
    else if (key == "--cases") out.cases = parse_number(value);
    else throw std::runtime_error("unknown option");
  }
  need(out.lane == "ipv4" || out.lane == "options" || out.lane == "stream" ||
           out.lane == "peers", "lane must be ipv4, options, stream, or peers");
  need(out.seed != 0 && ((out.seconds > 0) != (out.cases > 0)),
       "specify nonzero seed and exactly one of --seconds or --cases");
  need(out.seconds <= 86400 && out.cases <= 1000000000, "run limit exceeded");
  return out;
}

void report(const char* kind, const Args& a, std::uint64_t completed, Clock::time_point start,
            const Digest& digest) {
  const auto now = Clock::now();
  const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - start);
  const auto steady = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
  std::cout << kind << " lane=" << a.lane << " seed=" << a.seed << " completed=" << completed
            << " elapsed_ns=" << elapsed.count() << " steady_ns=" << steady.count()
            << " digest_fnv1a64=" << digest.hex()
            << (std::string_view(kind) == "UTCP_POSITIVE_FINAL" ? " exit=0" : "")
            << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto a = args(argc, argv);
    Digest digest;
    const auto start = Clock::now();
    auto next_report = start + std::chrono::minutes(1);
    std::uint64_t completed = 0;
    report("UTCP_POSITIVE_START", a, completed, start, digest);
    while (a.cases ? completed < a.cases : Clock::now() - start < std::chrono::seconds(a.seconds)) {
      const auto ordinal = completed;
      auto rng = Rng::derive(Seed::from_u64(a.seed + ordinal), a.lane);
      if (a.lane == "ipv4") ipv4_case(rng, digest, ordinal);
      else if (a.lane == "options") options_case(rng, digest, ordinal);
      else if (a.lane == "stream") stream_case(rng, digest, ordinal);
      else peers_case(rng, digest, ordinal);
      ++completed;
      if (Clock::now() >= next_report) {
        report("UTCP_POSITIVE_PROGRESS", a, completed, start, digest);
        next_report += std::chrono::minutes(1);
      }
    }
    report("UTCP_POSITIVE_FINAL", a, completed, start, digest);
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "UTCP_POSITIVE_FAIL " << e.what() << std::endl;
    return 1;
  }
}
