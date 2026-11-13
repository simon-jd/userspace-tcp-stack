// Stub DNS resolver messages (RFC 1035) for utcp-http-get (DESIGN §9): one
// A query with recursion desired, and the A records of the answer, following
// CNAMEs inside the answer section. Name compression (RFC 1035 §4.1.4) is
// decoded; pointers must point backwards, which also rules out loops.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "utcp/types.hpp"

namespace utcp::app {

inline constexpr std::uint16_t dns_type_a = 1;
inline constexpr std::uint16_t dns_type_cname = 5;
inline constexpr std::uint16_t dns_class_in = 1;
inline constexpr std::uint16_t dns_port = 53;

// A standard query (QR 0, opcode 0, RD 1) with one question: `name` IN `qtype`.
// `name` is dotted, an optional final dot allowed; labels 1-63 bytes, the
// encoded name at most 255 bytes (RFC 1035 §2.3.4).
[[nodiscard]] std::expected<std::vector<std::byte>, std::string> dns_encode_query(
    std::uint16_t id, std::string_view name, std::uint16_t qtype = dns_type_a);

struct DnsRecord {
  std::string name;  // lower-case, without the final dot
  std::uint16_t type = 0, klass = 0;
  std::uint32_t ttl = 0;
  std::vector<std::byte> rdata;
  std::string target;  // CNAME: the decoded name
};

struct DnsResponse {
  std::uint16_t id = 0;
  bool qr = false;         // a response
  std::uint8_t rcode = 0;  // 0 = no error, 3 = NXDOMAIN, ...
  bool truncated = false;  // TC
  std::string qname;       // the question, lower-case
  std::vector<DnsRecord> answers;
};

// Parses a whole message (header, question, answer section; the authority and
// additional sections are not read). Errors on truncation, bad pointers,
// labels or counts.
[[nodiscard]] std::expected<DnsResponse, std::string> dns_parse_response(
    std::span<const std::byte> msg);

// The IPv4 addresses for `name` in a parsed response: the response must have
// id `id`, QR set, rcode 0 and the question `name`; A records are taken for
// `name` or for the end of its CNAME chain within the answer section.
[[nodiscard]] std::expected<std::vector<Ipv4Addr>, std::string> dns_a_records(
    const DnsResponse& r, std::uint16_t id, std::string_view name);

}  // namespace utcp::app
