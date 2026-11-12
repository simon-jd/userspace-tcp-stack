// IPv4 input: validation, counters and protocol dispatch (DESIGN §1.2, §3.4,
// §4.4 first paragraph). The output side is StackCore::send_ipv4 (defined in
// ip.cpp): every datagram has IHL 5, DF set, TOS 0 and the configured TTL.
//
// A received datagram is dropped and counted if it is malformed (version,
// IHL, lengths, header checksum: IpInHdrErrors, IpExtInCsumErrors,
// IpExtInTruncatedPkts, as Linux ip_rcv_core), a fragment (frag_dropped, no
// reassembly), or not for the stack address (IpInAddrErrors). ICMP, TCP and
// UDP are delivered (IpInDelivers); TCP's header and checksum are validated
// here (TcpInSegs, TcpInErrs, TcpInCsumErrors, as Linux tcp_v4_rcv) before
// TcpEngine::on_segment. Other protocols get ICMP protocol unreachable
// (IpInUnknownProtos), UDP datagrams for unbound ports port unreachable.
#pragma once

#include <cstddef>
#include <span>

#include "utcp/packet.hpp"

namespace utcp {

class StackImpl;

// Processes one received datagram at s.core.now() (the caller has set it).
void ip_input(StackImpl& s, std::span<const std::byte> datagram, RxMeta meta);

}  // namespace utcp
